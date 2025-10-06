/* =======================
   RESTORE ONE TABLE from <Base>_Bak (FK-aware)
   ======================= */
DECLARE @Schema sysname = N'dbo';          -- change
DECLARE @Base   sysname = N'YourTable';    -- change
DECLARE @Parent nvarchar(300) = QUOTENAME(@Schema)+N'.'+QUOTENAME(@Base);
DECLARE @Backup nvarchar(300) = QUOTENAME(@Schema)+N'.'+QUOTENAME(@Base + N'_Bak');

-- comparable columns from target
DECLARE @Cols nvarchar(max);
;WITH c AS (
  SELECT c.name, c.column_id, c.is_computed, TYPE_NAME(c.user_type_id) AS typ
  FROM sys.columns c
  WHERE c.[object_id] = OBJECT_ID(@Parent)
)
SELECT @Cols = STUFF((
  SELECT N', ' + QUOTENAME(name)
  FROM c WHERE is_computed = 0 AND typ NOT IN (N'timestamp', N'rowversion')
  ORDER BY column_id
  FOR XML PATH(''), TYPE).value('.','nvarchar(max)'), 1, 2, N'');

IF @Cols IS NULL OR @Cols = N'' BEGIN RAISERROR('No comparable columns on %s.', 16, 1, @Parent); RETURN; END

-- referencing FKs (children)
DECLARE @FKs TABLE (disable_sql nvarchar(max), enable_sql nvarchar(max));
INSERT INTO @FKs(disable_sql, enable_sql)
SELECT
  N'ALTER TABLE ' + QUOTENAME(SCHEMA_NAME(ch.schema_id)) + N'.' + QUOTENAME(ch.name) +
    N' NOCHECK CONSTRAINT ' + QUOTENAME(fk.name) + N';',
  N'ALTER TABLE ' + QUOTENAME(SCHEMA_NAME(ch.schema_id)) + N'.' + QUOTENAME(ch.name) +
    N' WITH CHECK CHECK CONSTRAINT ' + QUOTENAME(fk.name) + N';'
FROM sys.foreign_keys fk
JOIN sys.objects ch ON ch.object_id = fk.parent_object_id
WHERE fk.referenced_object_id = OBJECT_ID(@Parent);

DECLARE @disableAll nvarchar(max) = N'';
SELECT @disableAll = @disableAll + disable_sql + CHAR(10) FROM @FKs;

DECLARE @enableAll nvarchar(max) = N'';
SELECT @enableAll = @enableAll + enable_sql + CHAR(10) FROM @FKs;

DECLARE @on  nvarchar(400) = N'SET IDENTITY_INSERT ' + @Parent + N' ON;';
DECLARE @off nvarchar(400) = N'SET IDENTITY_INSERT ' + @Parent + N' OFF;';

BEGIN TRY
  BEGIN TRAN;
  IF LEN(@disableAll) > 0 EXEC(@disableAll);

  EXEC(@on);
  EXEC(N'DELETE FROM ' + @Parent + N';');
  EXEC(N'INSERT INTO ' + @Parent + N' (' + @Cols + N') SELECT ' + @Cols + N' FROM ' + @Backup + N';');
  EXEC(@off);

  IF LEN(@enableAll) > 0 EXEC(@enableAll);
  COMMIT TRAN;

  PRINT N'Restored ' + @Parent + N' from ' + @Backup + N' (FKs temporarily disabled).';
END TRY
BEGIN CATCH
  IF XACT_STATE() <> 0 ROLLBACK TRAN;
  BEGIN TRY EXEC(@off); END TRY BEGIN CATCH END CATCH;
  THROW;
END CATCH