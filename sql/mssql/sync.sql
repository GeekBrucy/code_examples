/* =======================
   SYNC + BACKUP
   ======================= */
DECLARE @Suffix          sysname       = N'_ToDelete';   -- source suffix
DECLARE @KeyColumn       sysname       = N'Id';          -- TODO: change if PK isn’t Id
DECLARE @DoDeletes       bit           = 1;              -- 1: delete rows not in source; 0: skip deletes

DECLARE @Schema sysname, @Src sysname, @Base sysname;
DECLARE @SuffixLen int = LEN(@Suffix);

DECLARE cur CURSOR LOCAL FAST_FORWARD FOR
SELECT TABLE_SCHEMA,
       TABLE_NAME,
       LEFT(TABLE_NAME, LEN(TABLE_NAME) - @SuffixLen) AS BaseTable
FROM INFORMATION_SCHEMA.TABLES
WHERE RIGHT(TABLE_NAME, @SuffixLen) = @Suffix
  -- don’t process our verify table if it exists
  AND NOT (TABLE_SCHEMA = N'dbo'
           AND LEFT(TABLE_NAME, LEN(TABLE_NAME) - @SuffixLen) IN (N'SyncSummary'));

OPEN cur;
FETCH NEXT FROM cur INTO @Schema, @Src, @Base;

WHILE @@FETCH_STATUS = 0
BEGIN
    IF OBJECT_ID(QUOTENAME(@Schema)+N'.'+QUOTENAME(@Base), 'U') IS NULL
    BEGIN
        PRINT 'Skip: base table not found -> ' + @Schema + '.' + @Base;
        GOTO NextTable;
    END

    /* ---------- BACKUP to <Base>_Bak ---------- */
    DECLARE @Parent  nvarchar(300) = QUOTENAME(@Schema)+N'.'+QUOTENAME(@Base);
    DECLARE @BakName sysname      = @Base + N'_Bak';
    DECLARE @Backup  nvarchar(300) = QUOTENAME(@Schema)+N'.'+QUOTENAME(@BakName);

    DECLARE @sql nvarchar(max);

    IF OBJECT_ID(@Backup, 'U') IS NULL
    BEGIN
        -- Create and load in one shot
        SET @sql = N'SELECT * INTO ' + @Backup + N' FROM ' + @Parent + N';';
        EXEC(@sql);
    END
    ELSE
    BEGIN
        -- Refresh existing backup (keeps table, reloads data)
        SET @sql = N'DELETE FROM ' + @Backup + N'; INSERT INTO ' + @Backup + N' SELECT * FROM ' + @Parent + N';';
        EXEC(@sql);
    END
    PRINT 'Backed up ' + @Parent + ' -> ' + @Backup;

    /* ---------- Build column lists for MERGE (from BASE definition) ---------- */
    DECLARE @ColsAll nvarchar(max), @ColsUpd nvarchar(max);

    ;WITH cols AS (
        SELECT c.name, c.column_id, c.is_computed, TYPE_NAME(c.user_type_id) AS typ
        FROM sys.columns c
        WHERE c.[object_id] = OBJECT_ID(@Parent)
    ),
    cmp AS (
        SELECT name, column_id
        FROM cols
        WHERE is_computed = 0 AND typ NOT IN (N'timestamp', N'rowversion')
    )
    SELECT
        @ColsAll = STUFF((
            SELECT N', ' + QUOTENAME(name)
            FROM cmp ORDER BY column_id
            FOR XML PATH(''), TYPE
        ).value('.','nvarchar(max)'), 1, 2, N''),
        @ColsUpd = STUFF((
            SELECT N', T.' + QUOTENAME(name) + N' = S.' + QUOTENAME(name)
            FROM cmp WHERE name <> @KeyColumn
            ORDER BY column_id
            FOR XML PATH(''), TYPE
        ).value('.','nvarchar(max)'), 1, 2, N'');

    IF @ColsAll IS NULL OR @ColsAll = N''
    BEGIN
        PRINT 'Skip: no comparable columns -> ' + @Parent;
        GOTO NextTable;
    END

    /* ---------- MERGE from <Base>_ToDelete -> <Base> with IDENTITY_INSERT safety ---------- */
    DECLARE @On  nvarchar(400) = N'SET IDENTITY_INSERT ' + @Parent + N' ON;';
    DECLARE @Off nvarchar(400) = N'SET IDENTITY_INSERT ' + @Parent + N' OFF;';

    BEGIN TRY
        BEGIN TRAN;

        SET @sql = @On + N'
MERGE ' + @Parent + N' AS T
USING (SELECT ' + @ColsAll + N' FROM ' + QUOTENAME(@Schema)+N'.'+QUOTENAME(@Src) + N') AS S
   ON T.' + QUOTENAME(@KeyColumn) + N' = S.' + QUOTENAME(@KeyColumn) + N'
WHEN MATCHED THEN
    UPDATE SET ' + @ColsUpd + N'
WHEN NOT MATCHED BY TARGET THEN
    INSERT (' + @ColsAll + N') VALUES (' + @ColsAll + N')' +
CASE WHEN @DoDeletes = 1 THEN N'
WHEN NOT MATCHED BY SOURCE THEN
    DELETE' ELSE N'' END + N';
' + @Off;

        EXEC(@sql);
        COMMIT TRAN;

        PRINT 'Synced ' + @Parent + ' from ' + QUOTENAME(@Schema)+N'.'+QUOTENAME(@Src);
    END TRY
    BEGIN CATCH
        IF XACT_STATE() <> 0 ROLLBACK TRAN;
        BEGIN TRY EXEC(@Off); END TRY BEGIN CATCH END CATCH;
        PRINT CONCAT('Sync error on ', @Parent, ': (', ERROR_NUMBER(), ') ', ERROR_MESSAGE());
    END CATCH

    NextTable:
    FETCH NEXT FROM cur INTO @Schema, @Src, @Base;
END

CLOSE cur; DEALLOCATE cur;