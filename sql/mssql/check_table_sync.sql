/* =======================
   Settings
   ======================= */
DECLARE @Suffix          sysname = N'_ToDelete';    -- your staging/temp suffix
DECLARE @SummarySchema   sysname = N'dbo';
DECLARE @SummaryBaseName sysname = N'SyncSummary';  -- final table name = SyncSummary + Suffix

/* =======================
   Create final summary table (with suffix)
   ======================= */
DECLARE @SummaryTableQuoted nvarchar(300) =
    QUOTENAME(@SummarySchema) + N'.' + QUOTENAME(@SummaryBaseName + @Suffix);

IF OBJECT_ID(@SummaryTableQuoted, 'U') IS NOT NULL
    EXEC(N'DROP TABLE ' + @SummaryTableQuoted + N';');

EXEC(N'
CREATE TABLE ' + @SummaryTableQuoted + N'(
    SchemaName  sysname        NOT NULL,
    BaseTable   sysname        NOT NULL,
    SrcTable    sysname        NOT NULL,
    BaseRows    int            NULL,
    SrcRows     int            NULL,
    CountEqual  bit            NOT NULL,
    ExactMatch  bit            NOT NULL,  -- exact set equality over compared columns
    BaseMinus   int            NULL,      -- rows only in base
    SrcMinus    int            NULL,      -- rows only in source
    DiffQuery   nvarchar(max)  NULL       -- runnable SQL to list diffs
);');

/* Pre-build the dynamic insert into the final summary table */
DECLARE @InsertRowSql nvarchar(max) = N'
INSERT INTO ' + @SummaryTableQuoted + N'
 (SchemaName, BaseTable, SrcTable, BaseRows, SrcRows, CountEqual, ExactMatch, BaseMinus, SrcMinus, DiffQuery)
VALUES (@pSchema, @pBase, @pSrc, @pBC, @pSC, @pCntEq, @pExact, @pBms, @pSmb, @pDiff);';

/* =======================
   Loop tables that end with @Suffix
   ======================= */
DECLARE @Schema sysname, @Src sysname, @Base sysname;
DECLARE @Cols nvarchar(max), @sql nvarchar(max);
DECLARE @bc int, @sc int, @bms int, @smb int;
DECLARE @DiffQuery nvarchar(max);
DECLARE @CntEq bit, @Exact bit;

DECLARE cur CURSOR LOCAL FAST_FORWARD FOR
SELECT TABLE_SCHEMA,
       TABLE_NAME,
       LEFT(TABLE_NAME, LEN(TABLE_NAME) - LEN(@Suffix)) AS BaseTable
FROM INFORMATION_SCHEMA.TABLES
WHERE RIGHT(TABLE_NAME, LEN(@Suffix)) = @Suffix;

OPEN cur;
FETCH NEXT FROM cur INTO @Schema, @Src, @Base;

WHILE @@FETCH_STATUS = 0
BEGIN
    /* If base table missing, record and continue */
    IF OBJECT_ID(QUOTENAME(@Schema) + '.' + QUOTENAME(@Base), 'U') IS NULL
    BEGIN
        SET @bc = NULL; SET @sc = NULL; SET @bms = NULL; SET @smb = NULL;
        SET @CntEq = 0; SET @Exact = 0;
        SET @DiffQuery = N'/* Base table not found: ' + @Schema + N'.' + @Base + N' */';

        EXEC sp_executesql
            @InsertRowSql,
            N'@pSchema nvarchar(128), @pBase nvarchar(128), @pSrc nvarchar(128),
              @pBC int, @pSC int, @pCntEq bit, @pExact bit, @pBms int, @pSmb int, @pDiff nvarchar(max)',
            @pSchema=@Schema, @pBase=@Base, @pSrc=@Src,
            @pBC=@bc, @pSC=@sc, @pCntEq=@CntEq, @pExact=@Exact, @pBms=@bms, @pSmb=@smb, @pDiff=@DiffQuery;

        GOTO NextTable;
    END

    /* Build common comparable columns (exclude computed & rowversion) */
    ;WITH basecols AS (
        SELECT c.name, c.column_id
        FROM sys.columns c
        WHERE c.[object_id] = OBJECT_ID(QUOTENAME(@Schema) + '.' + QUOTENAME(@Base))
          AND c.is_computed = 0
          AND TYPE_NAME(c.user_type_id) NOT IN ('timestamp','rowversion')
    ),
    srccols AS (
        SELECT c.name
        FROM sys.columns c
        WHERE c.[object_id] = OBJECT_ID(QUOTENAME(@Schema) + '.' + QUOTENAME(@Src))
    ),
    common AS (
        SELECT b.name, b.column_id
        FROM basecols b
        INNER JOIN srccols s ON s.name = b.name
    )
    SELECT @Cols = STRING_AGG(QUOTENAME(name), ', ') WITHIN GROUP (ORDER BY column_id)
    FROM common;

    /* If no comparable columns, store rowcounts only and a hint */
    IF @Cols IS NULL OR @Cols = N''
    BEGIN
        SET @sql = N'
            SELECT @bc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N';
            SELECT @sc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N';';
        EXEC sp_executesql @sql, N'@bc int OUTPUT, @sc int OUTPUT', @bc=@bc OUTPUT, @sc=@sc OUTPUT;

        SET @CntEq = CASE WHEN @bc = @sc THEN 1 ELSE 0 END;
        SET @Exact = 0;
        SET @bms = NULL; SET @smb = NULL;
        SET @DiffQuery = N'/* No common comparable columns between ' + @Schema + N'.' + @Base +
                         N' and ' + @Schema + N'.' + @Src + N'. Check schema differences. */';

        EXEC sp_executesql
            @InsertRowSql,
            N'@pSchema nvarchar(128), @pBase nvarchar(128), @pSrc nvarchar(128),
              @pBC int, @pSC int, @pCntEq bit, @pExact bit, @pBms int, @pSmb int, @pDiff nvarchar(max)',
            @pSchema=@Schema, @pBase=@Base, @pSrc=@Src,
            @pBC=@bc, @pSC=@sc, @pCntEq=@CntEq, @pExact=@Exact, @pBms=@bms, @pSmb=@smb, @pDiff=@DiffQuery;

        GOTO NextTable;
    END

    /* Rowcounts + EXCEPT both ways */
    SET @sql = N'
        SELECT @bc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N';
        SELECT @sc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N';
        SELECT @bms = COUNT(*) FROM (
            SELECT ' + @Cols + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N'
            EXCEPT
            SELECT ' + @Cols + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N'
        ) X;
        SELECT @smb = COUNT(*) FROM (
            SELECT ' + @Cols + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N'
            EXCEPT
            SELECT ' + @Cols + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N'
        ) Y;';
    EXEC sp_executesql
        @sql,
        N'@bc int OUTPUT, @sc int OUTPUT, @bms int OUTPUT, @smb int OUTPUT',
        @bc=@bc OUTPUT, @sc=@sc OUTPUT, @bms=@bms OUTPUT, @smb=@smb OUTPUT;

    /* Build diff query text (only if there are diffs) */
    IF ISNULL(@bms,0)=0 AND ISNULL(@smb,0)=0
    BEGIN
        SET @DiffQuery = NULL;
        SET @Exact = 1;
    END
    ELSE
    BEGIN
        SET @Exact = 0;
        SET @DiffQuery = N'
/* Differences for ' + @Schema + N'.' + @Base + N' vs ' + @Schema + N'.' + @Src + N' */
SELECT ''BASE_MINUS'' AS side, * FROM (
    SELECT ' + @Cols + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N'
    EXCEPT
    SELECT ' + @Cols + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N'
) d
UNION ALL
SELECT ''SRC_MINUS'' AS side, * FROM (
    SELECT ' + @Cols + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N'
    EXCEPT
    SELECT ' + @Cols + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N'
) d;';
    END

    SET @CntEq = CASE WHEN @bc = @sc THEN 1 ELSE 0 END;

    /* Insert summary row into the final table */
    EXEC sp_executesql
        @InsertRowSql,
        N'@pSchema nvarchar(128), @pBase nvarchar(128), @pSrc nvarchar(128),
          @pBC int, @pSC int, @pCntEq bit, @pExact bit, @pBms int, @pSmb int, @pDiff nvarchar(max)',
        @pSchema=@Schema, @pBase=@Base, @pSrc=@Src,
        @pBC=@bc, @pSC=@sc, @pCntEq=@CntEq, @pExact=@Exact, @pBms=@bms, @pSmb=@smb, @pDiff=@DiffQuery;

    NextTable:
    FETCH NEXT FROM cur INTO @Schema, @Src, @Base;
END

CLOSE cur;
DEALLOCATE cur;

/* =======================
   Show results
   ======================= */
DECLARE @show nvarchar(max) = N'SELECT * FROM ' + @SummaryTableQuoted + N'
ORDER BY ExactMatch DESC, CountEqual DESC, SchemaName, BaseTable;';
EXEC(@show);

PRINT N'→ Summary written to ' + @SummaryTableQuoted + N'. Copy the DiffQuery text for any row with ExactMatch = 0 to see differences.';