/* =======================
   Settings
   ======================= */
DECLARE @Suffix          sysname       = N'_ToDelete';   -- staging/temp suffix
DECLARE @SummarySchema   sysname       = N'dbo';
DECLARE @SummaryBaseName sysname       = N'SyncSummary'; -- final = SyncSummary + Suffix

-- Global columns to compare for ALL tables.
-- If NULL/empty => compare ALL common non-computed, non-rowversion columns.
DECLARE @GlobalColsCSV   nvarchar(max) = N'Id,Code,Name';  -- e.g. N'Id,Code,Name' or NULL


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
    ExactMatch  bit            NOT NULL,
    BaseMinus   int            NULL,
    SrcMinus    int            NULL,
    DiffQuery   nvarchar(max)  NULL
);');

DECLARE @InsertRowSql nvarchar(max) = N'
INSERT INTO ' + @SummaryTableQuoted + N'
 (SchemaName, BaseTable, SrcTable, BaseRows, SrcRows, CountEqual, ExactMatch, BaseMinus, SrcMinus, DiffQuery)
VALUES (@pSchema, @pBase, @pSrc, @pBC, @pSC, @pCntEq, @pExact, @pBms, @pSmb, @pDiff);';


/* =======================
   Loop suffixed tables
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
    /* If base table missing */
    IF OBJECT_ID(QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base), 'U') IS NULL
    BEGIN
        SET @bc = NULL; SET @sc = NULL; SET @bms = NULL; SET @smb = NULL;
        SET @CntEq = 0;  SET @Exact = 0;
        SET @DiffQuery = N'/* Base table not found: ' + @Schema + N'.' + @Base + N' */';

        EXEC sp_executesql
            @InsertRowSql,
            N'@pSchema nvarchar(128), @pBase nvarchar(128), @pSrc nvarchar(128),
              @pBC int, @pSC int, @pCntEq bit, @pExact bit, @pBms int, @pSmb int, @pDiff nvarchar(max)',
            @pSchema=@Schema, @pBase=@Base, @pSrc=@Src,
            @pBC=@bc, @pSC=@sc, @pCntEq=@CntEq, @pExact=@Exact, @pBms=@bms, @pSmb=@smb, @pDiff=@DiffQuery;

        GOTO NextTable;
    END

    /* Build list of columns to compare
       1) common between base & source, excluding computed/rowversion
       2) if @GlobalColsCSV provided, keep only those that exist
    */
    ;WITH basecols AS (
        SELECT c.name, c.column_id
        FROM sys.columns c
        WHERE c.[object_id] = OBJECT_ID(QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base))
          AND c.is_computed = 0
          AND TYPE_NAME(c.user_type_id) NOT IN (N'timestamp', N'rowversion')
    ),
    srccols AS (
        SELECT c.name
        FROM sys.columns c
        WHERE c.[object_id] = OBJECT_ID(QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src))
    ),
    common AS (
        SELECT b.name, b.column_id
        FROM basecols b
        INNER JOIN srccols s ON s.name = b.name
    ),
    filtered AS (
        SELECT c.name, c.column_id
        FROM common c
        WHERE (NULLIF(LTRIM(RTRIM(@GlobalColsCSV)), N'') IS NULL)
           OR EXISTS (
                SELECT 1
                FROM STRING_SPLIT(@GlobalColsCSV, N',') ss
                WHERE LTRIM(RTRIM(ss.value)) = c.name
           )
    )
    SELECT @Cols = STRING_AGG(QUOTENAME(name), N', ') WITHIN GROUP (ORDER BY column_id)
    FROM filtered;

    /* If no comparable columns */
    IF @Cols IS NULL OR @Cols = N''
    BEGIN
        SET @sql = N'
            SELECT @bc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N';
            SELECT @sc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N';';
        EXEC sp_executesql @sql, N'@bc int OUTPUT, @sc int OUTPUT', @bc=@bc OUTPUT, @sc=@sc OUTPUT;

        SET @CntEq = IIF(@bc=@sc, 1, 0);
        SET @Exact = 0;
        SET @bms = NULL; SET @smb = NULL;
        SET @DiffQuery = N'/* No comparable columns for ' + @Schema + N'.' + @Base + N' vs ' + @Schema + N'.' + @Src + N' */';

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

    /* Build DiffQuery if needed */
    IF ISNULL(@bms,0)=0 AND ISNULL(@smb,0)=0
    BEGIN
        SET @Exact = 1;
        SET @DiffQuery = NULL;
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

    SET @CntEq = IIF(@bc=@sc, 1, 0);

    EXEC sp_executesql
        @InsertRowSql,
        N'@pSchema nvarchar(128), @pBase nvarchar(128), @pSrc nvarchar(128),
          @pBC int, @pSC int, @pCntEq bit, @pExact bit, @pBms int, @pSmb int, @pDiff nvarchar(max)',
        @pSchema=@Schema, @pBase=@Base, @pSrc=@Src,
        @pBC=@bc, @pSC=@sc, @pCntEq=@CntEq, @pExact=@Exact,
        @pBms=@bms, @pSmb=@smb, @pDiff=@DiffQuery;

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

PRINT N'→ Summary written to ' + @SummaryTableQuoted + N'. Copy DiffQuery for rows with ExactMatch=0 to see differences.';