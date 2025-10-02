/* =======================
   Settings
   ======================= */
DECLARE @Suffix            sysname       = N'_ToDelete';       -- staging/temp suffix for source tables
DECLARE @SummarySchema     sysname       = N'dbo';
DECLARE @SummaryBaseName   sysname       = N'SyncSummary';     -- final = SyncSummary + Suffix
DECLARE @GlobalColsCSV     nvarchar(max) = N'Id,Name,Sequence';-- REQUIRED: only these columns compared
DECLARE @StrictColumns     bit           = 1;                  -- 1=require ALL listed columns exist in BOTH tables

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
   Prep: normalize/de-dup requested column names (Id, Name, Sequence)
   ======================= */
DECLARE @Wanted TABLE (name sysname);  -- no PK to avoid dup insert errors
INSERT INTO @Wanted(name)
SELECT DISTINCT LTRIM(RTRIM(value))
FROM STRING_SPLIT(@GlobalColsCSV, N',')
WHERE NULLIF(LTRIM(RTRIM(value)), N'') IS NOT NULL;

IF NOT EXISTS(SELECT 1 FROM @Wanted)
BEGIN
    RAISERROR('Global column list (@GlobalColsCSV) is empty. Provide at least one column.', 16, 1);
    RETURN;
END

/* =======================
   Loop suffixed tables (exclude summary table itself)
   ======================= */
DECLARE @Schema sysname, @Src sysname, @Base sysname;
DECLARE @Cols nvarchar(max), @sql nvarchar(max);
DECLARE @bc int, @sc int, @bms int, @smb int;
DECLARE @DiffQuery nvarchar(max);
DECLARE @CntEq bit, @Exact bit;

DECLARE @SuffixLen int = LEN(@Suffix);

DECLARE cur CURSOR LOCAL FAST_FORWARD FOR
SELECT TABLE_SCHEMA,
       TABLE_NAME,
       LEFT(TABLE_NAME, LEN(TABLE_NAME) - @SuffixLen) AS BaseTable
FROM INFORMATION_SCHEMA.TABLES
WHERE RIGHT(TABLE_NAME, @SuffixLen) = @Suffix
  AND NOT (
        TABLE_SCHEMA = @SummarySchema
    AND LEFT(TABLE_NAME, LEN(TABLE_NAME) - @SuffixLen) = @SummaryBaseName
  );

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

    /* Discover which requested columns exist in BOTH tables (exclude computed/rowversion from base) */
    DECLARE @colsTable TABLE(name sysname, ord int);  -- no PK here

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
    both AS (
        SELECT b.name, b.column_id
        FROM basecols b
        INNER JOIN srccols s ON s.name = b.name
        INNER JOIN @Wanted  w ON w.name = b.name
    )
    INSERT INTO @colsTable(name, ord)
    SELECT DISTINCT name, MIN(column_id) OVER (PARTITION BY name)
    FROM both;

    /* Strict-mode check: if any requested column missing in either table, record and skip compare */
    IF @StrictColumns = 1
    BEGIN
        DECLARE @missing nvarchar(max);

        ;WITH allreq AS (SELECT name FROM @Wanted),
             have  AS (SELECT name FROM @colsTable)
        SELECT @missing = STUFF((
            SELECT N', ' + QUOTENAME(r.name)
            FROM allreq r
            WHERE NOT EXISTS (SELECT 1 FROM have h WHERE h.name = r.name)
            ORDER BY r.name
            FOR XML PATH(''), TYPE
        ).value('.', 'nvarchar(max)'), 1, 2, N'');

        IF @missing IS NOT NULL AND @missing <> N''
        BEGIN
            -- Rowcounts (for context)
            SET @sql = N'
                SELECT @bc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N';
                SELECT @sc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N';';
            EXEC sp_executesql @sql, N'@bc int OUTPUT, @sc int OUTPUT', @bc=@bc OUTPUT, @sc=@sc OUTPUT;

            SET @CntEq = CASE WHEN @bc=@sc THEN 1 ELSE 0 END;
            SET @Exact = 0;
            SET @bms = NULL; SET @smb = NULL;
            SET @DiffQuery = N'/* Missing requested columns in one or both tables: ' + @missing + N' */';

            EXEC sp_executesql
                @InsertRowSql,
                N'@pSchema nvarchar(128), @pBase nvarchar(128), @pSrc nvarchar(128),
                  @pBC int, @pSC int, @pCntEq bit, @pExact bit, @pBms int, @pSmb int, @pDiff nvarchar(max)',
                @pSchema=@Schema, @pBase=@Base, @pSrc=@Src,
                @pBC=@bc, @pSC=@sc, @pCntEq=@CntEq, @pExact=@Exact, @pBms=@bms, @pSmb=@smb, @pDiff=@DiffQuery;

            GOTO NextTable;
        END
    END

    /* Build comma-separated QUOTENAME list for the existing requested columns */
    SELECT @Cols = STUFF((
        SELECT N', ' + QUOTENAME(t.name)
        FROM @colsTable t
        ORDER BY t.ord, t.name
        FOR XML PATH(''), TYPE
    ).value('.', 'nvarchar(max)'), 1, 2, N'');

    /* If nothing to compare (shouldn't happen in strict mode) */
    IF @Cols IS NULL OR @Cols = N''
    BEGIN
        SET @bc = NULL; SET @sc = NULL; SET @CntEq = 0; SET @Exact = 0;
        SET @DiffQuery = N'/* No overlapping requested columns to compare */';

        EXEC sp_executesql
            @InsertRowSql,
            N'@pSchema nvarchar(128), @pBase nvarchar(128), @pSrc nvarchar(128),
              @pBC int, @pSC int, @pCntEq bit, @pExact bit, @pBms int, @pSmb int, @pDiff nvarchar(max)',
            @pSchema=@Schema, @pBase=@Base, @pSrc=@Src,
            @pBC=@bc, @pSC=@sc, @pCntEq=@CntEq, @pExact=@Exact, @pBms=NULL, @pSmb=NULL, @pDiff=@DiffQuery;

        GOTO NextTable;
    END

    /* Rowcounts + EXCEPT both ways (only Id,Name,Sequence) */
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

    /* DiffQuery text (only when different) */
    IF ISNULL(@bms,0)=0 AND ISNULL(@smb,0)=0
    BEGIN
        SET @Exact = 1;
        SET @DiffQuery = NULL;
    END
    ELSE
    BEGIN
        SET @Exact = 0;
        SET @DiffQuery = N'
/* Differences for ' + @Schema + N'.' + @Base + N' vs ' + @Schema + N'.' + @Src + N' (Id,Name,Sequence only) */
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

    SET @CntEq = CASE WHEN @bc=@sc THEN 1 ELSE 0 END;

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

PRINT N'→ Summary written to ' + @SummaryTableQuoted + N'. (Strict mode=' + CAST(@StrictColumns AS nvarchar(1)) +
      N') Copy DiffQuery for rows with ExactMatch=0 to see differences.';