/* =======================
   Settings
   ======================= */
DECLARE @Suffix          sysname = N'_ToDelete';    -- the temp/staging suffix
DECLARE @SummarySchema   sysname = N'dbo';          -- summary table schema
DECLARE @SummaryBaseName sysname = N'SyncSummary';  -- final name = SyncSummary + Suffix

/* =======================
   Create summary table
   ======================= */
DECLARE @SummaryTableQuoted nvarchar(300) = QUOTENAME(@SummarySchema) + N'.' + QUOTENAME(@SummaryBaseName + @Suffix);

IF OBJECT_ID(@SummaryTableQuoted) IS NOT NULL
    EXEC(N'DROP TABLE ' + @SummaryTableQuoted + N';');

EXEC(N'
CREATE TABLE ' + @SummaryTableQuoted + N'(
    SchemaName  sysname        NOT NULL,
    BaseTable   sysname        NOT NULL,
    SrcTable    sysname        NOT NULL,
    BaseRows    int            NULL,
    SrcRows     int            NULL,
    CountEqual  bit            NOT NULL,
    ExactMatch  bit            NOT NULL,  -- exact set match over compared columns
    BaseMinus   int            NULL,      -- rows only in base
    SrcMinus    int            NULL,      -- rows only in source
    DiffQuery   nvarchar(max)  NULL       -- runnable SQL to list diffs
);');

/* =======================
   Loop tables that end with @Suffix
   ======================= */
DECLARE @Schema sysname, @Src sysname, @Base sysname;
DECLARE @Cols nvarchar(max), @sql nvarchar(max);
DECLARE @bc int, @sc int, @bms int, @smb int;
DECLARE @DiffQuery nvarchar(max);

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
    /* base table must exist to compare */
    IF OBJECT_ID(QUOTENAME(@Schema) + '.' + QUOTENAME(@Base)) IS NULL
    BEGIN
        SET @bc = NULL; SET @sc = NULL; SET @bms = NULL; SET @smb = NULL;
        SET @DiffQuery = N'/* Base table not found: ' + @Schema + N'.' + @Base + N' */';

        EXEC sp_executesql
            N'INSERT INTO ' + @SummaryTableQuoted + N'
              (SchemaName, BaseTable, SrcTable, BaseRows, SrcRows, CountEqual, ExactMatch, BaseMinus, SrcMinus, DiffQuery)
              VALUES(@p1, @p2, @p3, @p4, @p5, 0, 0, @p6, @p7, @p8);',
            N'@p1 nvarchar(128), @p2 nvarchar(128), @p3 nvarchar(128), @p4 int, @p5 int, @p6 int, @p7 int, @p8 nvarchar(max)',
            @p1=@Schema, @p2=@Base, @p3=@Src, @p4=@bc, @p5=@sc, @p6=@bms, @p7=@smb, @p8=@DiffQuery;

        GOTO NextTable;
    END

    /* Build list of common comparable columns (exclude computed & rowversion) */
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

    /* If no comparable columns, record non-match (with a hint) */
    IF @Cols IS NULL OR @Cols = N''
    BEGIN
        -- just rowcounts for info
        DECLARE @cntSql nvarchar(max) = N'
            SELECT @bc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N';
            SELECT @sc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N';';
        EXEC sp_executesql @cntSql, N'@bc int OUTPUT, @sc int OUTPUT', @bc=@bc OUTPUT, @sc=@sc OUTPUT;

        SET @bms = NULL; SET @smb = NULL;
        SET @DiffQuery = N'/* No common comparable columns between ' + @Schema + N'.' + @Base +
                         N' and ' + @Schema + N'.' + @Src + N'. Check schema differences. */';

        EXEC sp_executesql
            N'INSERT INTO ' + @SummaryTableQuoted + N'
              (SchemaName, BaseTable, SrcTable, BaseRows, SrcRows, CountEqual, ExactMatch, BaseMinus, SrcMinus, DiffQuery)
              VALUES(@p1, @p2, @p3, @p4, @p5, 0, 0, @p6, @p7, @p8);',
            N'@p1 nvarchar(128), @p2 nvarchar(128), @p3 nvarchar(128), @p4 int, @p5 int, @p6 int, @p7 int, @p8 nvarchar(max)',
            @p1=@Schema, @p2=@Base, @p3=@Src, @p4=@bc, @p5=@sc, @p6=@bms, @p7=@smb, @p8=@DiffQuery;

        GOTO NextTable;
    END

    /* Rowcounts + EXCEPT in both directions */
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

    /* Build runnable diff query if needed */
    IF ISNULL(@bms,0) = 0 AND ISNULL(@smb,0) = 0
    BEGIN
        SET @DiffQuery = NULL; -- exact match
    END
    ELSE
    BEGIN
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

    /* Insert summary row */
    EXEC sp_executesql
        N'INSERT INTO ' + @SummaryTableQuoted + N'
          (SchemaName, BaseTable, SrcTable, BaseRows, SrcRows, CountEqual, ExactMatch, BaseMinus, SrcMinus, DiffQuery)
          VALUES(@p1, @p2, @p3, @p4, @p5,
                 CASE WHEN @p4 = @p5 THEN 1 ELSE 0 END,
                 CASE WHEN ISNULL(@p6,0)=0 AND ISNULL(@p7,0)=0 THEN 1 ELSE 0 END,
                 @p6, @p7, @p8);',
        N'@p1 nvarchar(128), @p2 nvarchar(128), @p3 nvarchar(128), @p4 int, @p5 int, @p6 int, @p7 int, @p8 nvarchar(max)',
        @p1=@Schema, @p2=@Base, @p3=@Src, @p4=@bc, @p5=@sc, @p6=@bms, @p7=@smb, @p8=@DiffQuery;

    NextTable:
    FETCH NEXT FROM cur INTO @Schema, @Src, @Base;
END

CLOSE cur; DEALLOCATE cur;

/* =======================
   Show results
   ======================= */
DECLARE @show nvarchar(max) =
    N'SELECT * FROM ' + @SummaryTableQuoted + N'
      ORDER BY ExactMatch DESC, CountEqual DESC, SchemaName, BaseTable;';
EXEC(@show);

PRINT N'→ Summary written to ' + @SummaryTableQuoted + N'. Copy the DiffQuery text and run it to see differing rows.';