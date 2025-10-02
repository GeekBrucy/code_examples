/* =======================
   Settings
   ======================= */
DECLARE @Suffix            sysname       = N'_ToDelete';       -- staging/temp suffix
DECLARE @SummarySchema     sysname       = N'dbo';
DECLARE @SummaryBaseName   sysname       = N'SyncSummary';     -- final = SyncSummary + Suffix
DECLARE @GlobalColsCSV     nvarchar(max) = N'Id, Name, Sequence'; -- only these columns compared

/* =======================
   Create summary table
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
   Loop suffixed tables (exclude summary itself)
   ======================= */
DECLARE @Schema sysname, @Src sysname, @Base sysname;
DECLARE @sql nvarchar(max);
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
    IF OBJECT_ID(QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base), 'U') IS NULL
    BEGIN
        SET @bc = NULL; SET @sc = NULL; SET @bms = NULL; SET @smb = NULL;
        SET @CntEq = 0;  SET @Exact = 0;
        SET @DiffQuery = N'/* Base table not found */';

        EXEC sp_executesql
            @InsertRowSql,
            N'@pSchema nvarchar(128), @pBase nvarchar(128), @pSrc nvarchar(128),
              @pBC int, @pSC int, @pCntEq bit, @pExact bit, @pBms int, @pSmb int, @pDiff nvarchar(max)',
            @pSchema=@Schema, @pBase=@Base, @pSrc=@Src,
            @pBC=@bc, @pSC=@sc, @pCntEq=@CntEq, @pExact=@Exact, @pBms=@bms, @pSmb=@smb, @pDiff=@DiffQuery;

        GOTO NextTable;
    END

    /* Rowcounts + EXCEPT using @GlobalColsCSV directly */
    SET @sql = N'
        SELECT @bc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N';
        SELECT @sc = COUNT(*) FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N';
        SELECT @bms = COUNT(*) FROM (
            SELECT ' + @GlobalColsCSV + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N'
            EXCEPT
            SELECT ' + @GlobalColsCSV + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N'
        ) X;
        SELECT @smb = COUNT(*) FROM (
            SELECT ' + @GlobalColsCSV + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N'
            EXCEPT
            SELECT ' + @GlobalColsCSV + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N'
        ) Y;';
    EXEC sp_executesql
        @sql,
        N'@bc int OUTPUT, @sc int OUTPUT, @bms int OUTPUT, @smb int OUTPUT',
        @bc=@bc OUTPUT, @sc=@sc OUTPUT, @bms=@bms OUTPUT, @smb=@smb OUTPUT;

    IF ISNULL(@bms,0)=0 AND ISNULL(@smb,0)=0
    BEGIN
        SET @Exact = 1; SET @DiffQuery = NULL;
    END
    ELSE
    BEGIN
        SET @Exact = 0;
        SET @DiffQuery = N'
/* Differences for ' + @Schema + N'.' + @Base + N' */
SELECT ''BASE_MINUS'' AS side, * FROM (
    SELECT ' + @GlobalColsCSV + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N'
    EXCEPT
    SELECT ' + @GlobalColsCSV + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N'
) d
UNION ALL
SELECT ''SRC_MINUS'' AS side, * FROM (
    SELECT ' + @GlobalColsCSV + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Src)  + N'
    EXCEPT
    SELECT ' + @GlobalColsCSV + N' FROM ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Base) + N'
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