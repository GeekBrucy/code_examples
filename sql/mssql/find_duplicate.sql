SELECT recordId, COUNT(*) AS Cnt
FROM dbo.YourTable
GROUP BY recordId
HAVING COUNT(*) > 1
ORDER BY Cnt DESC;

-- Preview rows that would be deleted
-- (keeps the lowest id per recordId)

;WITH d AS (
    SELECT
        *,
        rn = ROW_NUMBER() OVER (PARTITION BY recordId ORDER BY id ASC)
    FROM dbo.YourTable
)
SELECT *
FROM d
WHERE rn > 1
ORDER BY recordId, id;

-- Backup only duplicate rows (recommended)

;WITH d AS (
    SELECT
        *,
        rn = ROW_NUMBER() OVER (PARTITION BY recordId ORDER BY id ASC)
    FROM dbo.YourTable
)
SELECT *
INTO dbo.YourTable_deleted_dupes_20260115
FROM d
WHERE rn > 1;

-- Delete Duplicate Rows

BEGIN TRAN;

;WITH d AS (
    SELECT
        id,
        rn = ROW_NUMBER() OVER (PARTITION BY recordId ORDER BY id ASC)
    FROM dbo.YourTable
)
DELETE t
FROM dbo.YourTable t
JOIN d ON d.id = t.id
WHERE d.rn > 1;

-- Sanity check
SELECT recordId, COUNT(*) AS Cnt
FROM dbo.YourTable
GROUP BY recordId
HAVING COUNT(*) > 1;

-- If results look wrong:
-- ROLLBACK;

-- If everything looks good:
COMMIT;


-- Restore Deleted Rows (If Needed)

-- Because id is an IDENTITY, use IDENTITY_INSERT.

SET IDENTITY_INSERT dbo.YourTable ON;

INSERT INTO dbo.YourTable (
    id,
    recordId
    -- , other columns here (must list all non-null columns)
)
SELECT
    id,
    recordId
    -- , other columns here
FROM dbo.YourTable_deleted_dupes_20260115;

SET IDENTITY_INSERT dbo.YourTable OFF;

-- Prevent Future Duplicates (Highly Recommended)

-- Add a unique index on recordId

CREATE UNIQUE INDEX UX_YourTable_recordId
ON dbo.YourTable(recordId);

-- If recordId can be NULL

CREATE UNIQUE INDEX UX_YourTable_recordId
ON dbo.YourTable(recordId)
WHERE recordId IS NOT NULL;