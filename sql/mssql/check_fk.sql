-- check YourTable reference other tables?

SELECT
    fk.name AS ForeignKeyName,
    OBJECT_SCHEMA_NAME(fk.parent_object_id) AS FromSchema,
    OBJECT_NAME(fk.parent_object_id) AS FromTable,
    OBJECT_SCHEMA_NAME(fk.referenced_object_id) AS ToSchema,
    OBJECT_NAME(fk.referenced_object_id) AS ToTable
FROM sys.foreign_keys fk
WHERE fk.parent_object_id = OBJECT_ID(N'dbo.YourTable');

-- check YourTable referenced by other tables?

SELECT
    fk.name AS ForeignKeyName,
    OBJECT_SCHEMA_NAME(fk.parent_object_id) AS ReferencingSchema,
    OBJECT_NAME(fk.parent_object_id) AS ReferencingTable,
    OBJECT_SCHEMA_NAME(fk.referenced_object_id) AS ReferencedSchema,
    OBJECT_NAME(fk.referenced_object_id) AS ReferencedTable
FROM sys.foreign_keys fk
WHERE fk.referenced_object_id = OBJECT_ID(N'dbo.YourTable');