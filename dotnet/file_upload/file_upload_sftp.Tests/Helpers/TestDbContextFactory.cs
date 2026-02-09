using file_upload_sftp.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace file_upload_sftp.Tests.Helpers;

/// <summary>
/// Creates an SQLite in-memory AppDbContext for testing.
/// Uses a shared connection so the database persists across multiple DbContext instances
/// within the same test (important for services that create their own scope).
///
/// Must use SQLite (not EF InMemory provider) because OutboxProcessor uses ExecuteUpdateAsync.
/// </summary>
public sealed class TestDbContextFactory : IDisposable
{
    private readonly SqliteConnection _connection;

    public TestDbContextFactory()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using var db = CreateContext();
        db.Database.EnsureCreated();
    }

    public AppDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .Options;

        return new AppDbContext(options);
    }

    public void Dispose()
    {
        _connection.Dispose();
    }
}
