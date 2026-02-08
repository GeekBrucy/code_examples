using file_upload_sftp.Models;
using Microsoft.EntityFrameworkCore;

namespace file_upload_sftp.Data;

public class OutboxDbContext : DbContext
{
    public OutboxDbContext(DbContextOptions<OutboxDbContext> options) : base(options) { }

    public DbSet<OutboxEntry> OutboxEntries => Set<OutboxEntry>();
    public DbSet<OutboxFile> OutboxFiles => Set<OutboxFile>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<OutboxEntry>(e =>
        {
            e.HasIndex(x => new { x.Status, x.NextRetryAt });
            e.HasIndex(x => x.RecordId);
            e.Property(x => x.Status).HasConversion<string>();
        });

        modelBuilder.Entity<OutboxFile>(e =>
        {
            e.HasOne(f => f.OutboxEntry)
             .WithMany(o => o.Files)
             .HasForeignKey(f => f.OutboxEntryId)
             .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
