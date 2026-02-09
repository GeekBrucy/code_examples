using file_upload_sftp.Models;
using Microsoft.EntityFrameworkCore;

namespace file_upload_sftp.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    // Existing domain tables (represent what already exists in the real system)
    public DbSet<Report> Reports => Set<Report>();
    public DbSet<ReportAttachment> ReportAttachments => Set<ReportAttachment>();
    public DbSet<ReportReferral> ReportReferrals => Set<ReportReferral>();
    public DbSet<ExternalUser> ExternalUsers => Set<ExternalUser>();

    // Outbox
    public DbSet<OutboxEntry> OutboxEntries => Set<OutboxEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<OutboxEntry>(e =>
        {
            e.HasIndex(x => new { x.Status, x.NextRetryAt });
            e.HasIndex(x => x.ReportId);
            e.Property(x => x.Status).HasConversion<string>();
        });

        modelBuilder.Entity<ReportAttachment>(e =>
        {
            e.HasOne(a => a.Report)
             .WithMany(r => r.Attachments)
             .HasForeignKey(a => a.ReportId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ReportReferral>(e =>
        {
            e.HasOne(r => r.Report)
             .WithMany(rp => rp.Referrals)
             .HasForeignKey(r => r.ReportId)
             .OnDelete(DeleteBehavior.Cascade);

            e.HasOne(r => r.ExternalUser)
             .WithMany()
             .HasForeignKey(r => r.ExternalUserId)
             .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
