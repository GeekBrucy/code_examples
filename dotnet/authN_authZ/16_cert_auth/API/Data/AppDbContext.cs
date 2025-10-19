using API.Models;
using Microsoft.EntityFrameworkCore;

namespace API.Data;

/// <summary>
/// Application database context for certificate authentication audit logging.
/// This demonstrates a real-world DbContext that you would use in production.
/// </summary>
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<CertificateAuditLog> CertificateAuditLogs { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure CertificateAuditLog entity
        modelBuilder.Entity<CertificateAuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.Property(e => e.CertificateSubject)
                .IsRequired()
                .HasMaxLength(500);

            entity.Property(e => e.CertificateThumbprint)
                .IsRequired()
                .HasMaxLength(100);

            entity.Property(e => e.IssuerName)
                .HasMaxLength(500);

            entity.Property(e => e.FailureReason)
                .HasMaxLength(1000);

            entity.Property(e => e.IpAddress)
                .HasMaxLength(50);

            entity.Property(e => e.Endpoint)
                .HasMaxLength(200);

            // Index for performance when querying by thumbprint or time
            entity.HasIndex(e => e.CertificateThumbprint);
            entity.HasIndex(e => e.AuthenticationTime);
            entity.HasIndex(e => e.IsSuccessful);
        });
    }
}
