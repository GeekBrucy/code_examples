using Microsoft.EntityFrameworkCore;
using API.Models;

namespace API.Data;

public class PollingDbContext : DbContext
{
    public PollingDbContext(DbContextOptions<PollingDbContext> options) : base(options)
    {
    }

    public DbSet<UserSession> UserSessions { get; set; }
    public DbSet<UpdateRecord> UpdateRecords { get; set; }
    public DbSet<UpdateEvent> UpdateEvents { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<UserSession>(entity =>
        {
            entity.HasKey(e => e.UserId);
            entity.Property(e => e.UserId).HasMaxLength(100);
            entity.HasIndex(e => e.LastSync);
            entity.HasIndex(e => e.LastEventSequence);
        });

        modelBuilder.Entity<UpdateRecord>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasMaxLength(50);
            entity.Property(e => e.Type).HasMaxLength(50);
            entity.Property(e => e.Source).HasMaxLength(100);
            entity.Property(e => e.Content).HasColumnType("TEXT");
            
            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => e.UpdatedAt);
            entity.HasIndex(e => e.Source);
            entity.HasIndex(e => e.Type);
            entity.HasIndex(e => e.Priority);
        });

        modelBuilder.Entity<UpdateEvent>(entity =>
        {
            entity.HasKey(e => e.EventSequence);
            entity.Property(e => e.EventSequence).ValueGeneratedOnAdd(); // Auto-increment cursor
            entity.Property(e => e.UpdateRecordId).HasMaxLength(50);
            entity.Property(e => e.EventType).HasMaxLength(20);
            
            entity.HasIndex(e => e.EventSequence).IsUnique(); // Primary cursor index
            entity.HasIndex(e => e.UpdateRecordId);
            entity.HasIndex(e => e.EventTimestamp);
            
            // Foreign key relationship
            entity.HasOne(e => e.UpdateRecord)
                  .WithMany()
                  .HasForeignKey(e => e.UpdateRecordId)
                  .OnDelete(DeleteBehavior.SetNull); // Allow orphaned events if record is deleted
        });
    }
}