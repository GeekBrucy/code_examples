using _01_custom_auth.Domain;
using Microsoft.EntityFrameworkCore;

namespace _01_custom_auth.Infrastructure.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.ApplyConfigurationsFromAssembly(GetType().Assembly);
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Session> Sessions { get; set; }

    }
}