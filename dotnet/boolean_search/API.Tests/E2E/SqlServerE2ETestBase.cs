using API.Data;
using API.Models;
using Microsoft.EntityFrameworkCore;
using Xunit.Abstractions;

namespace API.Tests.E2E
{
    public abstract class SqlServerE2ETestBase : IDisposable
    {
        protected readonly MyDbContext Context;
        protected readonly ITestOutputHelper Output;
        protected readonly string DatabaseName;
        protected readonly string ConnectionString;

        protected SqlServerE2ETestBase(ITestOutputHelper output)
        {
            Output = output;
            DatabaseName = $"BooleanSearchDB_Test_{Guid.NewGuid():N}";
            ConnectionString = $"Server=localhost,1433;Database={DatabaseName};User Id=sa;Password=Password1;TrustServerCertificate=true;";

            var options = new DbContextOptionsBuilder<MyDbContext>()
                .UseSqlServer(ConnectionString)
                .Options;

            Context = new MyDbContext(options);
            
            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            Output.WriteLine($"Creating test database: {DatabaseName}");
            
            try
            {
                // Create the database
                Context.Database.EnsureCreated();
                
                // Seed test data FIRST
                SeedTestData();
                
                // Then create full-text catalog and index
                CreateFullTextIndex();
                
                Output.WriteLine($"✓ Database {DatabaseName} created successfully");
            }
            catch (Exception ex)
            {
                Output.WriteLine($"❌ Failed to create database: {ex.Message}");
                throw;
            }
        }

        private void CreateFullTextIndex()
        {
            try
            {
                // Create full-text catalog
                Context.Database.ExecuteSqlRaw(@"
                    IF NOT EXISTS (SELECT * FROM sys.fulltext_catalogs WHERE name = 'TestCatalog')
                    CREATE FULLTEXT CATALOG TestCatalog AS DEFAULT;
                ");

                // Create full-text index on SearchTargets.Texts
                Context.Database.ExecuteSqlRaw(@"
                    IF NOT EXISTS (SELECT * FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID('SearchTargets'))
                    CREATE FULLTEXT INDEX ON SearchTargets (Texts) 
                    KEY INDEX PK_SearchTargets ON TestCatalog;
                ");

                // Wait for full-text index to populate
                Output.WriteLine("⏳ Waiting for full-text index to populate...");
                
                // Force population and wait
                Context.Database.ExecuteSqlRaw(@"
                    ALTER FULLTEXT INDEX ON SearchTargets START FULL POPULATION;
                ");

                // Wait longer for indexing to complete
                System.Threading.Thread.Sleep(5000);
                
                // Force another population to be sure
                Context.Database.ExecuteSqlRaw(@"
                    ALTER FULLTEXT INDEX ON SearchTargets START FULL POPULATION;
                ");
                
                // Additional wait
                System.Threading.Thread.Sleep(2000);

                // Check if full-text service is running
                var ftsStatus = Context.Database.SqlQuery<int>($@"
                    SELECT FULLTEXTSERVICEPROPERTY('IsFullTextInstalled')
                ").ToList().FirstOrDefault();

                Output.WriteLine($"✓ Full-text index created successfully (FTS Installed: {ftsStatus == 1})");
            }
            catch (Exception ex)
            {
                Output.WriteLine($"⚠️ Full-text index creation warning: {ex.Message}");
                // Don't throw - FTS might not be available in all SQL Server configurations
            }
        }

        private void SeedTestData()
        {
            var testData = new[]
            {
                new SearchTarget { Texts = "apple banana cherry fruit healthy food" },
                new SearchTarget { Texts = "dog cat mouse animal pet domestic" },
                new SearchTarget { Texts = "red blue green apple color bright" },
                new SearchTarget { Texts = "technology computer software development programming" },
                new SearchTarget { Texts = "machine learning artificial intelligence python" },
                new SearchTarget { Texts = "web development javascript react angular" },
                new SearchTarget { Texts = "database sql server mysql postgresql" },
                new SearchTarget { Texts = "mobile app ios android development" },
                new SearchTarget { Texts = "cloud computing aws azure google" },
                new SearchTarget { Texts = "data science analytics visualization" }
            };

            Context.SearchTargets.AddRange(testData);
            Context.SaveChanges();

            Output.WriteLine($"✓ Seeded {testData.Length} test records");
        }

        public virtual void Dispose()
        {
            try
            {
                Output.WriteLine($"Cleaning up test database: {DatabaseName}");
                Context.Database.EnsureDeleted();
                Context.Dispose();
                Output.WriteLine("✓ Test database cleaned up successfully");
            }
            catch (Exception ex)
            {
                Output.WriteLine($"⚠️ Cleanup warning: {ex.Message}");
            }
        }
    }
}