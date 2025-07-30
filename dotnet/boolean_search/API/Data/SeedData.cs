using API.Models;
using Microsoft.EntityFrameworkCore;

namespace API.Data
{
    public static class SeedData
    {
        public static void Initialize(MyDbContext context)
        {
            context.Database.EnsureCreated();

            if (context.SearchTargets.Any())
            {
                return; // DB has been seeded
            }

            var searchTargets = new SearchTarget[]
            {
                new SearchTarget { Texts = "The quick brown fox jumps over the lazy dog" },
                new SearchTarget { Texts = "Programming with C# and .NET is powerful and efficient" },
                new SearchTarget { Texts = "Entity Framework Core provides excellent database access" },
                new SearchTarget { Texts = "Full-text search enables advanced text queries" },
                new SearchTarget { Texts = "Boolean search operators include AND, OR, and NOT" },
                new SearchTarget { Texts = "SQL Server supports complex query operations" },
                new SearchTarget { Texts = "Docker containers simplify development environment setup" },
                new SearchTarget { Texts = "Microservices architecture promotes scalability" },
                new SearchTarget { Texts = "REST APIs enable communication between services" },
                new SearchTarget { Texts = "Database indexing improves query performance dramatically" },
                new SearchTarget { Texts = "Programming languages include C#, Java, Python, and JavaScript" },
                new SearchTarget { Texts = "Software development requires careful planning and testing" },
                new SearchTarget { Texts = "Web applications use HTML, CSS, and JavaScript for frontend" },
                new SearchTarget { Texts = "Backend services handle data processing and business logic" }
            };

            context.SearchTargets.AddRange(searchTargets);
            context.SaveChanges();
        }
    }
}