using API.Data;
using API.DTOs;
using API.Models;
using API.Services.Search;
using Microsoft.EntityFrameworkCore;

namespace API.Tests.Services
{
    public class SearchServiceTests : IDisposable
    {
        private readonly MyDbContext _context;
        private readonly SearchService _searchService;

        public SearchServiceTests()
        {
            var options = new DbContextOptionsBuilder<MyDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new MyDbContext(options);
            _searchService = new SearchService(_context);

            SeedTestData();
        }

        private void SeedTestData()
        {
            _context.SearchTargets.AddRange(
                new SearchTarget { Id = 1, Texts = "apple banana cherry" },
                new SearchTarget { Id = 2, Texts = "dog cat mouse" },
                new SearchTarget { Id = 3, Texts = "red blue green apple" },
                new SearchTarget { Id = 4, Texts = "technology computer software" }
            );
            _context.SaveChanges();
        }

        [Fact]
        public void BuildQuery_ValidPayload_ReturnsQueryable()
        {
            var payload = new FullTextPayload { FreeText = "apple" };

            var result = _searchService.BuildQuery(payload);

            Assert.NotNull(result);
            Assert.IsAssignableFrom<IQueryable<SearchTarget>>(result);
        }

        [Fact]
        public void BuildQuery_InvalidPayload_ReturnsNull()
        {
            var payload = new FullTextPayload { FreeText = "apple AND" };

            var result = _searchService.BuildQuery(payload);

            Assert.Null(result);
        }

        [Fact]
        public void BuildQuery_EmptyPayload_ReturnsNull()
        {
            var payload = new FullTextPayload { FreeText = "" };

            var result = _searchService.BuildQuery(payload);

            Assert.Null(result);
        }

        [Fact]
        public void BuildQuery_NullPayload_ReturnsNull()
        {
            var payload = new FullTextPayload { FreeText = null };

            var result = _searchService.BuildQuery(payload);

            Assert.Null(result);
        }

        [Fact]
        public void BuildQuery_ValidSearch_ReturnsQueryableWithCorrectStructure()
        {
            var payload = new FullTextPayload { FreeText = "apple" };

            var query = _searchService.BuildQuery(payload);

            Assert.NotNull(query);
            Assert.IsAssignableFrom<IQueryable<SearchTarget>>(query);
        }

        [Fact]
        public void BuildQuery_ValidSearch_QueryContainsCorrectExpression()
        {
            var payload = new FullTextPayload { FreeText = "apple" };

            var query = _searchService.BuildQuery(payload);

            Assert.NotNull(query);
            Assert.Contains("Contains", query.Expression.ToString());
        }

        [Theory]
        [InlineData("apple AND banana")]
        [InlineData("\"red blue\"")]
        [InlineData("computer OR software")]
        public void BuildQuery_ValidBooleanQueries_ReturnsQueryable(string query)
        {
            var payload = new FullTextPayload { FreeText = query };

            var result = _searchService.BuildQuery(payload);

            Assert.NotNull(result);
        }

        [Theory]
        [InlineData("apple AND")]
        [InlineData("\"unmatched quote")]
        [InlineData("((unbalanced")]
        public void BuildQuery_InvalidBooleanQueries_ReturnsNull(string query)
        {
            var payload = new FullTextPayload { FreeText = query };

            var result = _searchService.BuildQuery(payload);

            Assert.Null(result);
        }

        public void Dispose()
        {
            _context.Dispose();
        }
    }
}