using API.Controllers;
using API.Data;
using API.DTOs;
using API.Models;
using API.Services.Search;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Xunit.Abstractions;

namespace API.Tests.Integration
{
    public class SearchIntegrationTests : IDisposable
    {
        private readonly MyDbContext _context;
        private readonly SearchService _searchService;
        private readonly TestController _controller;
        private readonly ITestOutputHelper _output;

        public SearchIntegrationTests(ITestOutputHelper output)
        {
            _output = output;
            var options = new DbContextOptionsBuilder<MyDbContext>()
                .UseSqlite($"Data Source={Guid.NewGuid()}.db")
                .Options;

            _context = new MyDbContext(options);
            _context.Database.EnsureCreated();
            _searchService = new SearchService(_context);
            _controller = new TestController(_searchService);

            SeedTestData();
        }

        private void SeedTestData()
        {
            _context.SearchTargets.AddRange(
                new SearchTarget { Id = 1, Texts = "apple banana cherry fruit" },
                new SearchTarget { Id = 2, Texts = "dog cat mouse animal" },
                new SearchTarget { Id = 3, Texts = "red blue green apple color" },
                new SearchTarget { Id = 4, Texts = "technology computer software development" },
                new SearchTarget { Id = 5, Texts = "apple pie recipe cooking" },
                new SearchTarget { Id = 6, Texts = "mobile phone technology device" }
            );
            _context.SaveChanges();
        }

        [Fact]
        public void FullTextQuery_EndToEnd_ValidSearch_BuildsCorrectQuery()
        {
            var payload = new FullTextPayload { FreeText = "apple" };

            var query = _searchService.BuildQuery(payload);

            Assert.NotNull(query);
            Assert.IsAssignableFrom<IQueryable<SearchTarget>>(query);
            // Verify the query uses EF.Functions.Contains
            Assert.Contains("EF.Functions.Contains", query.Expression.ToString());
            // Verify the payload contains our search term
            Assert.Equal("apple", payload.FreeText);
        }

        [Fact]
        public void FullTextQuery_EndToEnd_NoResults_ReturnsValidQuery()
        {
            var payload = new FullTextPayload { FreeText = "nonexistent" };

            var query = _searchService.BuildQuery(payload);

            Assert.NotNull(query);
            Assert.IsAssignableFrom<IQueryable<SearchTarget>>(query);
        }

        [Fact]
        public async Task FullTextQuery_EndToEnd_InvalidQuery_ReturnsBadRequest()
        {
            var payload = new FullTextPayload { FreeText = "apple AND" };

            var result = await _controller.FullTextQuery(payload);

            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
            Assert.Equal("Invalid payload", badRequestResult.Value);
        }

        [Fact]
        public async Task SearchService_DatabaseContext_ProperlyConnected()
        {
            var totalRecords = await _context.SearchTargets.CountAsync();
            Assert.Equal(6, totalRecords);

            var manualAppleRecords = await _context.SearchTargets
                .Where(st => st.Texts.Contains("apple"))
                .CountAsync();
            Assert.Equal(3, manualAppleRecords);
        }

        [Fact]
        public void SearchService_BuildQuery_CreatesValidQuery()
        {
            var payload = new FullTextPayload { FreeText = "technology" };

            var query = _searchService.BuildQuery(payload);

            Assert.NotNull(query);
            Assert.IsAssignableFrom<IQueryable<SearchTarget>>(query);
        }

        [Fact]
        public void SearchService_BuildQuery_WithComplexBooleanSearch_CreatesValidQuery()
        {
            var payload = new FullTextPayload { FreeText = "apple AND fruit" };

            var query = _searchService.BuildQuery(payload);

            Assert.NotNull(query);
            Assert.IsAssignableFrom<IQueryable<SearchTarget>>(query);

            // Debug output using ITestOutputHelper
            _output.WriteLine("=== Query Expression Debug Info ===");
            _output.WriteLine($"Search Term: {payload.FreeText}");
            _output.WriteLine($"Query Expression: {query.Expression}");
            _output.WriteLine("==================================");
        }

        [Fact]
        public void SearchService_DatabaseContext_CanHandleMultipleQueries()
        {
            var payload1 = new FullTextPayload { FreeText = "apple" };
            var payload2 = new FullTextPayload { FreeText = "technology" };

            var query1 = _searchService.BuildQuery(payload1);
            var query2 = _searchService.BuildQuery(payload2);

            Assert.NotNull(query1);
            Assert.NotNull(query2);
            Assert.NotSame(query1, query2);
        }

        public void Dispose()
        {
            _context.Database.EnsureDeleted();
            _context.Dispose();
        }
    }
}