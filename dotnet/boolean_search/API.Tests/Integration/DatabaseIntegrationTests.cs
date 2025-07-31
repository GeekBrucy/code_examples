using API.Controllers;
using API.Data;
using API.DTOs;
using API.Models;
using API.Tests.TestHelpers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Xunit.Abstractions;

namespace API.Tests.Integration
{
    public class DatabaseIntegrationTests : IDisposable
    {
        private readonly MyDbContext _context;
        private readonly TestableSearchService _searchService;
        private readonly TestController _controller;
        private readonly ITestOutputHelper _output;

        public DatabaseIntegrationTests(ITestOutputHelper output)
        {
            _output = output;
            var options = new DbContextOptionsBuilder<MyDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new MyDbContext(options);
            _searchService = new TestableSearchService(_context);
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
        public async Task DatabaseIntegration_SearchForApple_ReturnsCorrectResults()
        {
            var payload = new FullTextPayload { FreeText = "apple" };

            var query = _searchService.BuildQuery(payload);
            var results = await query!.ToListAsync();

            _output.WriteLine($"Search term: {payload.FreeText}");
            _output.WriteLine($"Results count: {results.Count}");
            foreach (var result in results)
            {
                _output.WriteLine($"  ID: {result.Id}, Text: {result.Texts}");
            }

            Assert.Equal(3, results.Count);
            Assert.All(results, item => Assert.Contains("apple", item.Texts));
            Assert.Contains(results, item => item.Id == 1);
            Assert.Contains(results, item => item.Id == 3);
            Assert.Contains(results, item => item.Id == 5);
        }

        [Theory]
        [InlineData("technology", 2)]
        [InlineData("animal", 1)]
        [InlineData("fruit", 1)]
        [InlineData("nonexistent", 0)]
        public async Task DatabaseIntegration_VariousSearchTerms_ReturnsCorrectCounts(string searchTerm, int expectedCount)
        {
            var payload = new FullTextPayload { FreeText = searchTerm };

            var query = _searchService.BuildQuery(payload);
            var results = await query!.ToListAsync();

            Assert.Equal(expectedCount, results.Count);
        }

        [Fact]
        public async Task DatabaseIntegration_DatabaseConnection_WorksCorrectly()
        {
            var totalRecords = await _context.SearchTargets.CountAsync();
            Assert.Equal(6, totalRecords);

            var appleRecords = await _context.SearchTargets
                .Where(st => st.Texts.Contains("apple"))
                .CountAsync();
            Assert.Equal(3, appleRecords);
        }

        [Fact]
        public async Task DatabaseIntegration_MultipleQueries_ReturnDifferentResults()
        {
            var applePayload = new FullTextPayload { FreeText = "apple" };
            var techPayload = new FullTextPayload { FreeText = "technology" };

            var appleQuery = _searchService.BuildQuery(applePayload);
            var techQuery = _searchService.BuildQuery(techPayload);

            var appleResults = await appleQuery!.ToListAsync();
            var techResults = await techQuery!.ToListAsync();

            Assert.Equal(3, appleResults.Count);
            Assert.Equal(2, techResults.Count);
            Assert.All(appleResults, item => Assert.Contains("apple", item.Texts));
            Assert.All(techResults, item => Assert.Contains("technology", item.Texts));
        }

        [Fact]
        public void DatabaseIntegration_InvalidQuery_ReturnsNull()
        {
            var payload = new FullTextPayload { FreeText = "apple AND" };

            var query = _searchService.BuildQuery(payload);

            Assert.Null(query);
        }

        public void Dispose()
        {
            _context.Dispose();
        }
    }
}