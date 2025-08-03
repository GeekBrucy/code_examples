using API.Controllers;
using API.DTOs;
using API.Services.Search;
using Microsoft.AspNetCore.Mvc;
using Xunit.Abstractions;

namespace API.Tests.E2E
{
    [Collection("SqlServer E2E Tests")] // Ensure tests run sequentially to avoid database conflicts
    public class ControllerE2ETests : SqlServerE2ETestBase
    {
        private readonly SearchService _searchService;
        private readonly TestController _controller;

        public ControllerE2ETests(ITestOutputHelper output) : base(output)
        {
            _searchService = new SearchService(Context);
            _controller = new TestController(_searchService);
        }

        [Fact]
        public async Task FullTextQuery_EndToEnd_SimpleSearch_ReturnsOkWithResults()
        {
            var payload = new FullTextPayload { FreeText = "apple" };

            var result = await _controller.FullTextQuery(payload);

            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var data = Assert.IsAssignableFrom<List<API.Models.SearchTarget>>(okResult.Value);

            Output.WriteLine($"E2E Search: '{payload.FreeText}' -> {data.Count} results");
            foreach (var item in data)
            {
                Output.WriteLine($"  ID: {item.Id}, Text: {item.Texts}");
            }

            Assert.True(data.Count >= 1, "Should find at least one result");
            Assert.All(data, item => Assert.Contains("apple", item.Texts));
        }

        [Fact]
        public async Task FullTextQuery_EndToEnd_BooleanSearch_ReturnsCorrectResults()
        {
            var payload = new FullTextPayload { FreeText = "technology AND computer" };

            var result = await _controller.FullTextQuery(payload);

            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var data = Assert.IsAssignableFrom<List<API.Models.SearchTarget>>(okResult.Value);

            Output.WriteLine($"E2E Boolean Search: '{payload.FreeText}' -> {data.Count} results");
            foreach (var item in data)
            {
                Output.WriteLine($"  ID: {item.Id}, Text: {item.Texts}");
            }

            Assert.True(data.Count >= 1, "Should find records with both 'technology' AND 'computer'");
            Assert.All(data, item => 
            {
                Assert.Contains("technology", item.Texts);
                Assert.Contains("computer", item.Texts);
            });
        }

        [Fact]
        public async Task FullTextQuery_EndToEnd_InvalidQuery_ReturnsBadRequest()
        {
            var payload = new FullTextPayload { FreeText = "apple AND" };

            var result = await _controller.FullTextQuery(payload);

            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
            Assert.Equal("Invalid payload", badRequestResult.Value);

            Output.WriteLine($"E2E Invalid Query: '{payload.FreeText}' -> Bad Request (Expected)");
        }

        [Fact]
        public async Task FullTextQuery_EndToEnd_EmptyResults_ReturnsOkWithEmptyList()
        {
            var payload = new FullTextPayload { FreeText = "nonexistent_term_xyz123" };

            var result = await _controller.FullTextQuery(payload);

            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var data = Assert.IsAssignableFrom<List<API.Models.SearchTarget>>(okResult.Value);

            Output.WriteLine($"E2E Empty Results: '{payload.FreeText}' -> {data.Count} results (Expected: 0)");

            Assert.Empty(data);
        }

        [Fact]
        public async Task FullTextQuery_EndToEnd_ComplexQuery_ExecutesSuccessfully()
        {
            var payload = new FullTextPayload { FreeText = "(\"machine learning\" OR \"data science\") AND python" };

            var result = await _controller.FullTextQuery(payload);

            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var data = Assert.IsAssignableFrom<List<API.Models.SearchTarget>>(okResult.Value);

            Output.WriteLine($"E2E Complex Query: '{payload.FreeText}' -> {data.Count} results");
            foreach (var item in data)
            {
                Output.WriteLine($"  ID: {item.Id}, Text: {item.Texts}");
            }

            // Complex query should execute without error, results may vary
            Assert.True(data.Count >= 0);
        }

        [Theory]
        [InlineData("development")]
        [InlineData("web OR mobile")]
        [InlineData("\"artificial intelligence\"")]
        [InlineData("database AND sql")]
        [InlineData("cloud AND NOT aws")]
        public async Task FullTextQuery_EndToEnd_VariousQueries_AllExecuteSuccessfully(string searchText)
        {
            var payload = new FullTextPayload { FreeText = searchText };

            var result = await _controller.FullTextQuery(payload);

            // Should either return OK with results or OK with empty results
            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var data = Assert.IsAssignableFrom<List<API.Models.SearchTarget>>(okResult.Value);

            Output.WriteLine($"E2E Query '{searchText}' -> {data.Count} results");

            Assert.True(data.Count >= 0, "Query should execute successfully");
        }

        [Fact]
        public async Task FullTextQuery_EndToEnd_StressTest_HandlesMultipleQueries()
        {
            var queries = new[]
            {
                "apple",
                "technology AND computer",
                "web OR mobile",
                "\"machine learning\"",
                "development AND NOT mobile",
                "database",
                "python",
                "cloud"
            };

            var allResults = new List<(string Query, int ResultCount)>();

            foreach (var queryText in queries)
            {
                var payload = new FullTextPayload { FreeText = queryText };
                var result = await _controller.FullTextQuery(payload);
                
                var okResult = Assert.IsType<OkObjectResult>(result.Result);
                var data = Assert.IsAssignableFrom<List<API.Models.SearchTarget>>(okResult.Value);
                
                allResults.Add((queryText, data.Count));
            }

            Output.WriteLine("E2E Stress Test Results:");
            foreach (var (query, count) in allResults)
            {
                Output.WriteLine($"  '{query}' -> {count} results");
            }

            Assert.True(allResults.Count == queries.Length, "All queries should execute successfully");
            Assert.All(allResults, result => Assert.True(result.ResultCount >= 0, "All queries should return valid results"));
        }
    }
}