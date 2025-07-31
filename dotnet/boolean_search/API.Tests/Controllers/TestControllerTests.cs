using API.Controllers;
using API.Data;
using API.DTOs;
using API.Models;
using API.Services.Search;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Xunit.Abstractions;

namespace API.Tests.Controllers
{
    public class TestControllerTests : IDisposable
    {
        private readonly MyDbContext _context;
        private readonly SearchService _searchService;
        private readonly TestController _controller;
        private readonly ITestOutputHelper _output;
        private readonly string _dbPath;

        public TestControllerTests(ITestOutputHelper output)
        {
            _output = output;
            _dbPath = $"test_{Guid.NewGuid()}.db";

            var options = new DbContextOptionsBuilder<MyDbContext>()
                .UseSqlite($"Data Source={_dbPath}")
                .Options;

            _context = new MyDbContext(options);
            _context.Database.EnsureCreated();
            
            // Use the REAL SearchService - no mocking, no test doubles
            _searchService = new SearchService(_context);
            _controller = new TestController(_searchService);

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
        public async Task FullTextQuery_ValidPayload_ReturnsOkWithResults()
        {
            var payload = new FullTextPayload { FreeText = "apple" };

            var result = await _controller.FullTextQuery(payload);

            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedData = Assert.IsAssignableFrom<List<SearchTarget>>(okResult.Value);

            _output.WriteLine($"Search term: {payload.FreeText}");
            _output.WriteLine($"Results count: {returnedData.Count}");
            foreach (var item in returnedData)
            {
                _output.WriteLine($"  ID: {item.Id}, Text: {item.Texts}");
            }

            Assert.Equal(2, returnedData.Count);
            Assert.All(returnedData, item => Assert.Contains("apple", item.Texts));
            Assert.Contains(returnedData, item => item.Id == 1);
            Assert.Contains(returnedData, item => item.Id == 3);
        }

        [Fact]
        public async Task FullTextQuery_EmptyResults_ReturnsOkWithEmptyList()
        {
            var payload = new FullTextPayload { FreeText = "nonexistent" };

            var result = await _controller.FullTextQuery(payload);

            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedData = Assert.IsAssignableFrom<List<SearchTarget>>(okResult.Value);

            _output.WriteLine($"Search term: {payload.FreeText}");
            _output.WriteLine($"Results count: {returnedData.Count}");

            Assert.Empty(returnedData);
        }

        [Fact]
        public async Task FullTextQuery_InvalidPayload_ReturnsBadRequest()
        {
            var payload = new FullTextPayload { FreeText = "apple AND" };

            var result = await _controller.FullTextQuery(payload);

            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
            Assert.Equal("Invalid payload", badRequestResult.Value);

            _output.WriteLine($"Invalid search term: {payload.FreeText}");
            _output.WriteLine($"Result: {badRequestResult.Value}");
        }

        [Fact]
        public async Task FullTextQuery_NullPayload_ReturnsBadRequest()
        {
            var payload = new FullTextPayload { FreeText = null! };

            var result = await _controller.FullTextQuery(payload);

            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
            Assert.Equal("Invalid payload", badRequestResult.Value);

            _output.WriteLine("Testing null payload");
            _output.WriteLine($"Result: {badRequestResult.Value}");
        }

        [Theory]
        [InlineData("apple", 2)]
        [InlineData("technology", 1)]
        [InlineData("dog", 1)]
        [InlineData("nonexistent", 0)]
        public async Task FullTextQuery_VariousValidInputs_ReturnsCorrectResults(string searchText, int expectedCount)
        {
            var payload = new FullTextPayload { FreeText = searchText };

            var result = await _controller.FullTextQuery(payload);

            var okResult = Assert.IsType<OkObjectResult>(result.Result);
            var returnedData = Assert.IsAssignableFrom<List<SearchTarget>>(okResult.Value);

            _output.WriteLine($"Testing search term: {searchText}");
            _output.WriteLine($"Expected count: {expectedCount}, Actual count: {returnedData.Count}");

            Assert.Equal(expectedCount, returnedData.Count);
            if (expectedCount > 0)
            {
                Assert.All(returnedData, item => Assert.Contains(searchText, item.Texts));
            }
        }

        [Theory]
        [InlineData("apple AND")]
        [InlineData("\"unmatched quote")]
        [InlineData("((unbalanced")]
        public async Task FullTextQuery_InvalidQueries_ReturnsBadRequest(string invalidQuery)
        {
            var payload = new FullTextPayload { FreeText = invalidQuery };

            var result = await _controller.FullTextQuery(payload);

            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
            Assert.Equal("Invalid payload", badRequestResult.Value);

            _output.WriteLine($"Invalid query: {invalidQuery}");
        }

        public void Dispose()
        {
            _context.Dispose();
            if (File.Exists(_dbPath))
            {
                File.Delete(_dbPath);
            }
        }
    }
}