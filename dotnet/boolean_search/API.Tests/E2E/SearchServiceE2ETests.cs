using API.DTOs;
using API.Services.Search;
using Microsoft.EntityFrameworkCore;
using Xunit.Abstractions;

namespace API.Tests.E2E
{
    [Collection("SqlServer E2E Tests")] // Ensure tests run sequentially to avoid database conflicts
    public class SearchServiceE2ETests : SqlServerE2ETestBase
    {
        private readonly SearchService _searchService;

        public SearchServiceE2ETests(ITestOutputHelper output) : base(output)
        {
            _searchService = new SearchService(Context);
        }

        [Fact]
        public async Task BuildQuery_SimpleWord_ReturnsMatchingRecords()
        {
            var payload = new FullTextPayload { FreeText = "apple" };

            var query = _searchService.BuildQuery(payload);
            var results = await query!.ToListAsync();

            Output.WriteLine($"Search: '{payload.FreeText}' -> {results.Count} results");
            foreach (var result in results)
            {
                Output.WriteLine($"  ID: {result.Id}, Text: {result.Texts}");
            }

            Assert.NotNull(query);
            Assert.True(results.Count >= 1, "Should find at least one record containing 'apple'");
            Assert.All(results, item => Assert.Contains("apple", item.Texts));
        }

        [Fact]
        public async Task BuildQuery_BooleanAND_ReturnsIntersectionResults()
        {
            var payload = new FullTextPayload { FreeText = "machine AND learning" };

            var query = _searchService.BuildQuery(payload);
            var results = await query!.ToListAsync();

            Output.WriteLine($"Search: '{payload.FreeText}' -> {results.Count} results");
            foreach (var result in results)
            {
                Output.WriteLine($"  ID: {result.Id}, Text: {result.Texts}");
            }

            Assert.NotNull(query);
            Assert.True(results.Count >= 1, "Should find records containing both 'machine' AND 'learning'");
            Assert.All(results, item => 
            {
                Assert.Contains("machine", item.Texts);
                Assert.Contains("learning", item.Texts);
            });
        }

        [Fact]
        public async Task BuildQuery_BooleanOR_ReturnsUnionResults()
        {
            var payload = new FullTextPayload { FreeText = "python OR javascript" };

            var query = _searchService.BuildQuery(payload);
            var results = await query!.ToListAsync();

            Output.WriteLine($"Search: '{payload.FreeText}' -> {results.Count} results");
            foreach (var result in results)
            {
                Output.WriteLine($"  ID: {result.Id}, Text: {result.Texts}");
            }

            Assert.NotNull(query);
            Assert.True(results.Count >= 1, "Should find records containing 'python' OR 'javascript'");
            Assert.All(results, item => 
                Assert.True(item.Texts.Contains("python") || item.Texts.Contains("javascript"),
                    $"Record should contain 'python' or 'javascript': {item.Texts}"));
        }

        [Fact]
        public async Task BuildQuery_BooleanANDNOT_ReturnsExcludingResults()
        {
            var payload = new FullTextPayload { FreeText = "development AND NOT mobile" };

            var query = _searchService.BuildQuery(payload);
            var results = await query!.ToListAsync();

            Output.WriteLine($"Search: '{payload.FreeText}' -> {results.Count} results");
            foreach (var result in results)
            {
                Output.WriteLine($"  ID: {result.Id}, Text: {result.Texts}");
            }

            Assert.NotNull(query);
            // Should find records with 'development' but NOT 'mobile'
            Assert.All(results, item => 
            {
                Assert.Contains("development", item.Texts);
                Assert.DoesNotContain("mobile", item.Texts);
            });
        }

        [Fact]
        public async Task BuildQuery_QuotedPhrase_ReturnsExactPhraseMatches()
        {
            var payload = new FullTextPayload { FreeText = "\"machine learning\"" };

            var query = _searchService.BuildQuery(payload);
            var results = await query!.ToListAsync();

            Output.WriteLine($"Search: '{payload.FreeText}' -> {results.Count} results");
            foreach (var result in results)
            {
                Output.WriteLine($"  ID: {result.Id}, Text: {result.Texts}");
            }

            Assert.NotNull(query);
            Assert.True(results.Count >= 1, "Should find records containing exact phrase 'machine learning'");
            Assert.All(results, item => Assert.Contains("machine learning", item.Texts));
        }

        [Fact]
        public async Task BuildQuery_ComplexBooleanQuery_ReturnsCorrectResults()
        {
            var payload = new FullTextPayload { FreeText = "(web OR mobile) AND development" };

            var query = _searchService.BuildQuery(payload);
            var results = await query!.ToListAsync();

            Output.WriteLine($"Search: '{payload.FreeText}' -> {results.Count} results");
            foreach (var result in results)
            {
                Output.WriteLine($"  ID: {result.Id}, Text: {result.Texts}");
            }

            Assert.NotNull(query);
            Assert.True(results.Count >= 1, "Should find records matching complex boolean query");
            Assert.All(results, item => 
            {
                Assert.Contains("development", item.Texts);
                Assert.True(item.Texts.Contains("web") || item.Texts.Contains("mobile"),
                    $"Record should contain 'web' or 'mobile': {item.Texts}");
            });
        }

        [Fact]
        public async Task BuildQuery_NonexistentTerm_ReturnsEmptyResults()
        {
            var payload = new FullTextPayload { FreeText = "nonexistent_term_12345" };

            var query = _searchService.BuildQuery(payload);
            var results = await query!.ToListAsync();

            Output.WriteLine($"Search: '{payload.FreeText}' -> {results.Count} results");

            Assert.NotNull(query);
            Assert.Empty(results);
        }

        [Fact]
        public void BuildQuery_InvalidBooleanSyntax_ReturnsNull()
        {
            var payload = new FullTextPayload { FreeText = "apple AND" };

            var query = _searchService.BuildQuery(payload);

            Output.WriteLine($"Invalid search: '{payload.FreeText}' -> {(query == null ? "NULL" : "Valid query")}");

            Assert.Null(query);
        }

        [Theory]
        [InlineData("apple")]
        [InlineData("technology AND computer")]
        [InlineData("web OR mobile")]
        [InlineData("\"data science\"")]
        [InlineData("development AND NOT mobile")]
        public async Task BuildQuery_VariousValidQueries_ExecuteSuccessfully(string searchTerm)
        {
            var payload = new FullTextPayload { FreeText = searchTerm };

            var query = _searchService.BuildQuery(payload);
            var results = await query!.ToListAsync();

            Output.WriteLine($"Search: '{searchTerm}' -> {results.Count} results");
            
            Assert.NotNull(query);
            // Results can be empty for some searches, but query should execute without error
            Assert.True(results.Count >= 0);
        }

        [Fact]
        public async Task BuildQuery_PerformanceTest_ExecutesQuickly()
        {
            var payload = new FullTextPayload { FreeText = "development OR technology OR data" };

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            var query = _searchService.BuildQuery(payload);
            var results = await query!.ToListAsync();
            
            stopwatch.Stop();

            Output.WriteLine($"Performance test: '{payload.FreeText}' -> {results.Count} results in {stopwatch.ElapsedMilliseconds}ms");

            Assert.NotNull(query);
            Assert.True(stopwatch.ElapsedMilliseconds < 1000, "Query should execute in less than 1 second");
            Assert.True(results.Count >= 0);
        }
    }
}