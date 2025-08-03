using API.Utils;
using Xunit.Abstractions;

namespace API.Tests.Utils
{
    public class BooleanSearchValidatorEdgeCaseTests
    {
        private readonly ITestOutputHelper _output;

        public BooleanSearchValidatorEdgeCaseTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [Theory]
        [InlineData("apple", true, "Single word")]
        [InlineData("apple banana", true, "Multiple words (implicit AND)")]
        [InlineData("\"exact phrase\"", true, "Quoted phrase")]
        [InlineData("apple*", true, "Prefix term")]
        [InlineData("apple AND banana", true, "Explicit AND")]
        [InlineData("apple OR banana", true, "OR operator")]
        [InlineData("apple AND NOT banana", true, "AND NOT combination")]
        [InlineData("(apple OR banana) AND cherry", true, "Parentheses grouping")]
        [InlineData("\"red apple\" OR \"green apple\"", true, "Multiple quoted phrases with OR")]
        [InlineData("apple NEAR banana", true, "NEAR operator")]
        public void Validate_ValidContainsQueries_ShouldReturnTrue(string query, bool expectedValid, string description)
        {
            _output.WriteLine($"Testing valid: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.True(result.IsValid, $"Query should be valid: {query}. Reason: {result.Reason}");
            Assert.Empty(result.Reason);
        }

        [Theory]
        [InlineData("NOT apple", false, "NOT cannot start query")]
        [InlineData("apple NOT banana", false, "NOT without AND")]
        [InlineData("apple OR NOT banana", false, "NOT after OR")]
        [InlineData("*apple", false, "Wildcard at beginning")]
        [InlineData("ap*ple", false, "Wildcard in middle")]
        [InlineData("\"unmatched quote", false, "Unbalanced quotes")]
        [InlineData("(apple AND banana", false, "Unbalanced parentheses")]
        [InlineData("AND apple", false, "AND at beginning")]
        [InlineData("apple AND", false, "AND at end")]
        [InlineData("apple OR", false, "OR at end")]
        [InlineData("apple NEAR", false, "NEAR at end")]
        [InlineData("", false, "Empty string")]
        [InlineData("   ", false, "Whitespace only")]
        public void Validate_InvalidContainsQueries_ShouldReturnFalse(string query, bool expectedValid, string description)
        {
            _output.WriteLine($"Testing invalid: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.False(result.IsValid, $"Query should be invalid: {query}");
            Assert.NotEmpty(result.Reason);
        }
    }
}