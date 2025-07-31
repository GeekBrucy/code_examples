using API.Utils;
using Xunit.Abstractions;

namespace API.Tests.Utils
{
    public class BooleanSearchValidatorTests
    {
        private readonly ITestOutputHelper _output;

        public BooleanSearchValidatorTests(ITestOutputHelper output)
        {
            _output = output;
        }

        #region Valid Queries - Should Pass

        [Theory]
        [InlineData("apple", "Simple word")]
        [InlineData("apple banana", "Multiple words")]
        [InlineData("\"exact phrase\"", "Quoted phrase")]
        [InlineData("apple AND banana", "Basic AND")]
        [InlineData("apple OR banana", "Basic OR")]
        [InlineData("apple AND NOT banana", "AND NOT combination")]
        [InlineData("apple NEAR banana", "NEAR operator")]
        [InlineData("(apple AND banana) OR cherry", "Parentheses grouping")]
        [InlineData("\"red apple\" AND \"green banana\"", "Multiple quoted phrases")]
        [InlineData("apple*", "Wildcard at end")]
        [InlineData("appl*", "Partial wildcard")]
        [InlineData("apple AND (banana OR cherry)", "Complex grouping")]
        [InlineData("(apple OR banana) AND NOT cherry", "Complex AND NOT")]
        [InlineData("\"multi word phrase\" AND single", "Mixed phrase and word")]
        public void Validate_ValidQueries_ShouldReturnTrue(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.True(result.IsValid, $"Query should be valid: {query}. Reason: {result.Reason}");
            Assert.Empty(result.Reason);
        }

        #endregion

        #region Invalid Queries - Should Fail

        [Theory]
        [InlineData("", "Empty string")]
        [InlineData("   ", "Whitespace only")]
        [InlineData(null, "Null input")]
        public void Validate_EmptyOrNullInput_ShouldReturnFalse(string? query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.False(result.IsValid);
            Assert.Equal("Search text cannot be empty.", result.Reason);
        }

        [Theory]
        [InlineData("\"unmatched quote", "Missing closing quote")]
        [InlineData("unmatched quote\"", "Missing opening quote")]
        [InlineData("\"first quote\" and \"unmatched", "Mixed matched and unmatched")]
        [InlineData("\"\"\"triple quotes\"", "Odd number of quotes")]
        public void Validate_UnbalancedQuotes_ShouldReturnFalse(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.False(result.IsValid);
            Assert.Equal("Unbalanced quotes detected.", result.Reason);
        }

        [Theory]
        [InlineData("(apple AND banana", "Missing closing parenthesis")]
        [InlineData("apple AND banana)", "Missing opening parenthesis")]
        [InlineData("((apple AND banana)", "Unmatched nested parentheses")]
        [InlineData("apple AND (banana))", "Extra closing parenthesis")]
        [InlineData(")apple AND banana(", "Reversed parentheses")]
        public void Validate_UnbalancedParentheses_ShouldReturnFalse(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.False(result.IsValid);
            Assert.Equal("Unbalanced parentheses detected.", result.Reason);
        }

        [Theory]
        [InlineData("AND apple", "AND at beginning")]
        [InlineData("apple AND", "AND at end")]
        [InlineData("OR apple", "OR at beginning")]
        [InlineData("apple OR", "OR at end")]
        [InlineData("NEAR apple", "NEAR at beginning")]
        [InlineData("apple NEAR", "NEAR at end")]
        [InlineData("apple AND AND banana", "Consecutive ANDs")]
        [InlineData("apple OR OR banana", "Consecutive ORs")]
        public void Validate_InvalidBooleanOperatorPosition_ShouldReturnFalse(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.False(result.IsValid);
            Assert.Equal("Invalid CONTAINS query syntax.", result.Reason);
        }

        [Theory]
        [InlineData("NOT apple", "NOT at beginning")]
        [InlineData("apple NOT banana", "NOT without AND")]
        [InlineData("apple OR NOT banana", "NOT after OR")]
        [InlineData("apple AND NOT", "NOT at end")]
        [InlineData("apple NEAR NOT banana", "NOT after NEAR")]
        public void Validate_InvalidNotOperatorUsage_ShouldReturnFalse(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.False(result.IsValid);
            Assert.Equal("Invalid CONTAINS query syntax.", result.Reason);
        }

        [Theory]
        [InlineData("apple*banana", "Wildcard in middle")]
        [InlineData("ap*ple", "Wildcard in middle of word")]
        [InlineData("*apple", "Wildcard at beginning")]
        [InlineData("app**le", "Multiple wildcards in middle")]
        public void Validate_InvalidWildcardPlacement_ShouldReturnFalse(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.False(result.IsValid);
            Assert.Equal("Invalid CONTAINS query syntax.", result.Reason);
        }

        #endregion

        #region Edge Cases and SQL Server Specific Rules

        [Theory]
        [InlineData("apple and banana", "Lowercase operators should work")]
        [InlineData("apple And banana", "Mixed case operators should work")]
        [InlineData("apple AnD banana", "Weird case operators should work")]
        public void Validate_CaseInsensitiveOperators_ShouldReturnTrue(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.True(result.IsValid, $"Query should be valid: {query}. Reason: {result.Reason}");
        }

        [Theory]
        [InlineData("apple    AND     banana", "Multiple spaces")]
        [InlineData("  apple AND banana  ", "Leading/trailing spaces")]
        [InlineData("\tapple\tAND\tbananat", "Tabs should be normalized")]
        public void Validate_WhitespaceNormalization_ShouldReturnTrue(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.True(result.IsValid, $"Query should be valid: {query}. Reason: {result.Reason}");
        }

        [Theory]
        [InlineData("\"\"", "Empty quotes")]
        [InlineData("apple \"\" banana", "Empty quotes in middle")]
        public void Validate_EmptyQuotes_ShouldReturnTrue(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            // This might need adjustment based on your business rules
            Assert.True(result.IsValid, $"Query should be valid: {query}. Reason: {result.Reason}");
        }

        [Theory]
        [InlineData("apple-banana", "Hyphenated words")]
        [InlineData("user@domain.com", "Email addresses")]
        [InlineData("C#", "Special characters")]
        [InlineData("product_123", "Underscores")]
        [InlineData("version-2.0", "Mixed special chars")]
        public void Validate_SpecialCharacters_ShouldReturnTrue(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.True(result.IsValid, $"Query should be valid: {query}. Reason: {result.Reason}");
        }

        #endregion

        #region Complex Real-World Scenarios

        [Theory]
        [InlineData("(\"red apple\" OR \"green apple\") AND NOT \"bad apple\"", "Complex fruit search")]
        [InlineData("(software AND development) OR (web AND programming)", "Tech job search")]
        [InlineData("\"machine learning\" AND (python OR java OR \"c#\")", "ML language search")]
        [InlineData("(car OR automobile) AND NOT (truck OR motorcycle)", "Vehicle search with exclusions")]
        public void Validate_ComplexRealWorldQueries_ShouldReturnTrue(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.True(result.IsValid, $"Complex query should be valid: {query}. Reason: {result.Reason}");
        }

        [Theory]
        [InlineData("((apple AND banana) OR (cherry AND date", "Unbalanced complex parentheses")]
        [InlineData("\"machine learning AND python", "Quote crosses boolean operator")]
        [InlineData("apple AND NOT OR banana", "Invalid operator sequence")]
        [InlineData("(AND apple) OR banana", "Operator in wrong position within parentheses")]
        public void Validate_ComplexInvalidQueries_ShouldReturnFalse(string query, string description)
        {
            _output.WriteLine($"Testing: {description} - '{query}'");

            var result = BooleanSearchValidator.Validate(query);

            Assert.False(result.IsValid, $"Complex invalid query should fail: {query}");
            Assert.NotEmpty(result.Reason);
        }

        #endregion

        #region Performance and Stress Tests

        [Fact]
        public void Validate_VeryLongValidQuery_ShouldHandle()
        {
            var longQuery = string.Join(" AND ", Enumerable.Range(1, 100).Select(i => $"word{i}"));
            _output.WriteLine($"Testing long query with {longQuery.Split(' ').Length} tokens");

            var result = BooleanSearchValidator.Validate(longQuery);

            Assert.True(result.IsValid, $"Long query should be valid. Reason: {result.Reason}");
        }

        [Fact]
        public void Validate_ManyNestedParentheses_ShouldHandle()
        {
            var nestedQuery = new string('(', 50) + "apple" + new string(')', 50);
            _output.WriteLine($"Testing deeply nested parentheses: {nestedQuery.Length} characters");

            var result = BooleanSearchValidator.Validate(nestedQuery);

            Assert.True(result.IsValid, $"Nested query should be valid. Reason: {result.Reason}");
        }

        #endregion
    }
}