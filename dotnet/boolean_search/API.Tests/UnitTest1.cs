using API.Utils;

namespace API.Tests
{
    public class BooleanSearchValidatorTests
    {
        [Theory]
        [InlineData("apple", true)]
        [InlineData("apple AND banana", true)]
        [InlineData("\"exact phrase\"", true)]
        [InlineData("apple OR banana", true)]
        [InlineData("apple AND NOT banana", true)]
        public void Validate_ValidQueries_ReturnsTrue(string query, bool expected)
        {
            var result = BooleanSearchValidator.Validate(query);
            Assert.Equal(expected, result.IsValid);
        }

        [Theory]
        [InlineData("", false)]
        [InlineData(null, false)]
        [InlineData("apple AND", false)]
        [InlineData("\"unmatched quote", false)]
        [InlineData("((unbalanced", false)]
        public void Validate_InvalidQueries_ReturnsFalse(string query, bool expected)
        {
            var result = BooleanSearchValidator.Validate(query);
            Assert.Equal(expected, result.IsValid);
        }
    }
}
