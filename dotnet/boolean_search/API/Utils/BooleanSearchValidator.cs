using System.Text.RegularExpressions;

namespace API.Utils
{
    public class BooleanSearchValidator
    {
        private static readonly Regex BooleanOperatorRegex =
            new(@"\b(AND|OR|NOT|NEAR)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public static (bool IsValid, string Reason) Validate(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return (false, "Search text cannot be empty.");

            input = Normalize(input);

            // Balanced quotes - more sophisticated check
            if (!AreQuotesBalanced(input))
                return (false, "Unbalanced quotes detected.");

            // Balanced parentheses
            if (!ParenthesesBalanced(input))
                return (false, "Unbalanced parentheses detected.");

            if (!IsValidContainsQuery(input))
                return (false, "Invalid CONTAINS query syntax.");

            return (true, string.Empty);
        }

        private static string Normalize(string input)
        {
            return Regex.Replace(input.Trim(), @"\s+", " ");
        }

        private static bool AreQuotesBalanced(string input)
        {
            var quoteCount = input.Count(c => c == '"');
            
            // Must have even number of quotes
            if (quoteCount % 2 != 0)
                return false;
                
            // Special case: check for problematic patterns like triple quotes
            if (input.Contains("\"\"\""))
                return false;
                
            // Simple balanced check - should not end inside a quote
            bool inQuote = false;
            foreach (char c in input)
            {
                if (c == '"')
                    inQuote = !inQuote;
            }
            
            return !inQuote;
        }

        private static bool ParenthesesBalanced(string input)
        {
            int balance = 0;
            foreach (var c in input)
            {
                if (c == '(') balance++;
                if (c == ')') balance--;
                if (balance < 0) return false;
            }
            return balance == 0;
        }

        private static bool IsValidContainsQuery(string input)
        {
            // First separate parentheses from words for proper tokenization
            var preprocessed = Regex.Replace(input, @"([()])", " $1 ");
            var tokens = Regex.Split(preprocessed, @"\s+")
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .ToList();

            for (int i = 0; i < tokens.Count; i++)
            {
                var token = tokens[i];

                // If token is a quoted phrase, skip operator validation
                if (token.StartsWith("\"") && token.EndsWith("\""))
                    continue;

                var upper = token.ToUpperInvariant();

                // Check for binary operators (AND, OR, NEAR)
                if (new[] { "AND", "OR", "NEAR" }.Contains(upper))
                {
                    // Cannot be first or last token
                    if (i == 0 || i == tokens.Count - 1)
                        return false;
                        
                    // Cannot immediately follow opening parenthesis
                    if (i > 0 && tokens[i - 1] == "(")
                        return false;
                        
                    // Cannot immediately precede closing parenthesis
                    if (i < tokens.Count - 1 && tokens[i + 1] == ")")
                        return false;
                        
                    // Check previous token is not also an operator
                    var prevUpper = tokens[i - 1].ToUpperInvariant();
                    if (new[] { "AND", "OR", "NEAR", "NOT" }.Contains(prevUpper))
                        return false;
                        
                    // Check next token is not also an operator (except NOT after AND)
                    if (i < tokens.Count - 1)
                    {
                        var nextUpper = tokens[i + 1].ToUpperInvariant();
                        if (new[] { "AND", "OR", "NEAR" }.Contains(nextUpper))
                            return false;
                        // NOT is only allowed after AND
                        if (nextUpper == "NOT" && upper != "AND")
                            return false;
                    }
                }

                // Check NOT operator rules
                if (upper == "NOT")
                {
                    // NOT cannot be first token
                    if (i == 0) return false;
                    
                    // Cannot immediately follow opening parenthesis
                    if (i > 0 && tokens[i - 1] == "(")
                        return false;
                    
                    // NOT must be preceded by AND
                    if (tokens[i - 1].ToUpperInvariant() != "AND") return false;
                    
                    // NOT cannot be last token
                    if (i == tokens.Count - 1) return false;
                    
                    // NOT cannot be followed by another operator
                    var nextUpper = tokens[i + 1].ToUpperInvariant();
                    if (new[] { "AND", "OR", "NEAR", "NOT" }.Contains(nextUpper))
                        return false;
                }
            }

            // Wildcards validation - more comprehensive
            if (Regex.IsMatch(input, @"\*\w+")) return false; // wildcard at beginning
            if (Regex.IsMatch(input, @"\w+\*+\w+")) return false; // wildcard in middle

            return true;
        }
    }
}