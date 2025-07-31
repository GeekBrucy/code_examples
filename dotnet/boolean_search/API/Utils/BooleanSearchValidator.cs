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

            // Balanced quotes
            if (input.Count(c => c == '"') % 2 != 0)
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
            var tokens = Regex.Split(input, @"\s+")
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .ToList();

            for (int i = 0; i < tokens.Count; i++)
            {
                var token = tokens[i];

                // If token is a quoted phrase, skip operator validation
                if (token.StartsWith("\"") && token.EndsWith("\""))
                    continue;

                var upper = token.ToUpperInvariant();

                if (new[] { "AND", "OR", "NEAR" }.Contains(upper))
                {
                    if (i == 0 || i == tokens.Count - 1)
                        return false; // cannot be first or last
                }

                if (upper == "NOT")
                {
                    if (i == 0) return false;
                    if (tokens[i - 1].ToUpperInvariant() != "AND") return false;
                    if (i == tokens.Count - 1) return false;
                }
            }

            // Wildcards only allowed at end of token
            if (Regex.IsMatch(input, @"\w+\*+\w+")) return false;

            return true;
        }
    }
}