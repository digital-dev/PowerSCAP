using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace PowerScap.Engine.Oval
{
    /// <summary>Helpers shared by collectors for matching object entity criteria against candidate values.</summary>
    public static class CollectorUtil
    {
        /// <summary>True when the candidate satisfies the criterion (operation + var_check).</summary>
        public static bool Satisfies(EntityCriterion c, string candidate)
        {
            if (c == null) return true;
            return c.Matches(candidate) == OvalResult.True;
        }

        /// <summary>Case-insensitive variant for Windows names (registry, accounts, services).</summary>
        public static bool SatisfiesIgnoreCase(EntityCriterion c, string candidate)
        {
            if (c == null) return true;
            if (c.Operation == "equals")
                return c.Values.Any(v => string.Equals(v, candidate, StringComparison.OrdinalIgnoreCase)) ? CheckAll(c, candidate) : false;
            if (c.Operation == "not equal")
                return c.Values.All(v => !string.Equals(v, candidate, StringComparison.OrdinalIgnoreCase));
            if (c.Operation == "pattern match")
            {
                var results = c.Values.Select(v => OvalResultText.FromBool(Regex.IsMatch(candidate, v, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))).ToList();
                return OvalLogic.Check(c.VarCheck, results) == OvalResult.True;
            }
            return Satisfies(c, candidate);
        }

        static bool CheckAll(EntityCriterion c, string candidate)
        {
            var results = c.Values.Select(v => OvalResultText.FromBool(string.Equals(v, candidate, StringComparison.OrdinalIgnoreCase))).ToList();
            return OvalLogic.Check(c.VarCheck, results) == OvalResult.True;
        }

        /// <summary>Literal values usable for direct lookup (equals, no regex), else null.</summary>
        public static IList<string> LiteralValues(EntityCriterion c)
        {
            if (c == null || c.IsNil) return null;
            if (c.Operation == "equals" || c.Operation == "case insensitive equals") return c.Values;
            return null;
        }

        /// <summary>Longest literal prefix of an anchored regex, used to narrow enumeration (e.g. "^Software\\Foo\\" → "Software\Foo\").</summary>
        public static string LiteralPrefix(string pattern)
        {
            if (string.IsNullOrEmpty(pattern) || pattern[0] != '^') return string.Empty;
            var sb = new System.Text.StringBuilder();
            for (int i = 1; i < pattern.Length; i++)
            {
                char ch = pattern[i];
                if (ch == '\\' && i + 1 < pattern.Length)
                {
                    char next = pattern[i + 1];
                    if (char.IsLetterOrDigit(next)) break; // \d, \w, \s ...
                    sb.Append(next);
                    i++;
                    continue;
                }
                if (".^$|?*+()[]{}".IndexOf(ch) >= 0)
                {
                    // A quantifier makes the previous char optional/repeatable: drop it.
                    if ((ch == '?' || ch == '*' || ch == '{') && sb.Length > 0) sb.Length--;
                    break;
                }
                sb.Append(ch);
            }
            return sb.ToString();
        }

        public static bool Is64BitView(ObjectSpec spec)
        {
            return spec.Behavior("windows_view", "64_bit") != "32_bit";
        }
    }
}
