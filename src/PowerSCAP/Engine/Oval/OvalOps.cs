using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Numerics;
using System.Text.RegularExpressions;

namespace PowerScap.Engine.Oval
{
    /// <summary>
    /// OVAL 5.11.2 datatype/operation comparisons (§5.3.6). Compare(actual, expected) answers
    /// "does the collected value satisfy the operation against the state value".
    /// </summary>
    public static class OvalOps
    {
        public static OvalResult Compare(string datatype, string operation, string actual, string expected)
        {
            if (string.IsNullOrEmpty(datatype)) datatype = "string";
            if (string.IsNullOrEmpty(operation)) operation = "equals";
            if (actual == null) actual = string.Empty;
            if (expected == null) expected = string.Empty;
            try
            {
                switch (datatype)
                {
                    case "string": return CompareString(operation, actual, expected);
                    case "int": return CompareInt(operation, actual, expected);
                    case "float": return CompareFloat(operation, actual, expected);
                    case "boolean": return CompareBoolean(operation, actual, expected);
                    case "binary": return CompareBinary(operation, actual, expected);
                    case "version":
                    case "fileset_revision":
                    case "ios_version":
                        return Ordered(operation, CompareVersion(actual, expected));
                    case "evr_string":
                    case "debian_evr_string":
                        return Ordered(operation, CompareEvr(actual, expected));
                    case "ipv4_address":
                    case "ipv6_address":
                        return CompareIp(operation, actual, expected);
                    default:
                        return OvalResult.Error;
                }
            }
            catch (FormatException) { return OvalResult.Error; }
            catch (OverflowException) { return OvalResult.Error; }
            catch (ArgumentException) { return OvalResult.Error; }
        }

        static OvalResult CompareString(string op, string a, string e)
        {
            switch (op)
            {
                case "equals": return OvalResultText.FromBool(string.Equals(a, e, StringComparison.Ordinal));
                case "not equal": return OvalResultText.FromBool(!string.Equals(a, e, StringComparison.Ordinal));
                case "case insensitive equals": return OvalResultText.FromBool(string.Equals(a, e, StringComparison.OrdinalIgnoreCase));
                case "case insensitive not equal": return OvalResultText.FromBool(!string.Equals(a, e, StringComparison.OrdinalIgnoreCase));
                case "pattern match": return OvalResultText.FromBool(PatternMatch(a, e));
                default: return OvalResult.Error;
            }
        }

        public static BigInteger ParseInt(string s)
        {
            s = s.Trim();
            bool neg = s.StartsWith("-");
            string body = neg ? s.Substring(1) : s;
            BigInteger v;
            if (body.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                v = BigInteger.Parse("0" + body.Substring(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
            else
                v = BigInteger.Parse(body, NumberStyles.None, CultureInfo.InvariantCulture);
            return neg ? -v : v;
        }

        static OvalResult CompareInt(string op, string a, string e)
        {
            BigInteger x = ParseInt(a), y = ParseInt(e);
            switch (op)
            {
                case "bitwise and": return OvalResultText.FromBool((x & y) == y);
                case "bitwise or": return OvalResultText.FromBool((x | y) == y);
                default: return Ordered(op, x.CompareTo(y));
            }
        }

        static OvalResult CompareFloat(string op, string a, string e)
        {
            double x = ParseFloat(a), y = ParseFloat(e);
            return Ordered(op, x.CompareTo(y));
        }

        static double ParseFloat(string s)
        {
            s = s.Trim();
            if (s == "INF") return double.PositiveInfinity;
            if (s == "-INF") return double.NegativeInfinity;
            if (s == "NaN") return double.NaN;
            return double.Parse(s, NumberStyles.Float, CultureInfo.InvariantCulture);
        }

        static bool ParseBool(string s)
        {
            switch (s.Trim().ToLowerInvariant())
            {
                case "true": case "1": return true;
                case "false": case "0": return false;
                default: throw new FormatException("Not a boolean: " + s);
            }
        }

        static OvalResult CompareBoolean(string op, string a, string e)
        {
            bool x = ParseBool(a), y = ParseBool(e);
            if (op == "equals") return OvalResultText.FromBool(x == y);
            if (op == "not equal") return OvalResultText.FromBool(x != y);
            return OvalResult.Error;
        }

        static OvalResult CompareBinary(string op, string a, string e)
        {
            if (!Regex.IsMatch(a, "^[0-9A-Fa-f]*$") || !Regex.IsMatch(e, "^[0-9A-Fa-f]*$"))
                return OvalResult.Error;
            bool eq = string.Equals(a, e, StringComparison.OrdinalIgnoreCase);
            if (op == "equals") return OvalResultText.FromBool(eq);
            if (op == "not equal") return OvalResultText.FromBool(!eq);
            return OvalResult.Error;
        }

        /// <summary>Maps a comparison (actual vs expected) to an ordered/equality operation.</summary>
        static OvalResult Ordered(string op, int cmp)
        {
            switch (op)
            {
                case "equals": return OvalResultText.FromBool(cmp == 0);
                case "not equal": return OvalResultText.FromBool(cmp != 0);
                case "greater than": return OvalResultText.FromBool(cmp > 0);
                case "greater than or equal": return OvalResultText.FromBool(cmp >= 0);
                case "less than": return OvalResultText.FromBool(cmp < 0);
                case "less than or equal": return OvalResultText.FromBool(cmp <= 0);
                default: return OvalResult.Error;
            }
        }

        /// <summary>OVAL version: integer components separated by any non-digit; missing components count as 0.</summary>
        public static int CompareVersion(string a, string e)
        {
            string[] x = Regex.Split(a.Trim(), "[^0-9]+");
            string[] y = Regex.Split(e.Trim(), "[^0-9]+");
            if (IsEmptyVersion(x) || IsEmptyVersion(y)) throw new FormatException("Not a version");
            int n = Math.Max(x.Length, y.Length);
            for (int i = 0; i < n; i++)
            {
                BigInteger xi = i < x.Length && x[i].Length > 0 ? BigInteger.Parse(x[i], CultureInfo.InvariantCulture) : BigInteger.Zero;
                BigInteger yi = i < y.Length && y[i].Length > 0 ? BigInteger.Parse(y[i], CultureInfo.InvariantCulture) : BigInteger.Zero;
                int c = xi.CompareTo(yi);
                if (c != 0) return c;
            }
            return 0;
        }

        static bool IsEmptyVersion(string[] parts)
        {
            foreach (var p in parts) if (p.Length > 0) return false;
            return true;
        }

        /// <summary>RPM-style epoch:version-release comparison (rpmvercmp).</summary>
        public static int CompareEvr(string a, string e)
        {
            string ea, va, ra, eb, vb, rb;
            SplitEvr(a, out ea, out va, out ra);
            SplitEvr(e, out eb, out vb, out rb);
            int c = RpmVerCmp(ea, eb);
            if (c != 0) return c;
            c = RpmVerCmp(va, vb);
            if (c != 0) return c;
            return RpmVerCmp(ra, rb);
        }

        static void SplitEvr(string s, out string epoch, out string version, out string release)
        {
            int colon = s.IndexOf(':');
            epoch = colon >= 0 ? s.Substring(0, colon) : "0";
            string rest = colon >= 0 ? s.Substring(colon + 1) : s;
            int dash = rest.LastIndexOf('-');
            version = dash >= 0 ? rest.Substring(0, dash) : rest;
            release = dash >= 0 ? rest.Substring(dash + 1) : "";
        }

        static int RpmVerCmp(string a, string b)
        {
            if (a == b) return 0;
            var ma = Regex.Matches(a, "[0-9]+|[A-Za-z]+");
            var mb = Regex.Matches(b, "[0-9]+|[A-Za-z]+");
            int n = Math.Min(ma.Count, mb.Count);
            for (int i = 0; i < n; i++)
            {
                string x = ma[i].Value, y = mb[i].Value;
                bool xd = char.IsDigit(x[0]), yd = char.IsDigit(y[0]);
                if (xd && !yd) return 1;
                if (!xd && yd) return -1;
                int c = xd ? BigInteger.Parse(x).CompareTo(BigInteger.Parse(y)) : string.CompareOrdinal(x, y);
                if (c != 0) return Math.Sign(c);
            }
            return ma.Count.CompareTo(mb.Count);
        }

        static OvalResult CompareIp(string op, string a, string e)
        {
            byte[] na, ma, ne, me;
            ParseCidr(a, out na, out ma);
            ParseCidr(e, out ne, out me);
            if (na.Length != ne.Length) return OvalResult.Error;
            switch (op)
            {
                case "subset of": return OvalResultText.FromBool(IsSubset(na, ma, ne, me));
                case "superset of": return OvalResultText.FromBool(IsSubset(ne, me, na, ma));
                case "equals":
                case "not equal":
                    bool eq = Bytes(na, ma) == Bytes(ne, me) && Bytes(ma, null) == Bytes(me, null);
                    return OvalResultText.FromBool(op == "equals" ? eq : !eq);
                default:
                    return Ordered(op, Bytes(na, ma).CompareTo(Bytes(ne, me)));
            }
        }

        static void ParseCidr(string s, out byte[] address, out byte[] mask)
        {
            string[] parts = s.Trim().Split('/');
            IPAddress ip = IPAddress.Parse(parts[0]);
            address = ip.GetAddressBytes();
            int bits = address.Length * 8;
            int prefix = parts.Length > 1 ? int.Parse(parts[1], CultureInfo.InvariantCulture) : bits;
            if (prefix < 0 || prefix > bits) throw new FormatException("Bad prefix");
            mask = new byte[address.Length];
            for (int i = 0; i < prefix; i++) mask[i / 8] |= (byte)(0x80 >> (i % 8));
        }

        static BigInteger Bytes(byte[] value, byte[] mask)
        {
            var copy = new byte[value.Length + 1];
            for (int i = 0; i < value.Length; i++)
                copy[value.Length - 1 - i] = mask == null ? value[i] : (byte)(value[i] & mask[i]);
            return new BigInteger(copy);
        }

        static bool IsSubset(byte[] na, byte[] ma, byte[] ne, byte[] me)
        {
            // a ⊆ e when a's prefix is at least as long as e's and a's network lies inside e's network.
            BigInteger maskA = Bytes(ma, null), maskE = Bytes(me, null);
            if ((maskA & maskE) != maskE) return false;
            return Bytes(na, me) == Bytes(ne, me);
        }

        static readonly Dictionary<string, string> PosixClasses = new Dictionary<string, string>
        {
            { "[:alpha:]", "a-zA-Z" }, { "[:digit:]", "0-9" }, { "[:alnum:]", "a-zA-Z0-9" },
            { "[:upper:]", "A-Z" }, { "[:lower:]", "a-z" }, { "[:space:]", "\\s" },
            { "[:xdigit:]", "0-9A-Fa-f" }, { "[:punct:]", "!-/:-@\\[-`{-~" }, { "[:blank:]", " \\t" },
            { "[:cntrl:]", "\\x00-\\x1f\\x7f" }, { "[:print:]", "\\x20-\\x7e" }, { "[:graph:]", "\\x21-\\x7e" },
            { "[:word:]", "\\w" }
        };

        static readonly Dictionary<string, Regex> RegexCache = new Dictionary<string, Regex>();

        public static Regex ToRegex(string perlPattern)
        {
            lock (RegexCache)
            {
                Regex r;
                if (RegexCache.TryGetValue(perlPattern, out r)) return r;
                string p = perlPattern;
                foreach (var kv in PosixClasses) p = p.Replace(kv.Key, kv.Value);
                r = new Regex(p, RegexOptions.CultureInvariant);
                RegexCache[perlPattern] = r;
                return r;
            }
        }

        public static bool PatternMatch(string input, string perlPattern)
        {
            return ToRegex(perlPattern).IsMatch(input ?? string.Empty);
        }
    }
}
