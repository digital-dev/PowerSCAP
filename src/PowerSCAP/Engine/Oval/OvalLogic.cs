using System;
using System.Collections.Generic;

namespace PowerScap.Engine.Oval
{
    /// <summary>OVAL 5.11.2 operator, check and existence truth tables (§5.3.1–5.3.3).</summary>
    public static class OvalLogic
    {
        struct Counts
        {
            public int T, F, E, U, NE, NA;
            public int Total { get { return T + F + E + U + NE + NA; } }
        }

        static Counts Count(IList<OvalResult> results)
        {
            var c = new Counts();
            foreach (var r in results)
            {
                switch (r)
                {
                    case OvalResult.True: c.T++; break;
                    case OvalResult.False: c.F++; break;
                    case OvalResult.Error: c.E++; break;
                    case OvalResult.Unknown: c.U++; break;
                    case OvalResult.NotEvaluated: c.NE++; break;
                    default: c.NA++; break;
                }
            }
            return c;
        }

        /// <summary>Error, then unknown, then not evaluated: the tail every table shares.</summary>
        static OvalResult Indeterminate(Counts c)
        {
            if (c.E > 0) return OvalResult.Error;
            if (c.U > 0) return OvalResult.Unknown;
            return OvalResult.NotEvaluated;
        }

        static bool AnyIndeterminate(Counts c) { return c.E + c.U + c.NE > 0; }

        public static OvalResult Combine(string op, IList<OvalResult> results)
        {
            var c = Count(results);
            if (c.T + c.F + c.E + c.U + c.NE == 0) return OvalResult.NotApplicable;
            switch ((op ?? "AND").ToUpperInvariant())
            {
                case "AND":
                    if (c.F > 0) return OvalResult.False;
                    if (AnyIndeterminate(c)) return Indeterminate(c);
                    return OvalResult.True;
                case "OR":
                    if (c.T > 0) return OvalResult.True;
                    if (AnyIndeterminate(c)) return Indeterminate(c);
                    return OvalResult.False;
                case "ONE":
                    if (c.T >= 2) return OvalResult.False;
                    if (AnyIndeterminate(c)) return Indeterminate(c);
                    return c.T == 1 ? OvalResult.True : OvalResult.False;
                case "XOR":
                    if (AnyIndeterminate(c)) return Indeterminate(c);
                    return c.T % 2 == 1 ? OvalResult.True : OvalResult.False;
                default:
                    return OvalResult.Error;
            }
        }

        public static OvalResult Negate(OvalResult r)
        {
            if (r == OvalResult.True) return OvalResult.False;
            if (r == OvalResult.False) return OvalResult.True;
            return r;
        }

        public static OvalResult Existence(string checkExistence, int exists, int doesNotExist, int error, int notCollected)
        {
            switch (checkExistence ?? "at_least_one_exists")
            {
                case "all_exist":
                    if (doesNotExist > 0) return OvalResult.False;
                    if (error > 0) return OvalResult.Error;
                    if (notCollected > 0) return OvalResult.Unknown;
                    return exists > 0 ? OvalResult.True : OvalResult.False;
                case "any_exist":
                    if (error > 0 && exists == 0) return OvalResult.Error;
                    return OvalResult.True;
                case "at_least_one_exists":
                    if (exists > 0) return OvalResult.True;
                    if (error > 0) return OvalResult.Error;
                    if (notCollected > 0) return OvalResult.Unknown;
                    return OvalResult.False;
                case "none_exist":
                    if (exists > 0) return OvalResult.False;
                    if (error > 0) return OvalResult.Error;
                    if (notCollected > 0) return OvalResult.Unknown;
                    return OvalResult.True;
                case "only_one_exists":
                    if (exists > 1) return OvalResult.False;
                    if (error > 0) return OvalResult.Error;
                    if (notCollected > 0) return OvalResult.Unknown;
                    return exists == 1 ? OvalResult.True : OvalResult.False;
                default:
                    return OvalResult.Error;
            }
        }

        public static OvalResult Check(string check, IList<OvalResult> itemResults)
        {
            check = check ?? "all";
            if (itemResults.Count == 0)
                return (check == "all" || check == "none satisfy" || check == "none exist") ? OvalResult.True : OvalResult.False;
            var c = Count(itemResults);
            if (c.T + c.F + c.E + c.U + c.NE == 0) return OvalResult.NotApplicable;
            switch (check)
            {
                case "all":
                    if (c.F > 0) return OvalResult.False;
                    if (AnyIndeterminate(c)) return Indeterminate(c);
                    return OvalResult.True;
                case "at least one":
                    if (c.T > 0) return OvalResult.True;
                    if (AnyIndeterminate(c)) return Indeterminate(c);
                    return OvalResult.False;
                case "none satisfy":
                case "none exist":
                    if (c.T > 0) return OvalResult.False;
                    if (AnyIndeterminate(c)) return Indeterminate(c);
                    return OvalResult.True;
                case "only one":
                    if (c.T > 1) return OvalResult.False;
                    if (AnyIndeterminate(c)) return Indeterminate(c);
                    return c.T == 1 ? OvalResult.True : OvalResult.False;
                default:
                    return OvalResult.Error;
            }
        }
    }
}
