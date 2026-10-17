namespace PowerScap.Engine.Oval
{
    /// <summary>OVAL ResultEnumeration (OVAL 5.11.2 results schema).</summary>
    public enum OvalResult
    {
        True,
        False,
        Error,
        Unknown,
        NotEvaluated,
        NotApplicable
    }

    public static class OvalResultText
    {
        public static string ToOval(OvalResult r)
        {
            switch (r)
            {
                case OvalResult.True: return "true";
                case OvalResult.False: return "false";
                case OvalResult.Error: return "error";
                case OvalResult.Unknown: return "unknown";
                case OvalResult.NotEvaluated: return "not evaluated";
                default: return "not applicable";
            }
        }

        public static OvalResult FromBool(bool b)
        {
            return b ? OvalResult.True : OvalResult.False;
        }
    }
}
