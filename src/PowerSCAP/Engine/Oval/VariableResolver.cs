using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace PowerScap.Engine.Oval
{
    public class VariableResult
    {
        public IList<string> Values { get; private set; }
        public CollectedFlag Flag { get; set; }
        public List<string> Messages { get; private set; }

        public VariableResult()
        {
            Values = new List<string>();
            Flag = CollectedFlag.Complete;
            Messages = new List<string>();
        }

        public static VariableResult Fail(CollectedFlag flag, string message)
        {
            var r = new VariableResult();
            r.Flag = flag;
            r.Messages.Add(message);
            return r;
        }
    }

    /// <summary>Resolves OVAL constant, external and local variables (OVAL 5.11.2 §4.2), memoized per id.</summary>
    public class VariableResolver
    {
        readonly OvalContext ctx;
        readonly IDictionary<string, IList<string>> external;
        readonly Dictionary<string, VariableResult> cache = new Dictionary<string, VariableResult>(StringComparer.Ordinal);
        readonly HashSet<string> resolving = new HashSet<string>(StringComparer.Ordinal);

        public VariableResolver(OvalContext ctx, IDictionary<string, IList<string>> externalValues)
        {
            this.ctx = ctx;
            this.external = externalValues ?? new Dictionary<string, IList<string>>();
        }

        public VariableResult Resolve(string varId)
        {
            VariableResult r;
            if (cache.TryGetValue(varId, out r)) return r;
            if (!resolving.Add(varId)) return VariableResult.Fail(CollectedFlag.Error, "Circular variable reference: " + varId);
            try
            {
                XmlElement v = ctx.Find(varId);
                if (v == null) r = VariableResult.Fail(CollectedFlag.Error, "Variable not found: " + varId);
                else r = ResolveElement(v);
            }
            catch (Exception ex)
            {
                r = VariableResult.Fail(CollectedFlag.Error, varId + ": " + ex.Message);
            }
            finally { resolving.Remove(varId); }
            cache[varId] = r;
            return r;
        }

        VariableResult ResolveElement(XmlElement v)
        {
            string id = v.GetAttribute("id");
            switch (v.LocalName)
            {
                case "constant_variable":
                {
                    var r = new VariableResult();
                    foreach (XmlElement value in Elements(v).Where(e => e.LocalName == "value")) r.Values.Add(value.InnerText);
                    return r;
                }
                case "external_variable":
                {
                    IList<string> values;
                    if (!external.TryGetValue(id, out values) || values == null)
                        return VariableResult.Fail(CollectedFlag.Error, "No value supplied for external variable " + id);
                    var r = new VariableResult();
                    foreach (var x in values) r.Values.Add(x);
                    return r;
                }
                case "local_variable":
                {
                    XmlElement component = Elements(v).FirstOrDefault(e => e.LocalName != "notes");
                    if (component == null) return VariableResult.Fail(CollectedFlag.Error, "Empty local_variable " + id);
                    return Component(component, v.GetAttribute("datatype"));
                }
                default:
                    return VariableResult.Fail(CollectedFlag.Error, "Unknown variable type " + v.LocalName);
            }
        }

        static IEnumerable<XmlElement> Elements(XmlElement parent)
        {
            return parent.ChildNodes.OfType<XmlElement>();
        }

        List<VariableResult> Children(XmlElement e, string datatype)
        {
            return Elements(e).Select(c => Component(c, datatype)).ToList();
        }

        /// <summary>Propagates the worst flag of the inputs; returns true when evaluation can continue.</summary>
        static bool Merge(VariableResult target, IEnumerable<VariableResult> inputs)
        {
            foreach (var i in inputs)
            {
                target.Messages.AddRange(i.Messages);
                if (i.Flag == CollectedFlag.Error) target.Flag = CollectedFlag.Error;
                else if (i.Flag != CollectedFlag.Complete && target.Flag == CollectedFlag.Complete) target.Flag = i.Flag;
            }
            return target.Flag != CollectedFlag.Error;
        }

        VariableResult Map(XmlElement e, string datatype, Func<string, IEnumerable<string>> f)
        {
            var inputs = Children(e, datatype);
            var r = new VariableResult();
            if (!Merge(r, inputs)) return r;
            foreach (var input in inputs)
                foreach (var value in input.Values)
                    foreach (var o in f(value)) r.Values.Add(o);
            return r;
        }

        VariableResult Component(XmlElement e, string datatype)
        {
            switch (e.LocalName)
            {
                case "literal_component":
                {
                    var r = new VariableResult();
                    r.Values.Add(e.InnerText);
                    return r;
                }
                case "variable_component":
                    return Resolve(e.GetAttribute("var_ref"));
                case "object_component":
                    return ObjectComponent(e);
                case "concat":
                {
                    var inputs = Children(e, datatype);
                    var r = new VariableResult();
                    if (!Merge(r, inputs)) return r;
                    IEnumerable<string> acc = new[] { "" };
                    foreach (var input in inputs)
                    {
                        var current = input.Values;
                        acc = acc.SelectMany(prefix => current.Select(s => prefix + s)).ToList();
                    }
                    if (inputs.All(i => i.Values.Count > 0)) foreach (var s in acc) r.Values.Add(s);
                    return r;
                }
                case "arithmetic":
                    return Arithmetic(e, datatype);
                case "begin":
                {
                    string ch = e.GetAttribute("character");
                    return Map(e, datatype, s => new[] { s.StartsWith(ch, StringComparison.Ordinal) ? s : ch + s });
                }
                case "end":
                {
                    string ch = e.GetAttribute("character");
                    return Map(e, datatype, s => new[] { s.EndsWith(ch, StringComparison.Ordinal) ? s : s + ch });
                }
                case "count":
                {
                    var inputs = Children(e, datatype);
                    var r = new VariableResult();
                    if (!Merge(r, inputs)) return r;
                    r.Values.Add(inputs.Sum(i => i.Values.Count).ToString(CultureInfo.InvariantCulture));
                    return r;
                }
                case "escape_regex":
                    return Map(e, datatype, s => new[] { EscapeRegex(s) });
                case "glob_to_regex":
                {
                    bool noEscape = e.GetAttribute("glob_noescape") == "true";
                    return Map(e, datatype, s => new[] { GlobToRegex(s, noEscape) });
                }
                case "regex_capture":
                {
                    Regex rx = OvalOps.ToRegex(e.GetAttribute("pattern"));
                    return Map(e, datatype, s =>
                    {
                        Match m = rx.Match(s);
                        if (m.Success && m.Groups.Count > 1 && m.Groups[1].Success) return new[] { m.Groups[1].Value };
                        return new[] { string.Empty };
                    });
                }
                case "split":
                {
                    string d = e.GetAttribute("delimiter");
                    return Map(e, datatype, s => s.Split(new[] { d }, StringSplitOptions.None));
                }
                case "substring":
                {
                    int start = int.Parse(e.GetAttribute("substring_start"), CultureInfo.InvariantCulture);
                    int length = int.Parse(e.GetAttribute("substring_length"), CultureInfo.InvariantCulture);
                    return Map(e, datatype, s =>
                    {
                        int from = Math.Max(start, 1) - 1;
                        if (from >= s.Length) return new[] { string.Empty };
                        int len = length < 0 ? s.Length - from : Math.Min(length, s.Length - from);
                        return new[] { s.Substring(from, len) };
                    });
                }
                case "unique":
                {
                    var inputs = Children(e, datatype);
                    var r = new VariableResult();
                    if (!Merge(r, inputs)) return r;
                    var seen = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var i in inputs) foreach (var s in i.Values) if (seen.Add(s)) r.Values.Add(s);
                    return r;
                }
                case "time_difference":
                    return TimeDifference(e, datatype);
                case "merge":
                {
                    // OVAL 5.12: concatenate every input value into a single value.
                    var inputs = Children(e, datatype);
                    var r = new VariableResult();
                    if (!Merge(r, inputs)) return r;
                    var all = inputs.SelectMany(i => i.Values).ToList();
                    string sort = e.GetAttribute("sort");
                    if (sort == "ascending") all.Sort(StringComparer.Ordinal);
                    else if (sort == "descending") { all.Sort(StringComparer.Ordinal); all.Reverse(); }
                    r.Values.Add(string.Join(e.GetAttribute("delimiter"), all));
                    return r;
                }
                default:
                    return VariableResult.Fail(CollectedFlag.Error, "Unsupported variable component " + e.LocalName);
            }
        }

        VariableResult ObjectComponent(XmlElement e)
        {
            XmlElement obj = ctx.FindObject(e.GetAttribute("object_ref"));
            if (obj == null) return VariableResult.Fail(CollectedFlag.Error, "Object not found: " + e.GetAttribute("object_ref"));
            CollectedObject collected = ObjectEvaluator.Evaluate(obj, ctx);
            var r = new VariableResult();
            r.Messages.AddRange(collected.Messages);
            if (collected.Flag == CollectedFlag.Error || collected.Flag == CollectedFlag.NotCollected)
            {
                r.Flag = collected.Flag == CollectedFlag.Error ? CollectedFlag.Error : CollectedFlag.NotCollected;
                return r;
            }
            string field = e.GetAttribute("item_field");
            string recordField = e.GetAttribute("record_field");
            foreach (var item in collected.Items)
            {
                if (item.Status != ItemStatus.Exists) continue;
                foreach (var entity in item.Get(field))
                {
                    if (entity.Status != ItemStatus.Exists) continue;
                    if (string.IsNullOrEmpty(recordField)) { r.Values.Add(entity.Value); continue; }
                    foreach (var f in entity.Fields)
                        if (f.Name == recordField && f.Status == ItemStatus.Exists) r.Values.Add(f.Value);
                }
            }
            if (r.Values.Count == 0 && r.Flag == CollectedFlag.Complete) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }

        VariableResult Arithmetic(XmlElement e, string datatype)
        {
            string op = e.GetAttribute("arithmetic_operation");
            var inputs = Children(e, datatype);
            var r = new VariableResult();
            if (!Merge(r, inputs)) return r;
            bool isFloat = datatype == "float";
            IEnumerable<string> acc = null;
            foreach (var input in inputs)
            {
                if (acc == null) { acc = input.Values.ToList(); continue; }
                var current = input.Values;
                acc = acc.SelectMany(a => current.Select(b => Apply(op, a, b, isFloat))).ToList();
            }
            if (acc != null) foreach (var s in acc) r.Values.Add(s);
            return r;
        }

        static string Apply(string op, string a, string b, bool isFloat)
        {
            if (isFloat)
            {
                double x = double.Parse(a, CultureInfo.InvariantCulture), y = double.Parse(b, CultureInfo.InvariantCulture);
                return (op == "multiply" ? x * y : x + y).ToString("R", CultureInfo.InvariantCulture);
            }
            BigInteger bx = OvalOps.ParseInt(a), by = OvalOps.ParseInt(b);
            return (op == "multiply" ? bx * by : bx + by).ToString(CultureInfo.InvariantCulture);
        }

        VariableResult TimeDifference(XmlElement e, string datatype)
        {
            string f1 = e.HasAttribute("format_1") ? e.GetAttribute("format_1") : "year_month_day";
            string f2 = e.HasAttribute("format_2") ? e.GetAttribute("format_2") : "year_month_day";
            var inputs = Children(e, datatype);
            var r = new VariableResult();
            if (!Merge(r, inputs)) return r;
            if (inputs.Count == 1)
            {
                foreach (var s in inputs[0].Values)
                    r.Values.Add(((long)(DateTime.UtcNow - ParseTime(s, f2)).TotalSeconds).ToString(CultureInfo.InvariantCulture));
            }
            else if (inputs.Count == 2)
            {
                foreach (var a in inputs[0].Values)
                    foreach (var b in inputs[1].Values)
                        r.Values.Add(((long)(ParseTime(b, f2) - ParseTime(a, f1)).TotalSeconds).ToString(CultureInfo.InvariantCulture));
            }
            return r;
        }

        static DateTime ParseTime(string s, string format)
        {
            s = s.Trim();
            switch (format)
            {
                case "seconds_since_epoch":
                    return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(double.Parse(s, CultureInfo.InvariantCulture));
                case "win_filetime":
                    return DateTime.FromFileTimeUtc(long.Parse(s.StartsWith("0x") ? s.Substring(2) : s,
                        s.StartsWith("0x") ? NumberStyles.HexNumber : NumberStyles.Integer, CultureInfo.InvariantCulture));
                case "month_day_year":
                    return DateTime.Parse(s, new CultureInfo("en-US"), DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);
                case "day_month_year":
                    return DateTime.Parse(s, new CultureInfo("en-GB"), DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);
                default:
                    return DateTime.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);
            }
        }

        public static string EscapeRegex(string s)
        {
            var sb = new StringBuilder();
            foreach (char c in s)
            {
                if ("\\^$.|?*+()[]{}".IndexOf(c) >= 0) sb.Append('\\');
                sb.Append(c);
            }
            return sb.ToString();
        }

        /// <summary>Glob to regex per OVAL glob_to_regex (Windows: path separator is backslash).</summary>
        public static string GlobToRegex(string glob, bool noEscape)
        {
            var sb = new StringBuilder("^");
            for (int i = 0; i < glob.Length; i++)
            {
                char c = glob[i];
                switch (c)
                {
                    case '*': sb.Append("[^\\\\]*"); break;
                    case '?': sb.Append("[^\\\\]"); break;
                    case '[':
                        int close = glob.IndexOf(']', i + 1);
                        if (close > i) { sb.Append(glob, i, close - i + 1); i = close; }
                        else sb.Append("\\[");
                        break;
                    case '\\':
                        if (!noEscape && i + 1 < glob.Length) { sb.Append(EscapeRegex(glob[i + 1].ToString())); i++; }
                        else sb.Append("\\\\");
                        break;
                    default:
                        sb.Append(EscapeRegex(c.ToString()));
                        break;
                }
            }
            return sb.Append('$').ToString();
        }
    }
}
