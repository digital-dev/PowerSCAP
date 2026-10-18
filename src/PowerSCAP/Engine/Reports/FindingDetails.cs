using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Xml;
using PowerScap.Engine.Content;
using PowerScap.Engine.Oval;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Engine.Reports
{
    /// <summary>
    /// Plain-text account of how a rule was evaluated, in SCC's layout: each OVAL test with its object and state
    /// requirements and every collected item with the values found. Used for .cklb finding_details and HTML detail.
    /// </summary>
    public class FindingDetails
    {
        public const int MaxItems = 50;

        readonly ScapContent content;
        readonly Dictionary<string, Dictionary<string, XmlElement>> indexes = new Dictionary<string, Dictionary<string, XmlElement>>();

        public FindingDetails(ScapContent content)
        {
            this.content = content;
        }

        public string Render(RuleResult r)
        {
            var sb = new StringBuilder();
            Line(sb, "Rule Result", Title(ResultsWriter.ResultText(r.Result)));
            if (!string.IsNullOrEmpty(r.Message)) Line(sb, "Message", r.Message);
            if (r.CheckSystem != null && r.CheckSystem != XccdfNs.OvalSystem && r.OvalResults.Count == 0)
                Line(sb, "Check", "Manual review required (" + r.CheckSystem + ")");
            foreach (var def in r.OvalResults)
            {
                Line(sb, "Definition", def.DefinitionId + " (" + OvalText(def.Result) + ")");
                foreach (var m in def.Messages) Line(sb, "Message", m);
                var index = Index(r.CheckHref);
                foreach (var t in def.Tests)
                {
                    sb.AppendLine();
                    sb.AppendLine("---");
                    sb.AppendLine();
                    Line(sb, "Test ID", t.TestId + " (" + t.TestType + ")");
                    Line(sb, "Result", OvalText(t.Result));
                    if (!string.IsNullOrEmpty(t.Comment)) Line(sb, "Test Title", t.Comment);
                    Line(sb, "Check Existence", ExistenceText(t.CheckExistence));
                    Line(sb, "Check", t.StateIds.Count == 0 ? "Result is based on check existence only." : CheckText(t.Check));
                    if (t.StateIds.Count > 1) Line(sb, "State Operator", t.StateOperator);
                    foreach (var m in t.Messages) Line(sb, "Message", m);

                    if (t.Object != null)
                    {
                        sb.AppendLine();
                        XmlElement obj;
                        index.TryGetValue(t.Object.ObjectId ?? "", out obj);
                        Line(sb, "Object ID", t.Object.ObjectId + (obj == null ? "" : " (" + obj.LocalName + ")"));
                        if (obj != null)
                        {
                            Line(sb, "Object Comment", obj.GetAttribute("comment"));
                            foreach (var req in Requirements(obj, true)) Line(sb, "Object Requirement", req);
                        }
                        Line(sb, "Collected Flag", FlagText(t.Object.Flag));
                        foreach (var m in t.Object.Messages.Take(10)) Line(sb, "Message", m);
                        if (t.Object.Messages.Count > 10) Line(sb, "Message", "... " + (t.Object.Messages.Count - 10) + " more messages");
                    }
                    foreach (var sid in t.StateIds)
                    {
                        sb.AppendLine();
                        XmlElement st;
                        index.TryGetValue(sid, out st);
                        Line(sb, "State ID", sid + (st == null ? "" : " (" + st.LocalName + ")"));
                        if (st == null) continue;
                        Line(sb, "State Comment", st.GetAttribute("comment"));
                        foreach (var req in Requirements(st, false)) Line(sb, "State Requirement", req);
                    }
                    int shown = 0;
                    foreach (var ir in t.Items)
                    {
                        if (shown == MaxItems) { sb.AppendLine(); Line(sb, "Collected Items", "... " + (t.Items.Count - MaxItems) + " more items"); break; }
                        shown++;
                        sb.AppendLine();
                        Line(sb, "Collected Item/State Result", ItemResultText(ir));
                        foreach (var e in ir.Item.Entities) Line(sb, "", EntityText(e));
                        foreach (var m in ir.Item.Messages) Line(sb, "Message", m);
                    }
                    if (t.Items.Count == 0 && t.Object != null && t.Object.Items.Count == 0)
                    {
                        sb.AppendLine();
                        Line(sb, "Collected Items", "none");
                    }
                }
            }
            return sb.ToString().TrimEnd();
        }

        static void Line(StringBuilder sb, string label, string text)
        {
            sb.Append(label.PadRight(28)).Append(": ").AppendLine(text ?? "");
        }

        static string Title(string s)
        {
            return string.IsNullOrEmpty(s) ? s : char.ToUpperInvariant(s[0]) + s.Substring(1);
        }

        Dictionary<string, XmlElement> Index(string href)
        {
            Dictionary<string, XmlElement> idx;
            if (href == null) return new Dictionary<string, XmlElement>();
            if (indexes.TryGetValue(href, out idx)) return idx;
            idx = new Dictionary<string, XmlElement>(StringComparer.Ordinal);
            XmlDocument doc;
            if (content.CheckComponents.TryGetValue(href, out doc))
                foreach (XmlElement e in doc.SelectNodes("//*[@id]"))
                    if (!idx.ContainsKey(e.GetAttribute("id"))) idx[e.GetAttribute("id")] = e;
            indexes[href] = idx;
            return idx;
        }

        /// <summary>Human-readable requirement lines for an object's or state's entities.</summary>
        static IEnumerable<string> Requirements(XmlElement element, bool isObject)
        {
            foreach (XmlNode n in element.ChildNodes)
            {
                var e = n as XmlElement;
                if (e == null || e.LocalName == "notes") continue;
                if (e.LocalName == "behaviors")
                {
                    yield return "behaviors: " + string.Join(", ", e.Attributes.Cast<XmlAttribute>().Select(a => a.Name + "=" + a.Value));
                    continue;
                }
                if (e.LocalName == "set")
                {
                    foreach (XmlNode r in e.ChildNodes)
                        if (r.LocalName == "object_reference") yield return "set member: " + r.InnerText.Trim();
                    yield return "set operator: " + (e.HasAttribute("set_operator") ? e.GetAttribute("set_operator") : "UNION");
                    continue;
                }
                if (e.LocalName == "filter")
                {
                    yield return (e.GetAttribute("action") == "include" ? "include items matching " : "exclude items matching ") + e.InnerText.Trim();
                    continue;
                }
                if (e.GetAttribute("nil", "http://www.w3.org/2001/XMLSchema-instance") == "true") continue;
                string op = e.HasAttribute("operation") ? e.GetAttribute("operation") : "equals";
                string value = e.HasAttribute("var_ref") ? "the value(s) of " + e.GetAttribute("var_ref") : "'" + e.InnerText.Trim() + "'";
                if (e.GetAttribute("datatype") == "record")
                {
                    var fields = e.ChildNodes.OfType<XmlElement>().Where(f => f.LocalName == "field")
                        .Select(f => "'" + f.GetAttribute("name") + "' must " + OperationText(f.HasAttribute("operation") ? f.GetAttribute("operation") : "equals") + " '" + f.InnerText.Trim() + "'");
                    yield return "for '" + e.LocalName + "': " + string.Join("; ", fields);
                    continue;
                }
                if (e.IsEmpty && !e.HasAttribute("var_ref") && e.HasAttribute("check_existence"))
                {
                    yield return "check_existence = '" + e.GetAttribute("check_existence") + "' for '" + e.LocalName + "'";
                    continue;
                }
                string prefix = isObject ? "check = " : "check_existence = '" + (e.HasAttribute("check_existence") ? e.GetAttribute("check_existence") : "at_least_one_exists") + "', check = " +
                    (e.HasAttribute("entity_check") ? e.GetAttribute("entity_check") : "all") + " ";
                yield return prefix + "'" + e.LocalName + "' must " + OperationText(op) + " " + value;
            }
        }

        static string OperationText(string op)
        {
            switch (op)
            {
                case "equals": return "be equal to";
                case "not equal": return "not be equal to";
                case "case insensitive equals": return "be equal (case insensitive) to";
                case "case insensitive not equal": return "not be equal (case insensitive) to";
                case "pattern match": return "match the pattern";
                case "greater than": return "be greater than";
                case "greater than or equal": return "be greater than or equal to";
                case "less than": return "be less than";
                case "less than or equal": return "be less than or equal to";
                case "bitwise and": return "match (bitwise and)";
                case "bitwise or": return "match (bitwise or)";
                case "subset of": return "be a subset of";
                case "superset of": return "be a superset of";
                default: return op;
            }
        }

        static string ExistenceText(string e)
        {
            switch (e)
            {
                case "all_exist": return "All collected items must exist.";
                case "any_exist": return "Zero or more collected items may exist.";
                case "none_exist": return "No collected items may exist.";
                case "only_one_exists": return "One and only one item may exist.";
                default: return "One or more collected items must exist.";
            }
        }

        static string CheckText(string c)
        {
            switch (c)
            {
                case "at least one": return "At least one collected item must match the given state(s).";
                case "none satisfy": return "No collected item may match the given state(s).";
                case "only one": return "One and only one item may match the given state(s).";
                default: return "All collected items must match the given state(s).";
            }
        }

        public static string OvalText(OvalResult r)
        {
            switch (r)
            {
                case OvalResult.True: return "true";
                case OvalResult.False: return "false";
                case OvalResult.Error: return "error";
                case OvalResult.Unknown: return "unknown";
                case OvalResult.NotApplicable: return "not applicable";
                default: return "not evaluated";
            }
        }

        static string FlagText(CollectedFlag f)
        {
            switch (f)
            {
                case CollectedFlag.DoesNotExist: return "does not exist";
                case CollectedFlag.NotCollected: return "not collected";
                case CollectedFlag.NotApplicable: return "not applicable";
                default: return f.ToString().ToLowerInvariant();
            }
        }

        static string ItemResultText(ItemResult ir)
        {
            if (ir.Item.Status == ItemStatus.DoesNotExist) return "does not exist";
            if (ir.Item.Status == ItemStatus.Error) return "error";
            return ir.Result == OvalResult.NotEvaluated ? "exists" : OvalText(ir.Result);
        }

        public static string EntityText(OvalEntity e)
        {
            if (e.Status == ItemStatus.DoesNotExist) return e.Name + " does not exist";
            if (e.Status == ItemStatus.Error) return e.Name + " error";
            if (e.Datatype == "record")
                return e.Name + ": " + string.Join(", ", e.Fields.Select(f => f.Name + " = '" + f.Value + "'"));
            return e.Name + " equals '" + e.Value + "'";
        }
    }
}
