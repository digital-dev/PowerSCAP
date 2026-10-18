using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Engine.Reports
{
    /// <summary>One STIG in a checklist, with its rules as the Results view models them.</summary>
    public class ChecklistStig
    {
        public ChecklistStig() { Rules = new List<RuleReport>(); }

        public string Name { get; set; }
        public string StigId { get; set; }
        public string Version { get; set; }
        public string ReleaseInfo { get; set; }
        public List<RuleReport> Rules { get; private set; }

        public override string ToString()
        {
            return Name + (string.IsNullOrEmpty(Version) ? "" : "  V" + Version) + "  (" + Rules.Count + " rules)";
        }
    }

    /// <summary>A STIG Viewer 3 checklist (.cklb), from PowerSCAP, SCC or STIG Viewer itself.</summary>
    public class ChecklistFile
    {
        public ChecklistFile() { Stigs = new List<ChecklistStig>(); }

        public string Path { get; set; }
        public string Title { get; set; }
        public string HostName { get; set; }
        public string Fqdn { get; set; }
        public string IpAddress { get; set; }
        public string Role { get; set; }
        public List<ChecklistStig> Stigs { get; private set; }
    }

    /// <summary>Reads .cklb JSON. Read-only: PowerSCAP shows checklists; editing them is STIG Viewer's job.</summary>
    public static class CklbReader
    {
        public static ChecklistFile Read(string path)
        {
            object parsed;
            try
            {
                parsed = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 256 }
                    .DeserializeObject(File.ReadAllText(path, Encoding.UTF8));
            }
            catch (ArgumentException e)
            {
                throw new InvalidDataException("Not a .cklb checklist (the file is not valid JSON): " + e.Message, e);
            }
            var doc = parsed as IDictionary<string, object>;
            if (doc == null || !doc.ContainsKey("stigs"))
                throw new InvalidDataException("Not a .cklb checklist: it has no \"stigs\" list.");

            var file = new ChecklistFile { Path = path, Title = Str(doc, "title") };
            var target = doc.ContainsKey("target_data") ? doc["target_data"] as IDictionary<string, object> : null;
            if (target != null)
            {
                file.HostName = Str(target, "host_name");
                file.Fqdn = Str(target, "fqdn");
                file.IpAddress = Str(target, "ip_address");
                file.Role = Str(target, "role");
            }
            foreach (var s in List(doc, "stigs"))
            {
                var stig = new ChecklistStig
                {
                    Name = Str(s, "stig_name") ?? Str(s, "display_name"),
                    StigId = Str(s, "stig_id"),
                    Version = Str(s, "version"),
                    ReleaseInfo = Str(s, "release_info")
                };
                foreach (var r in List(s, "rules")) stig.Rules.Add(Rule(r));
                file.Stigs.Add(stig);
            }
            return file;
        }

        static RuleReport Rule(IDictionary<string, object> r)
        {
            var rule = new RuleReport
            {
                GroupId = Str(r, "group_id") ?? Str(r, "group_id_src"),
                GroupTitle = Str(r, "group_title"),
                RuleId = Str(r, "rule_id_src") ?? Str(r, "rule_id"),
                StigId = Str(r, "rule_version"),
                Title = Str(r, "rule_title"),
                Severity = (Str(r, "severity") ?? "unknown").ToLowerInvariant(),
                Discussion = Str(r, "discussion"),
                CheckText = Str(r, "check_content"),
                FixText = Str(r, "fix_text"),
                Details = Str(r, "finding_details"),
                Comments = Str(r, "comments"),
                Result = ResultOf(Str(r, "status")),
                Source = "Checklist"
            };
            rule.Cat = rule.Severity == "high" ? "CAT I" : rule.Severity == "medium" ? "CAT II" : rule.Severity == "low" ? "CAT III" : "Unknown";
            foreach (var c in Strings(r, "ccis")) rule.Ccis.Add(c);
            foreach (var c in Strings(r, "legacy_ids")) rule.LegacyIds.Add(c);
            return rule;
        }

        /// <summary>STIG Viewer statuses (snake_case in .cklb; NotAFinding style in older .ckl exports) to XCCDF results.</summary>
        public static XccdfResult ResultOf(string status)
        {
            switch ((status ?? "").Replace("_", "").Replace(" ", "").ToLowerInvariant())
            {
                case "notafinding": return XccdfResult.Pass;
                case "open": return XccdfResult.Fail;
                case "notapplicable": return XccdfResult.NotApplicable;
                default: return XccdfResult.NotChecked;
            }
        }

        static string Str(IDictionary<string, object> o, string key)
        {
            object v;
            if (o == null || !o.TryGetValue(key, out v) || v == null) return null;
            string s = Convert.ToString(v, CultureInfo.InvariantCulture);
            return s.Length == 0 ? null : s;
        }

        static IEnumerable<IDictionary<string, object>> List(IDictionary<string, object> o, string key)
        {
            object v;
            if (o == null || !o.TryGetValue(key, out v)) return new IDictionary<string, object>[0];
            var e = v as IEnumerable;
            return e == null ? new IDictionary<string, object>[0] : e.OfType<IDictionary<string, object>>();
        }

        static IEnumerable<string> Strings(IDictionary<string, object> o, string key)
        {
            object v;
            if (o == null || !o.TryGetValue(key, out v) || v is string) return new string[0];
            var e = v as IEnumerable;
            return e == null ? new string[0] : e.OfType<object>().Select(x => Convert.ToString(x, CultureInfo.InvariantCulture)).Where(x => x.Length > 0);
        }
    }
}
