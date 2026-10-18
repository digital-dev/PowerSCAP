using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using PowerScap.Engine.Content;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Engine.Reports
{
    /// <summary>One rule as reports and checklists show it: STIG metadata, result and finding details.</summary>
    public class RuleReport
    {
        public RuleReport()
        {
            Ccis = new List<string>();
            LegacyIds = new List<string>();
            DescriptionTags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public string GroupId { get; set; }
        public string GroupTitle { get; set; }
        public string RuleId { get; set; }
        public string StigId { get; set; }
        public string Title { get; set; }
        public string Severity { get; set; }
        public string Cat { get; set; }
        public double Weight { get; set; }
        public string Discussion { get; set; }
        public string CheckText { get; set; }
        public string FixText { get; set; }
        public List<string> Ccis { get; set; }
        public List<string> LegacyIds { get; set; }
        public string DpmsTarget { get; set; }
        public string DpmsIdentifier { get; set; }
        public XccdfResult Result { get; set; }
        /// <summary>Where the result came from: "SCAP" for the content's own checks.</summary>
        public string Source { get; set; }
        public string Details { get; set; }
        public string CheckHref { get; set; }
        public string CheckName { get; set; }
        /// <summary>The tagged fields of the STIG description (VulnDiscussion, FalsePositives, Documentable, ...).</summary>
        public Dictionary<string, string> DescriptionTags { get; set; }

        public string ResultText { get { return ResultsWriter.ResultText(Result); } }

        /// <summary>True for results a reviewer must act on: fail, error, unknown.</summary>
        public bool IsNonCompliant
        {
            get { return Result == XccdfResult.Fail || Result == XccdfResult.Error || Result == XccdfResult.Unknown; }
        }
    }

    /// <summary>A scanned benchmark, ready for any output format.</summary>
    public class BenchmarkReport
    {
        public BenchmarkReport()
        {
            Rules = new List<RuleReport>();
            Scores = new List<Score>();
            Files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public string BenchmarkId { get; set; }
        public string Title { get; set; }
        public string Version { get; set; }
        public string ReleaseInfo { get; set; }
        public string StigName { get; set; }
        public string StigId { get; set; }
        public string StigVersion { get; set; }
        public string StigReleaseInfo { get; set; }
        public string Classification { get; set; }
        public string ProfileId { get; set; }
        public string ProfileTitle { get; set; }
        public DateTime Start { get; set; }
        public DateTime End { get; set; }
        public TargetInfo Target { get; set; }
        public List<Score> Scores { get; set; }
        public List<RuleReport> Rules { get; set; }
        public string ContentFile { get; set; }
        public string Signature { get; set; }
        /// <summary>Output files written for this benchmark, by kind (All-Settings, Checklist, ...).</summary>
        public Dictionary<string, string> Files { get; set; }

        public double DefaultScore
        {
            get
            {
                var s = Scores.FirstOrDefault(x => x.System == "urn:xccdf:scoring:default") ?? Scores.FirstOrDefault();
                return s == null ? 0 : s.Value;
            }
        }

        public int Count(XccdfResult r) { return Rules.Count(x => x.Result == r); }

        /// <summary>Open findings (fail) in a category, as STIG Viewer counts them; errors are not reviewed, not open.</summary>
        public int Open(string cat) { return Rules.Count(x => x.Cat == cat && x.Result == XccdfResult.Fail); }

        public static BenchmarkReport Build(ScapContent content, ResolvedProfile profile, List<RuleResult> results, List<Score> scores,
            TargetInfo target, DateTime start, DateTime end)
        {
            var b = content.Benchmark.DocumentElement;
            var report = new BenchmarkReport
            {
                BenchmarkId = content.BenchmarkId,
                Title = Child(b, "title"),
                Version = Child(b, "version"),
                ReleaseInfo = PlainText(b, "release-info"),
                ProfileId = profile.ProfileId,
                Start = start,
                End = end,
                Target = target,
                ContentFile = content.SourcePath
            };
            var meta = RearMatter(Child(b, "rear-matter"));
            report.StigName = Get(meta, "title") ?? report.Title;
            report.StigId = Get(meta, "stigid") ?? content.BenchmarkId;
            report.StigVersion = Get(meta, "version");
            report.StigReleaseInfo = Get(meta, "releaseinfo") ?? report.ReleaseInfo;
            report.Classification = Get(meta, "classification") ?? "UNCLASSIFIED";
            if (!string.IsNullOrEmpty(profile.ProfileId))
                foreach (XmlNode n in b.ChildNodes)
                {
                    var e = n as XmlElement;
                    if (e != null && e.LocalName == "Profile" && e.GetAttribute("id") == profile.ProfileId) report.ProfileTitle = Child(e, "title");
                }
            report.Scores.AddRange(scores);

            var details = new FindingDetails(content);
            foreach (var r in results.Where(x => x.Result != XccdfResult.NotSelected))
                report.Rules.Add(Describe(r, details));
            return report;
        }

        static RuleReport Describe(RuleResult r, FindingDetails details)
        {
            var e = r.Rule.RuleElement;
            var rr = new RuleReport
            {
                RuleId = r.Rule.RuleId,
                Title = Child(e, "title"),
                StigId = Child(e, "version"),
                Severity = string.IsNullOrEmpty(r.Rule.Severity) ? "unknown" : r.Rule.Severity,
                Weight = r.Rule.Weight,
                FixText = Child(e, "fixtext"),
                Result = r.Result,
                Source = "SCAP",
                CheckHref = r.CheckHref,
                CheckName = r.CheckName
            };
            rr.Cat = rr.Severity == "high" ? "CAT I" : rr.Severity == "medium" ? "CAT II" : rr.Severity == "low" ? "CAT III" : "Unknown";
            var group = e.ParentNode as XmlElement;
            if (group != null && group.LocalName == "Group")
            {
                string gid = group.GetAttribute("id");
                int v = gid.LastIndexOf("_V-", StringComparison.Ordinal);
                rr.GroupId = v >= 0 ? gid.Substring(v + 1) : gid;
                rr.GroupTitle = Child(group, "title");
            }
            foreach (Match m in Regex.Matches(Child(e, "description") ?? "", @"<(\w+)>(.*?)</\1>", RegexOptions.Singleline))
                rr.DescriptionTags[m.Groups[1].Value] = m.Groups[2].Value;
            string discussion;
            rr.Discussion = rr.DescriptionTags.TryGetValue("VulnDiscussion", out discussion) ? discussion : Child(e, "description");
            foreach (XmlNode n in e.ChildNodes)
            {
                var c = n as XmlElement;
                if (c == null) continue;
                if (c.LocalName == "ident")
                {
                    string system = c.GetAttribute("system");
                    if (system.IndexOf("cci", StringComparison.OrdinalIgnoreCase) >= 0) rr.Ccis.Add(c.InnerText.Trim());
                    else if (system.IndexOf("legacy", StringComparison.OrdinalIgnoreCase) >= 0) rr.LegacyIds.Add(c.InnerText.Trim());
                }
                else if (c.LocalName == "reference")
                {
                    foreach (XmlNode d in c.ChildNodes)
                    {
                        if (d.LocalName == "subject") rr.DpmsTarget = d.InnerText.Trim();
                        else if (d.LocalName == "identifier") rr.DpmsIdentifier = d.InnerText.Trim();
                    }
                }
                else if (c.LocalName == "check" && rr.CheckText == null)
                {
                    foreach (XmlNode d in c.ChildNodes)
                        if (d.LocalName == "check-content") rr.CheckText = d.InnerText.Trim();
                }
            }
            rr.Details = details.Render(r);
            return rr;
        }

        internal static string Child(XmlElement e, string name)
        {
            if (e == null) return null;
            foreach (XmlNode n in e.ChildNodes)
                if (n.NodeType == XmlNodeType.Element && n.LocalName == name) return n.InnerText.Trim();
            return null;
        }

        static string PlainText(XmlElement b, string id)
        {
            foreach (XmlNode n in b.ChildNodes)
            {
                var e = n as XmlElement;
                if (e != null && e.LocalName == "plain-text" && e.GetAttribute("id") == id) return e.InnerText.Trim();
            }
            return null;
        }

        /// <summary>DISA rear-matter "key:--:value" pairs, the metadata STIG Viewer checklists are built from.</summary>
        static Dictionary<string, string> RearMatter(string text)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(text)) return d;
            var ms = Regex.Matches(text, @"(?:^|\s)(\w+):--:");
            for (int i = 0; i < ms.Count; i++)
            {
                int start = ms[i].Index + ms[i].Length;
                int end = i + 1 < ms.Count ? ms[i + 1].Index : text.Length;
                d[ms[i].Groups[1].Value] = text.Substring(start, end - start).Trim();
            }
            return d;
        }

        static string Get(Dictionary<string, string> d, string key)
        {
            string v;
            return d.TryGetValue(key, out v) && v.Length > 0 ? v : null;
        }
    }
}
