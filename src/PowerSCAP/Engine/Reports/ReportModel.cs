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
        /// <summary>Reviewer comments (checklists read from .cklb; empty for scans).</summary>
        public string Comments { get; set; }
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

        /// <summary>The question to put to a reviewer for a manual rule: the content's OCIL question, else the check text.</summary>
        public string Question { get; set; }

        /// <summary>Layer 2 or 3 outcome (PowerSCAP script, or a person's answer). Never changes <see cref="Result"/>.</summary>
        public RuleReview Review { get; set; }

        /// <summary>The content left this rule to a person (the SCAP result is notchecked).</summary>
        public bool IsManual { get { return Result == XccdfResult.NotChecked; } }

        /// <summary>The status a checklist shows: the SCAP result when SCAP decided it, else the review's.</summary>
        public XccdfResult EffectiveResult
        {
            get { return IsManual && Review != null && Review.IsDecided ? Review.Status : Result; }
        }

        /// <summary>SCAP, Script, Answered, or Manual (left to a person and not yet reviewed).</summary>
        public string EffectiveSource
        {
            get
            {
                if (!IsManual) return string.IsNullOrEmpty(Source) ? "SCAP" : Source;
                if (Review == null || !Review.IsDecided) return "Manual";
                return Review.Source == RuleReview.Answer ? "Answered" : "Script";
            }
        }
    }

    /// <summary>
    /// The outcome of the layers beyond SCAP for a manual rule: a PowerSCAP native check (Script) or a person's answer.
    /// Kept apart from the SCAP result, which it never changes.
    /// </summary>
    public class RuleReview
    {
        public const string Script = "Script";
        public const string Answer = "Answer";

        /// <summary>Pass (not a finding), Fail (open), NotApplicable, or NotChecked when only evidence was gathered.</summary>
        public XccdfResult Status { get; set; }
        /// <summary>Script or Answer.</summary>
        public string Source { get; set; }
        /// <summary>Who answered (DOMAIN\user), or "PowerSCAP" for a script.</summary>
        public string Author { get; set; }
        public DateTime When { get; set; }
        public string Comment { get; set; }
        /// <summary>What a script found (accounts, adapters, policy values), shown to the reviewer.</summary>
        public string Evidence { get; set; }
        /// <summary>The rule changed (revision or check text) since this answer was given.</summary>
        public bool NeedsReReview { get; set; }

        public bool IsDecided
        {
            get { return !NeedsReReview && (Status == XccdfResult.Pass || Status == XccdfResult.Fail || Status == XccdfResult.NotApplicable); }
        }

        /// <summary>STIG Viewer's name for a status: Open, Not a Finding, Not Applicable, Not Reviewed.</summary>
        public static string StatusName(XccdfResult r)
        {
            switch (r)
            {
                case XccdfResult.Pass: return "Not a Finding";
                case XccdfResult.Fail: return "Open";
                case XccdfResult.NotApplicable: return "Not Applicable";
                default: return "Not Reviewed";
            }
        }

        /// <summary>"PowerSCAP automated" or "Answered by DOMAIN\user 2026-10-18".</summary>
        public string Label
        {
            get
            {
                return Source == Answer
                    ? "Answered by " + Author + " " + When.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)
                    : "PowerSCAP automated";
            }
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

        /// <summary>
        /// STIG completeness, 0-100: the share of rules with a status other than Not Reviewed once script checks and
        /// answers are counted. Separate from the SCAP scores, which only SCAP results feed.
        /// </summary>
        public double Completeness
        {
            get
            {
                if (Rules.Count == 0) return 0;
                return 100.0 * Rules.Count(x => x.EffectiveResult != XccdfResult.NotChecked && x.EffectiveResult != XccdfResult.Informational) / Rules.Count;
            }
        }

        /// <summary>Open findings per category counting script checks and answers (the checklist's view).</summary>
        public int OpenEffective(string cat) { return Rules.Count(x => x.Cat == cat && x.EffectiveResult == XccdfResult.Fail); }

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
            var questions = new OcilQuestions(content);
            foreach (var r in results.Where(x => x.Result != XccdfResult.NotSelected))
            {
                var rr = Describe(r, details);
                if (rr.IsManual) rr.Question = questions.For(r.Rule.RuleElement) ?? rr.CheckText;
                report.Rules.Add(rr);
            }
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
