using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;
using PowerScap.Engine.Reports;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Engine.Scan
{
    /// <summary>A past scan as the history list shows it (the full report loads on demand).</summary>
    public class HistoryEntry
    {
        public string ReportPath { get; set; }
        public string BenchmarkId { get; set; }
        public string Title { get; set; }
        public string Version { get; set; }
        public string ProfileId { get; set; }
        public string HostName { get; set; }
        public DateTime Start { get; set; }
        public double Score { get; set; }
        public int Open { get; set; }
        public int Passed { get; set; }
        public int Errors { get; set; }
        public int NotReviewed { get; set; }

        public override string ToString() { return string.Format("{0:yyyy-MM-dd HH:mm}  {1}", Start, Title); }
    }

    /// <summary>
    /// Scan history: each scan's report saved as JSON (&lt;stem&gt;.report.json) plus a small summary (&lt;stem&gt;.json)
    /// so the list loads without reading every report.
    /// </summary>
    public class ScanHistory
    {
        public ScanHistory(string root) { Root = Path.GetFullPath(root); }

        public string Root { get; private set; }

        /// <summary>%POWERSCAP_HISTORYDIR%, else %ProgramData%\PowerSCAP\history.</summary>
        public static string DefaultRoot()
        {
            string env = Environment.GetEnvironmentVariable("POWERSCAP_HISTORYDIR");
            if (!string.IsNullOrEmpty(env)) return env;
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"PowerSCAP\history");
        }

        static JavaScriptSerializer Json() { return new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 64 }; }

        public HistoryEntry Save(BenchmarkReport report)
        {
            Directory.CreateDirectory(Root);
            string xccdf;
            string stem = report.Files.TryGetValue("XCCDF", out xccdf)
                ? Path.GetFileName(xccdf).Replace("_XCCDF-Results.xml", "")
                : string.Format("{0}_{1:yyyyMMdd_HHmmss}", report.Target == null ? Environment.MachineName : report.Target.HostName, report.Start);
            string reportPath = Path.Combine(Root, stem + ".report.json");
            for (int n = 2; File.Exists(reportPath); n++) reportPath = Path.Combine(Root, stem + "_" + n + ".report.json");

            var entry = new HistoryEntry
            {
                ReportPath = reportPath,
                BenchmarkId = report.BenchmarkId,
                Title = report.StigName ?? report.Title,
                Version = report.StigVersion ?? report.Version,
                ProfileId = report.ProfileId,
                HostName = report.Target == null ? null : report.Target.HostName,
                Start = report.Start,
                Score = report.DefaultScore,
                Open = report.Count(XccdfResult.Fail),
                Passed = report.Count(XccdfResult.Pass),
                Errors = report.Count(XccdfResult.Error) + report.Count(XccdfResult.Unknown),
                NotReviewed = report.Count(XccdfResult.NotChecked)
            };
            var json = Json();
            File.WriteAllText(reportPath, json.Serialize(report), Encoding.UTF8);
            File.WriteAllText(reportPath.Substring(0, reportPath.Length - ".report.json".Length) + ".json", json.Serialize(entry), Encoding.UTF8);
            return entry;
        }

        /// <summary>Newest first. Summaries that cannot be read, or whose report is gone, are skipped.</summary>
        public IList<HistoryEntry> List()
        {
            var list = new List<HistoryEntry>();
            if (!Directory.Exists(Root)) return list;
            var json = Json();
            foreach (var f in Directory.GetFiles(Root, "*.json"))
            {
                if (f.EndsWith(".report.json", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    var e = json.Deserialize<HistoryEntry>(File.ReadAllText(f, Encoding.UTF8));
                    if (e == null || string.IsNullOrEmpty(e.ReportPath)) continue;
                    // The folder may have moved: the report sits next to its summary.
                    e.ReportPath = f.Substring(0, f.Length - ".json".Length) + ".report.json";
                    if (!File.Exists(e.ReportPath)) continue;
                    e.Start = e.Start.ToLocalTime();
                    list.Add(e);
                }
                catch (Exception ex)
                {
                    if (ex is OutOfMemoryException) throw;
                }
            }
            return list.OrderByDescending(e => e.Start).ToList();
        }

        public BenchmarkReport Load(string reportPath)
        {
            var r = Json().Deserialize<BenchmarkReport>(File.ReadAllText(reportPath, Encoding.UTF8));
            r.Start = r.Start.ToLocalTime();
            r.End = r.End.ToLocalTime();
            if (r.Files == null) r.Files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            else r.Files = new Dictionary<string, string>(r.Files, StringComparer.OrdinalIgnoreCase);
            foreach (var rule in r.Rules)
                if (rule.DescriptionTags != null) rule.DescriptionTags = new Dictionary<string, string>(rule.DescriptionTags, StringComparer.OrdinalIgnoreCase);
            return r;
        }

        /// <summary>The newest earlier scan of the same benchmark and profile, for "changed since" comparisons.</summary>
        public HistoryEntry Previous(BenchmarkReport report)
        {
            return List().FirstOrDefault(e => e.BenchmarkId == report.BenchmarkId && e.ProfileId == report.ProfileId && e.Start < report.Start.AddSeconds(-1));
        }
    }
}
