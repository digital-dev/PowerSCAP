using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;
using PowerScap.Engine.Content;
using PowerScap.Engine.Oval;
using PowerScap.Engine.Reports;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Engine.Scan
{
    [Flags]
    public enum OutputFormats { None = 0, Html = 1, Cklb = 2, Oval = 4, Arf = 8, All = 15 }

    public class ScanRequest
    {
        public ScanRequest() { Formats = OutputFormats.Html | OutputFormats.Cklb; }

        /// <summary>SCAP source data stream (.xml or .zip) or standalone XCCDF benchmark.</summary>
        public string ContentPath { get; set; }
        /// <summary>XCCDF profile; null or empty selects the benchmark's first profile.</summary>
        public string ProfileId { get; set; }
        public string OutputPath { get; set; }
        /// <summary>Outputs besides the XCCDF results, which are always written.</summary>
        public OutputFormats Formats { get; set; }
        public bool AllowInvalidSignature { get; set; }
    }

    /// <summary>A finished scan: the report every output is built from, plus the raw rule results and signature check.</summary>
    public class ScanOutcome
    {
        public BenchmarkReport Report { get; set; }
        public List<RuleResult> Results { get; set; }
        public SignatureReport Signature { get; set; }
    }

    /// <summary>Reports on the calling thread (Progress&lt;T&gt; posts to the thread pool when there is no UI thread).</summary>
    public class SyncProgress<T> : IProgress<T>
    {
        readonly Action<T> handler;
        public SyncProgress(Action<T> handler) { this.handler = handler; }
        public void Report(T value) { handler(value); }
    }

    public class ScanException : Exception
    {
        public ScanException(string message) : base(message) { }
    }

    /// <summary>
    /// One benchmark scan, end to end: signature check, evaluation, XCCDF results and the requested reports.
    /// Invoke-PowerScapScan and the GUI both run scans through this class.
    /// </summary>
    public class ScanRunner
    {
        readonly CollectorRegistry collectors;

        /// <summary>Benchmarks scanned by one runner share its collectors (each folder and key is read once).</summary>
        public ScanRunner(CollectorRegistry collectors)
        {
            this.collectors = collectors ?? CollectorRegistry.CreateDefault();
        }

        /// <summary>When set, each finished scan is also saved there for later browsing and comparison.</summary>
        public string HistoryRoot { get; set; }

        /// <summary>Messages about non-fatal problems (a history save that failed).</summary>
        public event Action<string> Warning;

        public ScanOutcome Run(ScanRequest request, IProgress<ScanProgress> progress, CancellationToken cancel)
        {
            if (request == null) throw new ArgumentNullException("request");
            string path = request.ContentPath;
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) throw new ScanException("Content file is missing from disk: " + path);
            if (string.IsNullOrEmpty(request.OutputPath)) throw new ScanException("No output folder was given.");

            var remarks = new List<string>();
            var signature = SignatureVerifier.Verify(path);
            if (signature.State == SignatureState.Invalid)
            {
                if (!request.AllowInvalidSignature)
                    throw new ScanException("Signature check failed for " + Path.GetFileName(path) + ": " + signature.Message +
                        ". Re-download the content or allow the invalid signature.");
                remarks.Add("Signature verification failed and was overridden by the operator: " + signature.Message);
            }
            cancel.ThrowIfCancellationRequested();

            DateTime start = DateTime.Now;
            var content = ScapContentLoader.Load(path);
            string profileId = string.IsNullOrEmpty(request.ProfileId) ? FirstProfile(content) : request.ProfileId;
            var profile = ProfileResolver.Resolve(content, profileId);
            var results = RuleEvaluator.Evaluate(content, profile, collectors, progress, cancel);
            var scores = Scoring.Compute(profile, results);
            var target = TargetInfo.Collect();
            DateTime end = DateTime.Now;
            // Nothing is written until evaluation is complete: a cancelled scan leaves no partial files.
            cancel.ThrowIfCancellationRequested();

            Directory.CreateDirectory(request.OutputPath);
            string stem = Stem(request.OutputPath, target.HostName, content.BenchmarkId, start);
            string xccdf = stem + "_XCCDF-Results.xml";
            ResultsWriter.WriteXccdf(content, profile, results, scores, target, xccdf, start, end, remarks);

            var report = BenchmarkReport.Build(content, profile, results, scores, target, start, end);
            report.Signature = signature.ToString();
            report.Files["XCCDF"] = xccdf;
            var f = request.Formats;
            if ((f & OutputFormats.Html) != 0)
            {
                report.Files["All-Settings"] = stem + "_All-Settings.html";
                report.Files["Non-Compliance"] = stem + "_Non-Compliance.html";
                HtmlReport.Write(report, report.Files["All-Settings"], false);
                HtmlReport.Write(report, report.Files["Non-Compliance"], true);
            }
            if ((f & OutputFormats.Cklb) != 0)
            {
                report.Files["Checklist"] = stem + "_Checklist.cklb";
                CklbWriter.Write(new[] { report }, report.Files["Checklist"]);
            }
            if ((f & (OutputFormats.Oval | OutputFormats.Arf)) != 0)
            {
                var oval = OvalResultsWriter.Build(results, content, target, end);
                if ((f & OutputFormats.Oval) != 0)
                {
                    int i = 0;
                    foreach (var kv in oval)
                    {
                        i++;
                        string name = oval.Count > 1 ? stem + "_OVAL-Results-" + i + ".xml" : stem + "_OVAL-Results.xml";
                        kv.Value.Save(name);
                        report.Files[oval.Count > 1 ? "OVAL-" + i : "OVAL"] = name;
                    }
                }
                if ((f & OutputFormats.Arf) != 0)
                {
                    report.Files["ARF"] = stem + "_ARF.xml";
                    ArfWriter.Write(report, xccdf, oval, report.Files["ARF"]);
                }
            }

            if (!string.IsNullOrEmpty(HistoryRoot))
            {
                try { new ScanHistory(HistoryRoot).Save(report); }
                catch (Exception e)
                {
                    if (e is OutOfMemoryException) throw;
                    var w = Warning;
                    if (w != null) w("The scan finished but could not be saved to the scan history: " + e.Message);
                }
            }
            return new ScanOutcome { Report = report, Results = results, Signature = signature };
        }

        /// <summary>The combined summary page for several benchmarks scanned together; null for fewer than two.</summary>
        public static string WriteSummary(IList<BenchmarkReport> reports, string outputPath)
        {
            if (reports == null || reports.Count < 2) return null;
            string file = Path.Combine(outputPath, string.Format("{0}_{1:yyyyMMdd_HHmmss}_Summary.html", reports[0].Target.HostName, reports[0].Start));
            SummaryReport.Write(reports, file);
            return file;
        }

        /// <summary>The profiles a benchmark offers, in document order (id, title).</summary>
        public static IList<KeyValuePair<string, string>> Profiles(ScapContent content)
        {
            var list = new List<KeyValuePair<string, string>>();
            foreach (XmlNode n in content.Benchmark.DocumentElement.ChildNodes)
            {
                var e = n as XmlElement;
                if (e == null || e.LocalName != "Profile") continue;
                string title = null;
                foreach (XmlNode c in e.ChildNodes)
                    if (c.NodeType == XmlNodeType.Element && c.LocalName == "title") { title = c.InnerText.Trim(); break; }
                list.Add(new KeyValuePair<string, string>(e.GetAttribute("id"), title ?? e.GetAttribute("id")));
            }
            return list;
        }

        static string FirstProfile(ScapContent content)
        {
            var p = Profiles(content);
            return p.Count > 0 ? p[0].Key : null;
        }

        /// <summary>&lt;host&gt;_&lt;benchmark&gt;_&lt;yyyyMMdd_HHmmss&gt;, with _2, _3 ... so an earlier run in the same second is never overwritten.</summary>
        static string Stem(string folder, string host, string benchmarkId, DateTime start)
        {
            string shortName = Regex.Replace(benchmarkId ?? "benchmark", "^xccdf_.*?_benchmark_", "");
            shortName = Regex.Replace(shortName, @"[^\w\-\.]", "_");
            string stem = Path.Combine(folder, string.Format("{0}_{1}_{2:yyyyMMdd_HHmmss}", host, shortName, start));
            string candidate = stem;
            for (int n = 2; File.Exists(candidate + "_XCCDF-Results.xml"); n++) candidate = stem + "_" + n;
            return candidate;
        }
    }
}
