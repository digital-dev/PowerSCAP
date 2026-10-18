using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Engine.Reports
{
    /// <summary>A person's answer to a manual rule, as stored.</summary>
    public class StoredAnswer
    {
        public string BenchmarkId { get; set; }
        /// <summary>The STIG ID (rule version, e.g. WN11-00-000070): stable across content releases.</summary>
        public string StigId { get; set; }
        /// <summary>The XCCDF rule id with its revision (SV-253269r958702_rule) when answered.</summary>
        public string RuleId { get; set; }
        /// <summary>SHA-256 of the check text when answered.</summary>
        public string CheckHash { get; set; }
        /// <summary>pass, fail, notapplicable (XCCDF result names).</summary>
        public string Status { get; set; }
        public string Comment { get; set; }
        public string Author { get; set; }
        public DateTime WhenUtc { get; set; }
    }

    /// <summary>
    /// Answers to manual rules (design layer 3), one JSON file per machine in %ProgramData%\PowerSCAP\answers
    /// (%POWERSCAP_ANSWERSDIR% overrides). Answers are reused on later scans; one given to an earlier revision or check
    /// text of the rule is flagged for re-review rather than applied.
    /// </summary>
    public class AnswerStore
    {
        readonly object gate = new object();

        public AnswerStore(string root) { Root = Path.GetFullPath(root); }

        public string Root { get; private set; }

        public static string DefaultRoot()
        {
            string env = Environment.GetEnvironmentVariable("POWERSCAP_ANSWERSDIR");
            if (!string.IsNullOrEmpty(env)) return env;
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"PowerSCAP\answers");
        }

        string FileFor(string host) { return Path.Combine(Root, (string.IsNullOrEmpty(host) ? Environment.MachineName : host).ToUpperInvariant() + ".json"); }

        static string Key(string benchmarkId, string stigId) { return (benchmarkId ?? "") + "|" + (stigId ?? ""); }

        public static string Hash(string text)
        {
            using (var sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes((text ?? "").Replace("\r\n", "\n").Trim()))).Replace("-", "").ToLowerInvariant();
        }

        public IList<StoredAnswer> All(string host)
        {
            lock (gate) return Read(host).Values.ToList();
        }

        public StoredAnswer Get(string host, string benchmarkId, string stigId)
        {
            StoredAnswer a;
            lock (gate) return Read(host).TryGetValue(Key(benchmarkId, stigId), out a) ? a : null;
        }

        /// <summary>Records an answer for a manual rule of this benchmark; returns it as stored.</summary>
        public StoredAnswer Save(string host, string benchmarkId, RuleReport rule, XccdfResult status, string comment, string author)
        {
            if (status != XccdfResult.Pass && status != XccdfResult.Fail && status != XccdfResult.NotApplicable)
                throw new ArgumentException("An answer is Not a Finding, Open or Not Applicable.", "status");
            var a = new StoredAnswer
            {
                BenchmarkId = benchmarkId,
                StigId = rule.StigId,
                RuleId = rule.RuleId,
                CheckHash = Hash(rule.CheckText),
                Status = ResultsWriter.ResultText(status),
                Comment = comment ?? "",
                Author = string.IsNullOrEmpty(author) ? Environment.UserDomainName + "\\" + Environment.UserName : author,
                WhenUtc = DateTime.UtcNow
            };
            lock (gate)
            {
                var all = Read(host);
                all[Key(benchmarkId, rule.StigId)] = a;
                Write(host, all);
            }
            return a;
        }

        public bool Remove(string host, string benchmarkId, string stigId)
        {
            lock (gate)
            {
                var all = Read(host);
                if (!all.Remove(Key(benchmarkId, stigId))) return false;
                Write(host, all);
                return true;
            }
        }

        /// <summary>
        /// Puts stored answers on the report's manual rules. An answer replaces a script's review (a person's judgement
        /// over the script's evidence, which is kept); rules SCAP decided are never touched.
        /// </summary>
        public int Apply(BenchmarkReport report)
        {
            string host = report.Target == null ? null : report.Target.HostName;
            Dictionary<string, StoredAnswer> all;
            lock (gate) all = Read(host);
            int applied = 0;
            foreach (var rule in report.Rules.Where(r => r.IsManual))
            {
                StoredAnswer a;
                if (!all.TryGetValue(Key(report.BenchmarkId, rule.StigId), out a)) continue;
                rule.Review = ToReview(a, rule, rule.Review);
                applied++;
            }
            return applied;
        }

        public static RuleReview ToReview(StoredAnswer a, RuleReport rule, RuleReview script)
        {
            return new RuleReview
            {
                Status = ParseStatus(a.Status),
                Source = RuleReview.Answer,
                Author = a.Author,
                When = a.WhenUtc.ToLocalTime(),
                Comment = a.Comment,
                Evidence = script == null ? null : script.Evidence,
                // The rule was revised (new revision suffix or different check text) after this answer was given.
                NeedsReReview = !string.Equals(a.RuleId, rule.RuleId, StringComparison.Ordinal) || a.CheckHash != Hash(rule.CheckText)
            };
        }

        static XccdfResult ParseStatus(string s)
        {
            switch (s)
            {
                case "pass": return XccdfResult.Pass;
                case "fail": return XccdfResult.Fail;
                case "notapplicable": return XccdfResult.NotApplicable;
                default: return XccdfResult.NotChecked;
            }
        }

        Dictionary<string, StoredAnswer> Read(string host)
        {
            var map = new Dictionary<string, StoredAnswer>(StringComparer.Ordinal);
            string file = FileFor(host);
            if (!File.Exists(file)) return map;
            List<StoredAnswer> list;
            try { list = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Deserialize<List<StoredAnswer>>(File.ReadAllText(file, Encoding.UTF8)); }
            catch (ArgumentException e) { throw new InvalidDataException("The answer file " + file + " is damaged: " + e.Message, e); }
            catch (InvalidOperationException e) { throw new InvalidDataException("The answer file " + file + " is damaged: " + e.Message, e); }
            foreach (var a in list ?? new List<StoredAnswer>()) map[Key(a.BenchmarkId, a.StigId)] = a;
            return map;
        }

        void Write(string host, Dictionary<string, StoredAnswer> all)
        {
            Directory.CreateDirectory(Root);
            string file = FileFor(host), tmp = file + ".tmp";
            File.WriteAllText(tmp, new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize(all.Values.OrderBy(a => a.BenchmarkId).ThenBy(a => a.StigId).ToList()), Encoding.UTF8);
            if (File.Exists(file)) File.Replace(tmp, file, null); else File.Move(tmp, file);
        }
    }
}
