using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Engine.Reports
{
    /// <summary>One page across every benchmark in a scan: scores, open findings by CAT, links to each report.</summary>
    public static class SummaryReport
    {
        public static void Write(IList<BenchmarkReport> reports, string path)
        {
            File.WriteAllText(path, Render(reports, Path.GetDirectoryName(Path.GetFullPath(path))), new UTF8Encoding(false));
        }

        public static string Render(IList<BenchmarkReport> reports, string folder)
        {
            var first = reports.First();
            string host = first.Target == null ? "" : first.Target.HostName;
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>");
            sb.Append("<title>Scan Summary - ").Append(HtmlReport.E(host)).AppendLine("</title>");
            sb.Append("<style>").Append(HtmlReport.Css).Append(Extra).AppendLine("</style></head><body>");
            sb.AppendLine("<header class=\"top\"><div class=\"wrap\">");
            sb.Append("<div class=\"eyebrow\">PowerSCAP ").Append(HtmlReport.E(EngineInfo.Version)).AppendLine(" &#183; Scan summary</div>");
            sb.Append("<h1>").Append(HtmlReport.E(host)).AppendLine("</h1>");
            sb.Append("<div class=\"sub\">").Append(reports.Count).Append(" benchmarks &#183; ")
              .Append(HtmlReport.E(first.Start.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).AppendLine("</div>");
            sb.AppendLine("</div></header><main class=\"wrap\">");

            sb.AppendLine("<section class=\"tiles\">");
            Tile(sb, "fail", reports.Sum(r => r.Count(XccdfResult.Fail)), "Open findings");
            Tile(sb, "fail", reports.Sum(r => r.Open("CAT I")), "CAT I open");
            Tile(sb, "error", reports.Sum(r => r.Open("CAT II")), "CAT II open");
            Tile(sb, "notchecked", reports.Sum(r => r.Open("CAT III")), "CAT III open");
            Tile(sb, "pass", reports.Sum(r => r.Count(XccdfResult.Pass)), "Not a finding");
            Tile(sb, "notchecked", reports.Sum(r => r.Count(XccdfResult.NotChecked)), "Not reviewed");
            sb.AppendLine("</section>");

            sb.AppendLine("<table class=\"sum\"><thead><tr><th>Benchmark</th><th>Score</th><th>Fail</th><th>CAT I</th><th>CAT II</th><th>CAT III</th><th>Pass</th><th>N/A</th><th>Not reviewed</th><th>Error</th><th>Reports</th></tr></thead><tbody>");
            foreach (var r in reports.OrderByDescending(x => x.Open("CAT I")).ThenBy(x => x.DefaultScore))
            {
                sb.Append("<tr><td><b>").Append(HtmlReport.E(r.StigName ?? r.Title)).Append("</b><div class=\"muted\">")
                  .Append(HtmlReport.E(r.Version)).Append("</div></td>");
                sb.Append("<td><div class=\"bar\"><span style=\"width:").Append(r.DefaultScore.ToString("0", CultureInfo.InvariantCulture)).Append("%\"></span></div>")
                  .Append(r.DefaultScore.ToString("0.0", CultureInfo.InvariantCulture)).Append("%</td>");
                Cell(sb, r.Count(XccdfResult.Fail), "fail");
                Cell(sb, r.Open("CAT I"), "fail");
                Cell(sb, r.Open("CAT II"), "");
                Cell(sb, r.Open("CAT III"), "");
                Cell(sb, r.Count(XccdfResult.Pass), "");
                Cell(sb, r.Count(XccdfResult.NotApplicable), "");
                Cell(sb, r.Count(XccdfResult.NotChecked) + r.Count(XccdfResult.Informational), "");
                Cell(sb, r.Count(XccdfResult.Error) + r.Count(XccdfResult.Unknown), "");
                sb.Append("<td class=\"links\">");
                foreach (var kv in r.Files)
                    sb.Append("<a href=\"").Append(HtmlReport.E(Relative(folder, kv.Value))).Append("\">").Append(HtmlReport.E(kv.Key)).Append("</a> ");
                sb.AppendLine("</td></tr>");
            }
            sb.AppendLine("</tbody></table></main>");
            sb.AppendLine("<footer class=\"wrap muted\">Scores use the XCCDF default model. Results come from each benchmark's own automated SCAP checks.</footer>");
            sb.AppendLine("</body></html>");
            return sb.ToString();
        }

        static void Tile(StringBuilder sb, string cls, int n, string label)
        {
            sb.Append("<div class=\"tile ").Append(cls).Append("\"><div class=\"n\">").Append(n).Append("</div><div class=\"l\">").Append(HtmlReport.E(label)).AppendLine("</div></div>");
        }

        static void Cell(StringBuilder sb, int n, string cls)
        {
            sb.Append("<td class=\"num").Append(n > 0 && cls.Length > 0 ? " " + cls : "").Append("\">").Append(n).Append("</td>");
        }

        static string Relative(string folder, string file)
        {
            string full = Path.GetFullPath(file);
            return full.StartsWith(folder + Path.DirectorySeparatorChar, System.StringComparison.OrdinalIgnoreCase)
                ? full.Substring(folder.Length + 1).Replace('\\', '/') : new System.Uri(full).AbsoluteUri;
        }

        const string Extra = @"
table.sum{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:24px}
.sum th,.sum td{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.sum th{color:var(--muted);font-weight:600;font-size:12px}
.sum td.num{text-align:right;font-variant-numeric:tabular-nums}.sum td.fail{color:var(--fail);font-weight:700}
.bar{height:6px;background:var(--panel2);border-radius:3px;margin-bottom:4px;min-width:80px}.bar span{display:block;height:6px;background:var(--accent);border-radius:3px}
.links a{color:var(--accent);margin-right:8px;white-space:nowrap}@media (max-width:900px){.sum{display:block;overflow-x:auto}}";
    }
}
