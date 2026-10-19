using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Engine.Reports
{
    /// <summary>
    /// SCC-style HTML reports: All-Settings (every rule) and Non-Compliance (fail, error, unknown). One static,
    /// self-contained, well-formed file per report; it opens in the user's browser, never inside the scanner.
    /// </summary>
    public static class HtmlReport
    {
        public static void Write(BenchmarkReport r, string path, bool nonComplianceOnly)
        {
            File.WriteAllText(path, Render(r, nonComplianceOnly), new UTF8Encoding(false));
        }

        public static string Render(BenchmarkReport r, bool nonComplianceOnly)
        {
            var rules = nonComplianceOnly ? r.Rules.Where(x => x.IsNonCompliant).ToList() : r.Rules;
            string kind = nonComplianceOnly ? "Non-Compliance" : "All Settings";
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\">");
            sb.AppendLine("<head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>");
            sb.Append("<title>").Append(E(kind + " - " + (r.StigName ?? r.Title) + " - " + Host(r))).AppendLine("</title>");
            sb.Append("<style>").Append(Css).AppendLine("</style></head>");
            sb.AppendLine("<body>");

            // Header
            sb.AppendLine("<header class=\"top\"><div class=\"wrap\">");
            if (r.OutsideScap) kind = "Outside-SCAP evaluation";
            sb.Append("<div class=\"eyebrow\">PowerSCAP ").Append(E(EngineInfo.Version)).Append(" &#183; ").Append(E(kind)).AppendLine(" report</div>");
            sb.Append("<h1>").Append(E(r.StigName ?? r.Title)).AppendLine("</h1>");
            sb.Append("<div class=\"sub\">").Append(E(r.Title)).Append(" &#183; version ").Append(E(r.Version))
              .Append(string.IsNullOrEmpty(r.ReleaseInfo) ? "" : " &#183; " + E(r.ReleaseInfo)).AppendLine("</div>");
            sb.Append("<div class=\"sub\">Host <b>").Append(E(Host(r))).Append("</b> &#183; scanned ")
              .Append(E(r.Start.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).Append(" &#183; profile ")
              .Append(E(r.ProfileTitle ?? r.ProfileId ?? "(default)")).AppendLine("</div>");
            sb.AppendLine("<button type=\"button\" class=\"theme\" id=\"theme\" title=\"Switch light/dark\">&#9680;</button>");
            sb.AppendLine("</div></header>");

            sb.AppendLine("<main class=\"wrap\">");
            if (r.OutsideScap)
                sb.AppendLine("<p class=\"outside\"><b>Not a SCAP result.</b> This benchmark's own platform checks rule this machine out, so a SCAP " +
                    "scan reports every rule Not Applicable (as SCC does). Here its checks were evaluated anyway, to show which of its settings " +
                    "are in place. Use it as guidance only: it is not a compliance result, and it is not in any checklist, score or history.</p>");
            Tiles(sb, r);
            Info(sb, r);

            // Toolbar
            sb.AppendLine("<section class=\"toolbar\">");
            sb.AppendLine("<input type=\"search\" id=\"q\" placeholder=\"Filter by ID, title or text\" aria-label=\"Filter rules\"/>");
            sb.AppendLine("<div class=\"chips\" id=\"chips\">");
            foreach (var chip in new[] { "all", "fail", "pass", "error", "unknown", "notapplicable", "notchecked" })
            {
                if (nonComplianceOnly && (chip == "pass" || chip == "notapplicable" || chip == "notchecked")) continue;
                sb.Append("<button type=\"button\" data-f=\"").Append(chip).Append("\"").Append(chip == "all" ? " class=\"on\"" : "").Append(">")
                  .Append(E(ChipLabel(chip))).AppendLine("</button>");
            }
            sb.AppendLine("</div>");
            sb.AppendLine("<button type=\"button\" id=\"expand\">Expand all</button>");
            sb.AppendLine("</section>");

            if (rules.Count == 0) sb.AppendLine("<p class=\"empty\">No findings. Every evaluated rule passed or does not apply.</p>");
            foreach (var cat in new[] { "CAT I", "CAT II", "CAT III", "Unknown" })
            {
                var group = rules.Where(x => x.Cat == cat).ToList();
                if (group.Count == 0) continue;
                sb.Append("<section class=\"cat\"><h2>").Append(E(cat)).Append(" <span class=\"muted\">").Append(group.Count)
                  .Append(group.Count == 1 ? " rule" : " rules").AppendLine("</span></h2>");
                foreach (var rule in group) Rule(sb, rule);
                sb.AppendLine("</section>");
            }
            BeyondScap(sb, r, nonComplianceOnly);
            sb.AppendLine("</main>");
            sb.Append("<footer class=\"wrap muted\">Generated by PowerSCAP ").Append(E(EngineInfo.Version)).Append(" from ")
              .Append(E(Path.GetFileName(r.ContentFile ?? ""))).Append(". Results labeled SCAP come from the benchmark's own automated checks.</footer>");
            sb.Append("<script>//<![CDATA[\n").Append(Script).AppendLine("\n//]]></script>");
            sb.AppendLine("</body></html>");
            return sb.ToString();
        }

        static string Host(BenchmarkReport r) { return r.Target == null ? "" : r.Target.HostName; }

        static void Tiles(StringBuilder sb, BenchmarkReport r)
        {
            sb.AppendLine("<section class=\"tiles\">");
            sb.Append("<div class=\"tile score\"><div class=\"n\">").Append(r.DefaultScore.ToString("0.0", CultureInfo.InvariantCulture))
              .AppendLine("%</div><div class=\"l\">Score (default model)</div></div>");
            Tile(sb, "fail", r.Count(XccdfResult.Fail), "Open findings");
            Tile(sb, "pass", r.Count(XccdfResult.Pass), "Not a finding");
            Tile(sb, "error", r.Count(XccdfResult.Error) + r.Count(XccdfResult.Unknown), "Error / unknown");
            Tile(sb, "notapplicable", r.Count(XccdfResult.NotApplicable), "Not applicable");
            Tile(sb, "notchecked", r.Count(XccdfResult.NotChecked) + r.Count(XccdfResult.Informational), "Not reviewed");
            if (r.Rules.Any(x => x.IsManual))
                sb.Append("<div class=\"tile complete\"><div class=\"n\">").Append(r.Completeness.ToString("0.0", CultureInfo.InvariantCulture))
                  .AppendLine("%</div><div class=\"l\">STIG completeness (with PowerSCAP checks and answers)</div></div>");
            sb.AppendLine("<div class=\"tile cats\">");
            foreach (var cat in new[] { "CAT I", "CAT II", "CAT III" })
                sb.Append("<div><span class=\"n\">").Append(r.Open(cat)).Append("</span> <span class=\"l\">").Append(cat).AppendLine(" open</span></div>");
            sb.AppendLine("</div></section>");
        }

        static void Tile(StringBuilder sb, string cls, int n, string label)
        {
            sb.Append("<div class=\"tile ").Append(cls).Append("\"><div class=\"n\">").Append(n).Append("</div><div class=\"l\">").Append(E(label)).AppendLine("</div></div>");
        }

        static void Info(StringBuilder sb, BenchmarkReport r)
        {
            sb.AppendLine("<section class=\"info\">");
            sb.AppendLine("<div><h3>Target</h3><dl>");
            if (r.Target != null)
            {
                Dt(sb, "Host", r.Target.HostName);
                Dt(sb, "FQDN", r.Target.Fqdn);
                Dt(sb, "Operating system", (r.Target.OsName ?? "") + " " + (r.Target.OsVersion ?? ""));
                Dt(sb, "Addresses", string.Join(", ", r.Target.Addresses));
                Dt(sb, "Scanned as", r.Target.Identity + (r.Target.Privileged ? " (administrator)" : " (not elevated: some checks could not run)"));
            }
            sb.AppendLine("</dl></div>");
            sb.AppendLine("<div><h3>Content</h3><dl>");
            Dt(sb, "Benchmark", r.BenchmarkId);
            Dt(sb, "STIG", (r.StigId ?? "") + (string.IsNullOrEmpty(r.StigReleaseInfo) ? "" : " - " + r.StigReleaseInfo));
            Dt(sb, "File", Path.GetFileName(r.ContentFile ?? ""));
            if (!string.IsNullOrEmpty(r.Signature)) Dt(sb, "Signature", r.Signature);
            Dt(sb, "Duration", ((int)(r.End - r.Start).TotalSeconds).ToString(CultureInfo.InvariantCulture) + " s");
            foreach (var s in r.Scores)
                Dt(sb, "Score " + s.System.Replace("urn:xccdf:scoring:", ""), s.Value.ToString("0.00", CultureInfo.InvariantCulture) + " / " + s.Maximum.ToString("0.00", CultureInfo.InvariantCulture));
            sb.AppendLine("</dl></div></section>");
        }

        static void Dt(StringBuilder sb, string k, string v)
        {
            sb.Append("<dt>").Append(E(k)).Append("</dt><dd>").Append(E(v)).AppendLine("</dd>");
        }

        static void Rule(StringBuilder sb, RuleReport rule)
        {
            string res = rule.ResultText;
            string search = (rule.GroupId + " " + rule.RuleId + " " + rule.StigId + " " + rule.Title + " " + string.Join(" ", rule.Ccis)).ToLowerInvariant();
            sb.Append("<details class=\"rule\" data-r=\"").Append(E(res)).Append("\" data-s=\"").Append(E(search)).AppendLine("\">");
            sb.Append("<summary><span class=\"badge ").Append(E(res)).Append("\">").Append(E(Label(rule.Result))).Append("</span>")
              .Append("<span class=\"vid\">").Append(E(rule.GroupId)).Append("</span>")
              .Append("<span class=\"sid\">").Append(E(rule.StigId)).Append("</span>")
              .Append("<span class=\"ttl\">").Append(E(rule.Title)).Append("</span>")
              .Append("<span class=\"src\">").Append(E(rule.Source)).AppendLine("</span></summary>");
            sb.AppendLine("<div class=\"body\">");
            sb.Append("<div class=\"ids\"><span>Rule ").Append(E(rule.RuleId)).Append("</span><span>").Append(E(rule.Cat)).Append(" (").Append(E(rule.Severity))
              .Append(")</span><span>").Append(E(string.Join(", ", rule.Ccis))).AppendLine("</span></div>");
            Block(sb, "Discussion", rule.Discussion);
            Block(sb, "Check", rule.CheckText);
            Block(sb, "Fix", rule.FixText);
            if (!string.IsNullOrEmpty(rule.Details))
                sb.Append("<h4>Evaluation (expected vs. actual)</h4><pre>").Append(E(rule.Details)).AppendLine("</pre>");
            sb.AppendLine("</div></details>");
        }

        /// <summary>
        /// The manual rules with what PowerSCAP's checks found and what reviewers answered (design layers 2 and 3), kept
        /// apart from the SCAP results above, which they never change.
        /// </summary>
        static void BeyondScap(StringBuilder sb, BenchmarkReport r, bool nonComplianceOnly)
        {
            var manual = r.Rules.Where(x => x.IsManual).ToList();
            if (nonComplianceOnly) manual = manual.Where(x => x.EffectiveResult == XccdfResult.Fail).ToList();
            if (manual.Count == 0) return;
            sb.Append("<section class=\"cat beyond\"><h2>Beyond SCAP <span class=\"muted\">").Append(manual.Count)
              .Append(manual.Count == 1 ? " manual rule" : " manual rules").AppendLine("</span></h2>");
            sb.AppendLine("<p class=\"muted\">The content leaves these rules to a reviewer. PowerSCAP's own checks and recorded answers are shown here; they do not change the SCAP results or scores.</p>");
            foreach (var rule in manual)
            {
                var v = rule.Review;
                string res = ResultsWriter.ResultText(rule.EffectiveResult);
                string search = (rule.GroupId + " " + rule.RuleId + " " + rule.StigId + " " + rule.Title + " " + string.Join(" ", rule.Ccis)).ToLowerInvariant();
                string source = v == null ? "Not reviewed" : v.NeedsReReview ? "Needs re-review" : v.IsDecided ? v.Label : "Evidence only";
                sb.Append("<details class=\"rule\" data-r=\"").Append(E(res)).Append("\" data-s=\"").Append(E(search)).AppendLine("\">");
                sb.Append("<summary><span class=\"badge ").Append(E(res)).Append("\">").Append(E(RuleReview.StatusName(rule.EffectiveResult))).Append("</span>")
                  .Append("<span class=\"vid\">").Append(E(rule.GroupId)).Append("</span>")
                  .Append("<span class=\"sid\">").Append(E(rule.StigId)).Append("</span>")
                  .Append("<span class=\"ttl\">").Append(E(rule.Title)).Append("</span>")
                  .Append("<span class=\"src\">").Append(E(source)).AppendLine("</span></summary>");
                sb.AppendLine("<div class=\"body\">");
                sb.Append("<div class=\"ids\"><span>Rule ").Append(E(rule.RuleId)).Append("</span><span>").Append(E(rule.Cat))
                  .Append("</span><span>SCAP result: ").Append(E(rule.ResultText)).AppendLine("</span></div>");
                if (v != null && v.NeedsReReview)
                    sb.AppendLine("<p class=\"warn\">This rule changed since it was answered. Review it again; the earlier answer is not applied.</p>");
                if (v != null && !string.IsNullOrEmpty(v.Evidence))
                    sb.Append("<h4>What PowerSCAP found</h4><pre>").Append(E(v.Evidence)).AppendLine("</pre>");
                if (v != null && v.Source == RuleReview.Answer)
                {
                    sb.Append("<h4>").Append(E(v.Label)).Append("</h4>");
                    Block(sb, "Comment", v.Comment);
                }
                Block(sb, "Question", rule.Question ?? rule.CheckText);
                Block(sb, "Fix", rule.FixText);
                sb.AppendLine("</div></details>");
            }
            sb.AppendLine("</section>");
        }

        static void Block(StringBuilder sb, string title, string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            sb.Append("<h4>").Append(E(title)).Append("</h4><p class=\"txt\">").Append(E(text.Trim())).AppendLine("</p>");
        }

        public static string Label(XccdfResult r)
        {
            switch (r)
            {
                case XccdfResult.Pass: return "Pass";
                case XccdfResult.Fail: return "Fail";
                case XccdfResult.Error: return "Error";
                case XccdfResult.Unknown: return "Unknown";
                case XccdfResult.NotApplicable: return "N/A";
                case XccdfResult.NotChecked: return "Not checked";
                case XccdfResult.Informational: return "Info";
                default: return r.ToString();
            }
        }

        static string ChipLabel(string chip)
        {
            switch (chip)
            {
                case "all": return "All";
                case "fail": return "Fail";
                case "pass": return "Pass";
                case "error": return "Error";
                case "unknown": return "Unknown";
                case "notapplicable": return "N/A";
                default: return "Not checked";
            }
        }

        /// <summary>HTML-encodes text from content and collected values (never trusted).</summary>
        /// <summary>
        /// HTML-encodes text. Characters XML 1.0 cannot carry (NUL and other controls in collected registry or console
        /// values) become '?', so the page stays well-formed XHTML.
        /// </summary>
        public static string E(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(s.Length);
            foreach (char c in s) sb.Append(System.Xml.XmlConvert.IsXmlChar(c) ? c : '?');
            return WebUtility.HtmlEncode(sb.ToString());
        }

        internal const string Css = @"
:root{--bg:#0e1116;--panel:#161b22;--panel2:#1c2330;--line:#2a3240;--text:#e6edf3;--muted:#8b97a7;--accent:#2dd4bf;
--pass:#3fb950;--fail:#f85149;--warn:#d29922;--na:#6e7681;--info:#58a6ff;color-scheme:dark}
@media (prefers-color-scheme: light){:root:not([data-theme=dark]){--bg:#f6f8fa;--panel:#fff;--panel2:#f0f3f6;--line:#d0d7de;--text:#1f2328;
--muted:#59636e;--accent:#0f766e;--pass:#1a7f37;--fail:#cf222e;--warn:#9a6700;--na:#6e7781;--info:#0969da;color-scheme:light}}
:root[data-theme=light]{--bg:#f6f8fa;--panel:#fff;--panel2:#f0f3f6;--line:#d0d7de;--text:#1f2328;--muted:#59636e;--accent:#0f766e;
--pass:#1a7f37;--fail:#cf222e;--warn:#9a6700;--na:#6e7781;--info:#0969da;color-scheme:light}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 'Segoe UI',system-ui,sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:0 16px}.top{background:var(--panel);border-bottom:1px solid var(--line);padding:20px 0;position:relative}
.top .wrap{position:relative}.eyebrow{color:var(--accent);font-size:12px;letter-spacing:.08em;text-transform:uppercase;font-weight:600}
h1{margin:4px 0 6px;font-size:24px}.sub{color:var(--muted)}.sub b{color:var(--text)}
.theme{position:absolute;right:16px;top:0;background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:8px;width:36px;height:36px;cursor:pointer;font-size:18px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;border-top:3px solid var(--na)}
.tile .n{font-size:26px;font-weight:700}.tile .l{color:var(--muted);font-size:12px}.tile.score{border-top-color:var(--accent)}
.tile.pass{border-top-color:var(--pass)}.tile.fail{border-top-color:var(--fail)}.tile.error{border-top-color:var(--warn)}.tile.notchecked{border-top-color:var(--info)}
.tile.cats{border-top-color:var(--fail)}.tile.cats .n{font-size:18px}.tile.complete{border-top-color:var(--accent)}
.beyond{border-top:2px dashed var(--line);padding-top:8px}.outside{border:1px solid var(--warn);border-radius:10px;padding:12px 16px;margin:20px 0 0;background:var(--panel)}.warn{color:var(--warn);font-weight:600}
.info{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px;margin-bottom:20px}
.info>div{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}.info h3{margin:0 0 8px;font-size:14px;color:var(--accent)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:0}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;position:sticky;top:0;background:var(--bg);padding:10px 0;z-index:2}
.toolbar input{flex:1 1 260px;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font:inherit}
.chips{display:flex;flex-wrap:wrap;gap:6px}.toolbar button{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:999px;padding:6px 12px;cursor:pointer;font:inherit}
.toolbar button.on{background:var(--accent);color:#04201c;border-color:var(--accent)}
h2{font-size:16px;margin:24px 0 8px}.muted{color:var(--muted);font-weight:400}
.rule{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:6px 0}
.rule summary{display:flex;gap:10px;align-items:center;padding:9px 12px;cursor:pointer;list-style:none}.rule summary::-webkit-details-marker{display:none}
.badge{min-width:86px;text-align:center;font-size:12px;font-weight:700;border-radius:999px;padding:2px 8px;border:1px solid}
.badge.pass{color:var(--pass);border-color:var(--pass)}.badge.fail{color:var(--fail);border-color:var(--fail)}.badge.error,.badge.unknown{color:var(--warn);border-color:var(--warn)}
.badge.notapplicable{color:var(--na);border-color:var(--na)}.badge.notchecked,.badge.informational{color:var(--info);border-color:var(--info)}
.vid{font-family:Consolas,monospace;color:var(--muted);min-width:78px}.sid{font-family:Consolas,monospace;color:var(--muted);min-width:130px}
.ttl{flex:1}.src{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:4px;padding:0 5px}
.body{padding:4px 16px 14px;border-top:1px solid var(--line)}.ids{display:flex;flex-wrap:wrap;gap:14px;color:var(--muted);font-size:12px;margin:8px 0}
h4{margin:12px 0 4px;font-size:13px;color:var(--accent)}.txt{white-space:pre-wrap;margin:0}
pre{background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto;font:12px/1.45 Consolas,monospace;max-height:520px}
.empty{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px}footer{padding:24px 16px;font-size:12px}
.hidden{display:none}@media (max-width:640px){.sid{display:none}.vid{min-width:0}.badge{min-width:0}}
@media print{.toolbar,.theme{display:none}.rule{break-inside:avoid}}";

        const string Script = @"(function(){
var root=document.documentElement,key='powerscap-theme';
try{var t=localStorage.getItem(key);if(t){root.setAttribute('data-theme',t);}}catch(e){}
document.getElementById('theme').addEventListener('click',function(){
 var dark=root.getAttribute('data-theme')?root.getAttribute('data-theme')==='dark':!window.matchMedia('(prefers-color-scheme: light)').matches;
 var next=dark?'light':'dark';root.setAttribute('data-theme',next);try{localStorage.setItem(key,next);}catch(e){}});
var q=document.getElementById('q'),f='all',rules=[].slice.call(document.querySelectorAll('.rule'));
function apply(){var s=q.value.toLowerCase();rules.forEach(function(r){
 var ok=(f==='all'||r.getAttribute('data-r')===f)&&(!s||r.getAttribute('data-s').indexOf(s)>=0||r.textContent.toLowerCase().indexOf(s)>=0);
 r.classList.toggle('hidden',!ok);});
 [].forEach.call(document.querySelectorAll('.cat'),function(c){c.classList.toggle('hidden',!c.querySelector('.rule:not(.hidden)'));});}
q.addEventListener('input',apply);
[].forEach.call(document.querySelectorAll('#chips button'),function(b){b.addEventListener('click',function(){
 f=b.getAttribute('data-f');[].forEach.call(document.querySelectorAll('#chips button'),function(x){x.classList.toggle('on',x===b);});apply();});});
var ex=document.getElementById('expand');ex.addEventListener('click',function(){var open=ex.textContent==='Expand all';
 rules.forEach(function(r){if(!r.classList.contains('hidden'))r.open=open;});ex.textContent=open?'Collapse all':'Expand all';});
})();";
    }
}
