using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Xml;
using Microsoft.Win32;
using PowerScap.Engine.Content;

namespace PowerScap.Engine.Xccdf
{
    public class TargetInfo
    {
        public string HostName { get; set; }
        public string Fqdn { get; set; }
        public List<string> Addresses { get; set; }
        public string OsName { get; set; }
        public string OsVersion { get; set; }
        public string Identity { get; set; }
        public bool Privileged { get; set; }

        public TargetInfo() { Addresses = new List<string>(); }

        public static TargetInfo Collect()
        {
            var t = new TargetInfo();
            t.HostName = Environment.MachineName;
            try { t.Fqdn = Dns.GetHostEntry(string.Empty).HostName; } catch (Exception) { t.Fqdn = t.HostName; }
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
                foreach (var a in nic.GetIPProperties().UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork))
                    t.Addresses.Add(a.Address.ToString());
            using (var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                if (k != null)
                {
                    t.OsName = k.GetValue("ProductName") as string;
                    t.OsVersion = (k.GetValue("DisplayVersion") as string) ?? (k.GetValue("ReleaseId") as string);
                    int build;
                    if (int.TryParse(k.GetValue("CurrentBuildNumber") as string, out build) && build >= 22000 && t.OsName != null)
                        t.OsName = t.OsName.Replace("Windows 10", "Windows 11");
                }
            }
            var id = WindowsIdentity.GetCurrent();
            t.Identity = id.Name;
            t.Privileged = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            return t;
        }
    }

    /// <summary>Writes an XCCDF 1.2 results document: a copy of the benchmark with one TestResult appended.</summary>
    public static class ResultsWriter
    {
        public static void WriteXccdf(ScapContent content, ResolvedProfile profile, List<RuleResult> results, List<Score> scores,
            TargetInfo target, string path)
        {
            WriteXccdf(content, profile, results, scores, target, path, DateTime.Now, DateTime.Now);
        }

        public static void WriteXccdf(ScapContent content, ResolvedProfile profile, List<RuleResult> results, List<Score> scores,
            TargetInfo target, string path, DateTime start, DateTime end)
        {
            WriteXccdf(content, profile, results, scores, target, path, start, end, null);
        }

        /// <summary>Remarks become TestResult remark elements (e.g. an operator's signature override).</summary>
        public static void WriteXccdf(ScapContent content, ResolvedProfile profile, List<RuleResult> results, List<Score> scores,
            TargetInfo target, string path, DateTime start, DateTime end, IEnumerable<string> remarks)
        {
            var doc = new XmlDocument();
            doc.AppendChild(doc.CreateXmlDeclaration("1.0", "UTF-8", null));
            XmlElement benchmark = (XmlElement)doc.ImportNode(content.Benchmark.DocumentElement, true);
            doc.AppendChild(benchmark);
            string ns = benchmark.NamespaceURI;
            Func<string, XmlElement> el = name => doc.CreateElement(name, ns);

            XmlElement tr = el("TestResult");
            string shortProfile = string.IsNullOrEmpty(profile.ProfileId) ? "default" : profile.ProfileId;
            tr.SetAttribute("id", "xccdf_powerscap_testresult_" + Sanitize(shortProfile));
            tr.SetAttribute("start-time", start.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture));
            tr.SetAttribute("end-time", end.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture));
            tr.SetAttribute("test-system", "cpe:/a:powerscap:powerscap:" + EngineInfo.Version);
            tr.SetAttribute("version", "1.0");

            Text(tr, el("title"), "PowerSCAP scan of " + target.HostName);
            if (remarks != null) foreach (var r in remarks) Text(tr, el("remark"), r);
            XmlElement identity = el("identity");
            identity.SetAttribute("authenticated", "true");
            identity.SetAttribute("privileged", target.Privileged ? "true" : "false");
            Text(tr, identity, target.Identity);
            if (!string.IsNullOrEmpty(profile.ProfileId))
            {
                XmlElement p = el("profile");
                p.SetAttribute("idref", profile.ProfileId);
                tr.AppendChild(p);
            }
            Text(tr, el("target"), target.HostName);
            foreach (var a in target.Addresses) Text(tr, el("target-address"), a);
            XmlElement facts = el("target-facts");
            Fact(facts, el, "urn:xccdf:fact:asset:identifier:fqdn", target.Fqdn);
            Fact(facts, el, "urn:xccdf:fact:asset:identifier:host_name", target.HostName);
            if (target.OsName != null) Fact(facts, el, "urn:xccdf:fact:asset:identifier:os_name", target.OsName);
            if (target.OsVersion != null) Fact(facts, el, "urn:xccdf:fact:asset:identifier:os_version", target.OsVersion);
            tr.AppendChild(facts);

            foreach (var v in profile.Values)
            {
                XmlElement sv = el("set-value");
                sv.SetAttribute("idref", v.Key);
                Text(tr, sv, v.Value);
            }

            foreach (var r in results.Where(x => x.Result != XccdfResult.NotSelected))
            {
                XmlElement rr = el("rule-result");
                rr.SetAttribute("idref", r.Rule.RuleId);
                rr.SetAttribute("role", r.Rule.Role);
                rr.SetAttribute("time", end.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture));
                rr.SetAttribute("severity", r.Rule.Severity);
                rr.SetAttribute("weight", r.Rule.Weight.ToString("0.0#####", CultureInfo.InvariantCulture));
                Text(rr, el("result"), ResultText(r.Result));
                foreach (XmlElement ident in r.Rule.RuleElement.ChildNodes.OfType<XmlElement>().Where(e => e.LocalName == "ident"))
                    rr.AppendChild(doc.ImportNode(ident, true));
                if (r.CheckSystem != null)
                {
                    XmlElement check = el("check");
                    check.SetAttribute("system", r.CheckSystem);
                    if (r.CheckHref != null)
                    {
                        XmlElement cref = el("check-content-ref");
                        cref.SetAttribute("href", r.CheckHref);
                        if (!string.IsNullOrEmpty(r.CheckName)) cref.SetAttribute("name", r.CheckName);
                        check.AppendChild(cref);
                    }
                    rr.AppendChild(check);
                }
                if (!string.IsNullOrEmpty(r.Message))
                {
                    XmlElement msg = el("message");
                    msg.SetAttribute("severity", "info");
                    Text(rr, msg, r.Message);
                }
                tr.AppendChild(rr);
            }

            foreach (var s in scores)
            {
                XmlElement score = el("score");
                score.SetAttribute("system", s.System);
                score.SetAttribute("maximum", s.Maximum.ToString("R", CultureInfo.InvariantCulture));
                Text(tr, score, s.Value.ToString("R", CultureInfo.InvariantCulture));
            }

            // TestResult follows all Rules/Groups but precedes an enveloped signature, if any.
            XmlNode signature = benchmark.ChildNodes.OfType<XmlElement>().FirstOrDefault(e => e.LocalName == "signature" || e.LocalName == "Signature");
            if (signature != null) benchmark.InsertBefore(tr, signature);
            else benchmark.AppendChild(tr);

            var settings = new XmlWriterSettings { Indent = true, Encoding = new System.Text.UTF8Encoding(false) };
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path)));
            using (var w = XmlWriter.Create(path, settings)) doc.Save(w);
        }

        public static string ResultText(XccdfResult r)
        {
            switch (r)
            {
                case XccdfResult.Pass: return "pass";
                case XccdfResult.Fail: return "fail";
                case XccdfResult.Error: return "error";
                case XccdfResult.Unknown: return "unknown";
                case XccdfResult.NotApplicable: return "notapplicable";
                case XccdfResult.NotChecked: return "notchecked";
                case XccdfResult.NotSelected: return "notselected";
                case XccdfResult.Informational: return "informational";
                default: return "fixed";
            }
        }

        static void Text(XmlElement parent, XmlElement child, string text)
        {
            child.InnerText = text ?? string.Empty;
            parent.AppendChild(child);
        }

        static void Fact(XmlElement facts, Func<string, XmlElement> el, string name, string value)
        {
            XmlElement f = el("fact");
            f.SetAttribute("name", name);
            f.SetAttribute("type", "string");
            f.InnerText = value ?? string.Empty;
            facts.AppendChild(f);
        }

        static string Sanitize(string id)
        {
            return new string(id.Select(c => char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.' ? c : '_').ToArray());
        }
    }
}
