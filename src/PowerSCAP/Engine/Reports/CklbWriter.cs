using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Web.Script.Serialization;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Engine.Reports
{
    /// <summary>STIG Viewer 3 checklist (.cklb, JSON), with the fields and status values SCC writes.</summary>
    public static class CklbWriter
    {
        public static void Write(IList<BenchmarkReport> reports, string path)
        {
            File.WriteAllText(path, Render(reports), new UTF8Encoding(false));
        }

        public static string Render(IList<BenchmarkReport> reports)
        {
            var first = reports.First();
            var target = first.Target ?? new TargetInfo();
            string ip = target.Addresses.FirstOrDefault() ?? "";
            var doc = new Dictionary<string, object>();
            doc["title"] = "PowerSCAP Generated CKLB at: " + first.End.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);
            doc["id"] = Uuid();
            doc["active"] = false;
            doc["mode"] = 1;
            doc["has_path"] = true;
            doc["target_data"] = new Dictionary<string, object>
            {
                { "target_type", "Computing" },
                { "host_name", target.HostName ?? "" },
                { "ip_address", ip },
                { "mac_address", MacOf(ip) },
                { "fqdn", target.Fqdn ?? "" },
                { "comments", "" },
                { "role", "Workstation" },
                { "is_web_database", false },
                { "technology_area", "" },
                { "web_db_site", "" },
                { "web_db_instance", "" },
                { "classification", null }
            };
            doc["stigs"] = reports.Select(Stig).ToList();
            doc["cklb_version"] = "1.0";
            return new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize(doc);
        }

        static Dictionary<string, object> Stig(BenchmarkReport r)
        {
            string stigUuid = Uuid();
            var s = new Dictionary<string, object>();
            s["stig_name"] = r.StigName ?? r.Title;
            s["display_name"] = r.Rules.Select(x => x.DpmsTarget).FirstOrDefault(x => !string.IsNullOrEmpty(x)) ?? r.StigName;
            s["stig_id"] = r.StigId;
            s["release_info"] = r.StigReleaseInfo ?? r.ReleaseInfo ?? "";
            s["version"] = r.StigVersion ?? "";
            s["uuid"] = stigUuid;
            s["reference_identifier"] = r.Rules.Select(x => x.DpmsIdentifier).FirstOrDefault(x => !string.IsNullOrEmpty(x)) ?? "";
            s["size"] = r.Rules.Count;
            s["classification"] = r.Classification ?? "UNCLASSIFIED";
            s["rules"] = r.Rules.Select(x => Rule(x, r, stigUuid)).ToList();
            return s;
        }

        static Dictionary<string, object> Rule(RuleReport x, BenchmarkReport r, string stigUuid)
        {
            string ruleId = x.RuleId ?? "";
            int sv = ruleId.IndexOf("SV-", StringComparison.Ordinal);
            string ruleIdSrc = sv >= 0 ? ruleId.Substring(sv) : ruleId;
            string shortId = ruleIdSrc.EndsWith("_rule", StringComparison.Ordinal) ? ruleIdSrc.Substring(0, ruleIdSrc.Length - 5) : ruleIdSrc;
            var d = new Dictionary<string, object>();
            d["uuid"] = Uuid();
            d["stig_uuid"] = stigUuid;
            d["target_key"] = null;
            d["stig_ref"] = null;
            d["group_id"] = x.GroupId ?? "";
            d["group_id_src"] = x.GroupId ?? "";
            d["rule_id"] = shortId;
            d["rule_id_src"] = ruleIdSrc;
            d["weight"] = x.Weight.ToString("0.0", CultureInfo.InvariantCulture);
            d["classification"] = Title(r.Classification ?? "UNCLASSIFIED");
            d["severity"] = x.Severity;
            d["rule_version"] = x.StigId ?? "";
            d["group_title"] = x.GroupTitle ?? "";
            d["rule_title"] = x.Title ?? "";
            d["fix_text"] = x.FixText ?? "";
            d["false_positives"] = Tag(x, "FalsePositives");
            d["false_negatives"] = Tag(x, "FalseNegatives");
            d["discussion"] = x.Discussion ?? "";
            d["check_content"] = x.CheckText ?? "";
            d["documentable"] = Tag(x, "Documentable");
            d["mitigations"] = Tag(x, "Mitigations");
            d["potential_impacts"] = Tag(x, "PotentialImpacts");
            d["third_party_tools"] = Tag(x, "ThirdPartyTools");
            d["mitigation_control"] = Tag(x, "MitigationControl");
            d["responsibility"] = Tag(x, "Responsibility");
            d["security_override_guidance"] = Tag(x, "SeverityOverrideGuidance");
            d["ia_controls"] = Tag(x, "IAControls");
            d["check_content_ref"] = new Dictionary<string, object> { { "href", x.CheckHref ?? "" }, { "name", x.CheckName ?? "" } };
            d["legacy_ids"] = x.LegacyIds.ToList();
            d["ccis"] = x.Ccis.ToList();
            d["group_tree"] = new List<object>
            {
                new Dictionary<string, object> { { "id", x.GroupId ?? "" }, { "title", x.GroupTitle ?? "" }, { "description", "<GroupDescription></GroupDescription>" } }
            };
            d["reference_identifier"] = x.DpmsIdentifier ?? "";
            d["createdAt"] = r.End.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
            d["updatedAt"] = d["createdAt"];
            d["STIGUuid"] = stigUuid;
            d["status"] = Status(x.Result);
            d["overrides"] = new Dictionary<string, object>();
            d["comments"] = "";
            d["finding_details"] = "Tool: PowerSCAP " + EngineInfo.Version + "\nTime: " + r.End.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture) +
                "\nSource: " + x.Source + "\nResult: " + x.ResultText + "\n\n" + (x.Details ?? "").Replace("\r\n", "\n");
            return d;
        }

        /// <summary>XCCDF result → STIG Viewer status (as SCC maps them).</summary>
        public static string Status(XccdfResult r)
        {
            switch (r)
            {
                case XccdfResult.Pass: return "not_a_finding";
                case XccdfResult.Fail: return "open";
                case XccdfResult.NotApplicable: return "not_applicable";
                default: return "not_reviewed";
            }
        }

        static string Tag(RuleReport x, string name)
        {
            string v;
            return x.DescriptionTags.TryGetValue(name, out v) ? v : "";
        }

        static string Title(string s)
        {
            return string.IsNullOrEmpty(s) ? s : char.ToUpperInvariant(s[0]) + s.Substring(1).ToLowerInvariant();
        }

        static string Uuid() { return Guid.NewGuid().ToString().ToUpperInvariant(); }

        static string MacOf(string ip)
        {
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                    if (nic.GetIPProperties().UnicastAddresses.Any(a => a.Address.ToString() == ip))
                        return string.Join(":", nic.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
            }
            catch (NetworkInformationException) { }
            return "";
        }
    }
}
