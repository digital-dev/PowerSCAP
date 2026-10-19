using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Xml;
using PowerScap.Engine.Content;
using PowerScap.Engine.Oval;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Engine.Reports
{
    /// <summary>
    /// OVAL 5.12.3 results documents (full results: definitions, tests with tested items, and the system
    /// characteristics with collected objects and items), one per OVAL check component the scan used. 5.12.3, as SCC
    /// writes: it is a superset of 5.11.2 and the only version that defines some items the content uses
    /// (shellcommand_item, the Windows Update item's installed flag).
    /// </summary>
    public static class OvalResultsWriter
    {
        public const string ResNs = "http://oval.mitre.org/XMLSchema/oval-results-5";
        public const string CommonNs = "http://oval.mitre.org/XMLSchema/oval-common-5";
        public const string ScNs = "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5";
        const string WinScNs = ScNs + "#windows";
        const string IndScNs = ScNs + "#independent";

        static readonly HashSet<string> IndependentItems = new HashSet<string>
        {
            "environmentvariable58_item", "family_item", "filehash58_item", "shellcommand_item", "textfilecontent_item", "variable_item", "xmlfilecontent_item"
        };

        /// <summary>
        /// Each item type's entities in the order the OVAL 5.12.3 system characteristics schema requires
        /// (generated from windows- and independent-system-characteristics-schema.xsd). Entities a type does not
        /// define are left out of the document.
        /// </summary>
        static readonly Dictionary<string, string[]> EntityOrder = new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            { "accesstoken_item", new[] { "security_principle", "seassignprimarytokenprivilege", "seauditprivilege", "sebackupprivilege", "sechangenotifyprivilege", "secreateglobalprivilege", "secreatepagefileprivilege", "secreatepermanentprivilege", "secreatesymboliclinkprivilege", "secreatetokenprivilege", "sedebugprivilege", "seenabledelegationprivilege", "seimpersonateprivilege", "seincreasebasepriorityprivilege", "seincreasequotaprivilege", "seincreaseworkingsetprivilege", "seloaddriverprivilege", "selockmemoryprivilege", "semachineaccountprivilege", "semanagevolumeprivilege", "seprofilesingleprocessprivilege", "serelabelprivilege", "seremoteshutdownprivilege", "serestoreprivilege", "sesecurityprivilege", "seshutdownprivilege", "sesyncagentprivilege", "sesystemenvironmentprivilege", "sesystemprofileprivilege", "sesystemtimeprivilege", "setakeownershipprivilege", "setcbprivilege", "setimezoneprivilege", "seundockprivilege", "seunsolicitedinputprivilege", "sebatchlogonright", "seinteractivelogonright", "senetworklogonright", "seremoteinteractivelogonright", "seservicelogonright", "sedenybatchLogonright", "sedenyinteractivelogonright", "sedenynetworklogonright", "sedenyremoteInteractivelogonright", "sedenyservicelogonright", "setrustedcredmanaccessnameright" } },
            { "auditeventpolicysubcategories_item", new[] { "credential_validation", "kerberos_authentication_service", "kerberos_service_ticket_operations", "kerberos_ticket_events", "other_account_logon_events", "application_group_management", "computer_account_management", "distribution_group_management", "other_account_management_events", "security_group_management", "user_account_management", "dpapi_activity", "process_creation", "process_termination", "rpc_events", "directory_service_access", "directory_service_changes", "directory_service_replication", "detailed_directory_service_replication", "account_lockout", "ipsec_extended_mode", "ipsec_main_mode", "ipsec_quick_mode", "logoff", "logon", "network_policy_server", "other_logon_logoff_events", "special_logon", "logon_claims", "application_generated", "certification_services", "detailed_file_share", "file_share", "file_system", "filtering_platform_connection", "filtering_platform_packet_drop", "handle_manipulation", "kernel_object", "other_object_access_events", "registry", "sam", "removable_storage", "central_access_policy_staging", "audit_policy_change", "authentication_policy_change", "authorization_policy_change", "filtering_platform_policy_change", "mpssvc_rule_level_policy_change", "other_policy_change_events", "non_sensitive_privilege_use", "other_privilege_use_events", "sensitive_privilege_use", "ipsec_driver", "other_system_events", "security_state_change", "security_system_extension", "system_integrity", "group_membership", "pnp_activity", "user_device_claims", "audit_detailedtracking_tokenrightadjusted" } },
            { "cmdlet_item", new[] { "module_name", "module_id", "module_version", "verb", "noun", "parameters", "select", "value" } },
            { "environmentvariable58_item", new[] { "pid", "name", "value" } },
            { "family_item", new[] { "family" } },
            { "file_item", new[] { "filepath", "path", "filename", "owner", "size", "a_time", "c_time", "m_time", "ms_checksum", "version", "type", "attribute", "development_class", "company", "internal_name", "language", "original_filename", "product_name", "product_version", "windows_view" } },
            { "fileeffectiverights_item", new[] { "filepath", "path", "filename", "trustee_sid", "trustee_name", "standard_delete", "standard_read_control", "standard_write_dac", "standard_write_owner", "standard_synchronize", "access_system_security", "generic_read", "generic_write", "generic_execute", "generic_all", "file_read_data", "file_write_data", "file_append_data", "file_read_ea", "file_write_ea", "file_execute", "file_delete_child", "file_read_attributes", "file_write_attributes", "windows_view" } },
            { "filehash58_item", new[] { "filepath", "path", "filename", "hash_type", "hash", "windows_view" } },
            { "group_item", new[] { "group", "user", "subgroup" } },
            { "group_sid_item", new[] { "group_sid", "user_sid", "subgroup_sid", "group", "user", "subgroup" } },
            { "lockoutpolicy_item", new[] { "force_logoff", "lockout_duration", "lockout_observation_window", "lockout_threshold" } },
            { "ntuser_item", new[] { "key", "name", "sid", "username", "account_type", "logged_on", "days_since_last_logon", "user_has_signed_into_explorer", "enabled", "date_modified", "days_since_modified", "filepath", "last_write_time", "type", "value" } },
            { "passwordpolicy_item", new[] { "max_passwd_age", "min_passwd_age", "min_passwd_len", "password_hist_len", "password_complexity", "reversible_encryption", "anonymous_name_lookup" } },
            { "registry_item", new[] { "hive", "key", "name", "last_write_time", "type", "value", "expanded_value", "windows_view" } },
            { "regkeyeffectiverights_item", new[] { "hive", "key", "trustee_sid", "trustee_name", "standard_delete", "standard_read_control", "standard_write_dac", "standard_write_owner", "standard_synchronize", "access_system_security", "generic_read", "generic_write", "generic_execute", "generic_all", "key_query_value", "key_set_value", "key_create_sub_key", "key_enumerate_sub_keys", "key_notify", "key_create_link", "key_wow64_64key", "key_wow64_32key", "key_wow64_res", "windows_view" } },
            { "service_item", new[] { "service_name", "display_name", "description", "service_type", "start_type", "current_state", "controls_accepted", "start_name", "path", "pid", "service_flag", "dependencies" } },
            { "sharedresource_item", new[] { "netname", "shared_type", "max_uses", "current_uses", "local_path", "access_read_permission", "access_write_permission", "access_create_permission", "access_exec_permission", "access_delete_permission", "access_atrib_permission", "access_perm_permission", "access_all_permission" } },
            { "shellcommand_item", new[] { "shell", "command", "pattern", "exit_status", "stdout_line", "subexpression", "stderr_line" } },
            { "sid_item", new[] { "trustee_name", "trustee_sid", "trustee_domain" } },
            { "sid_sid_item", new[] { "trustee_sid", "trustee_name", "trustee_domain" } },
            { "textfilecontent_item", new[] { "filepath", "path", "filename", "pattern", "instance", "line", "text", "subexpression", "windows_view" } },
            { "user_item", new[] { "user", "enabled", "group", "last_logon", "full_name", "comment", "password_age_days", "lockout", "passwd_notreqd", "dont_expire_passwd", "encrypted_text_password_allowed", "not_delegated", "use_des_key_only", "dont_require_preauth", "password_expired", "smartcard_required", "trusted_for_delegation", "trusted_to_authenticate_for_delegation" } },
            { "user_sid_item", new[] { "user_sid", "enabled", "group_sid", "last_logon", "user", "group", "full_name", "comment", "password_age_days" } },
            { "userright_item", new[] { "userright", "trustee_name", "trustee_sid" } },
            { "variable_item", new[] { "var_ref", "value" } },
            { "wmi57_item", new[] { "namespace", "wql", "result" } },
            { "wmi_item", new[] { "namespace", "wql", "result" } },
            { "wuaupdatesearcher_item", new[] { "search_criteria", "update_id", "title", "support_url", "is_installed", "is_hidden", "msrc_severity", "last_deployment_change_time", "source", "source_path", "days_since_source_modified" } },
            { "xmlfilecontent_item", new[] { "filepath", "path", "filename", "xpath", "value_of", "windows_view" } },
        };

        /// <summary>One results document per check component href.</summary>
        public static IDictionary<string, XmlDocument> Build(IEnumerable<RuleResult> results, ScapContent content, TargetInfo target, DateTime when)
        {
            var byHref = results.Where(r => r.CheckHref != null && r.OvalResults.Count > 0).GroupBy(r => r.CheckHref);
            var docs = new Dictionary<string, XmlDocument>();
            foreach (var g in byHref)
            {
                XmlDocument defs;
                if (!content.CheckComponents.TryGetValue(g.Key, out defs)) continue;
                docs[g.Key] = BuildOne(g.SelectMany(r => r.OvalResults).ToList(), defs, target, when);
            }
            return docs;
        }

        static XmlDocument BuildOne(List<DefinitionResult> defResults, XmlDocument defs, TargetInfo target, DateTime when)
        {
            var versions = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (XmlElement e in defs.SelectNodes("//*[@id]"))
                if (!versions.ContainsKey(e.GetAttribute("id"))) versions[e.GetAttribute("id")] = e.GetAttribute("version");
            Func<string, string> version = id => { string v; return versions.TryGetValue(id ?? "", out v) && v.Length > 0 ? v : "1"; };

            var doc = new XmlDocument();
            doc.AppendChild(doc.CreateXmlDeclaration("1.0", "UTF-8", null));
            var root = doc.CreateElement("oval_results", ResNs);
            root.SetAttribute("xmlns:oval", CommonNs);
            doc.AppendChild(root);
            root.AppendChild(Generator(doc, ResNs, when));

            var directives = El(doc, root, "directives", ResNs);
            foreach (var d in new[] { "definition_true", "definition_false", "definition_unknown", "definition_error", "definition_not_evaluated", "definition_not_applicable" })
            {
                var x = El(doc, directives, d, ResNs);
                x.SetAttribute("reported", "true");
                x.SetAttribute("content", "full");
            }
            root.AppendChild(doc.ImportNode(defs.DocumentElement, true));

            var system = El(doc, El(doc, root, "results", ResNs), "system", ResNs);
            var definitions = El(doc, system, "definitions", ResNs);
            var tests = El(doc, system, "tests", ResNs);
            var seenDefs = new HashSet<string>();
            var seenTests = new HashSet<string>();
            var objects = new Dictionary<string, CollectedObject>(StringComparer.Ordinal);
            var items = new Dictionary<int, OvalItem>();

            foreach (var d in defResults)
            {
                if (seenDefs.Add(d.DefinitionId))
                {
                    var de = El(doc, definitions, "definition", ResNs);
                    de.SetAttribute("definition_id", d.DefinitionId);
                    de.SetAttribute("version", version(d.DefinitionId));
                    de.SetAttribute("result", FindingDetails.OvalText(d.Result));
                }
                foreach (var t in d.Tests)
                {
                    if (!seenTests.Add(t.TestId)) continue;
                    var te = El(doc, tests, "test", ResNs);
                    te.SetAttribute("test_id", t.TestId);
                    te.SetAttribute("version", version(t.TestId));
                    te.SetAttribute("check_existence", t.CheckExistence ?? "at_least_one_exists");
                    te.SetAttribute("check", t.Check ?? "all");
                    if (t.StateIds.Count > 1) te.SetAttribute("state_operator", t.StateOperator ?? "AND");
                    te.SetAttribute("result", FindingDetails.OvalText(t.Result));
                    foreach (var ir in t.Items)
                    {
                        var ti = El(doc, te, "tested_item", ResNs);
                        ti.SetAttribute("item_id", ir.Item.Id.ToString(CultureInfo.InvariantCulture));
                        ti.SetAttribute("result", FindingDetails.OvalText(ir.Result));
                        items[ir.Item.Id] = ir.Item;
                    }
                    if (t.Object != null && t.Object.ObjectId != null)
                    {
                        objects[t.Object.ObjectId] = t.Object;
                        foreach (var i in t.Object.Items) items[i.Id] = i;
                    }
                }
            }

            var sc = El(doc, system, "oval_system_characteristics", ScNs);
            sc.SetAttribute("xmlns:win-sc", WinScNs);
            sc.SetAttribute("xmlns:ind-sc", IndScNs);
            sc.AppendChild(Generator(doc, ScNs, when));
            var info = El(doc, sc, "system_info", ScNs);
            Text(doc, info, "os_name", ScNs, target == null ? "" : target.OsName);
            Text(doc, info, "os_version", ScNs, target == null ? "" : target.OsVersion);
            Text(doc, info, "architecture", ScNs, Environment.Is64BitOperatingSystem ? "AMD64" : "x86");
            Text(doc, info, "primary_host_name", ScNs, target == null ? "" : target.Fqdn);
            var ifaces = El(doc, info, "interfaces", ScNs);
            if (target != null)
                foreach (var a in target.Addresses)
                {
                    string name, mac;
                    Adapter(a, out name, out mac);
                    var i = El(doc, ifaces, "interface", ScNs);
                    Text(doc, i, "interface_name", ScNs, name);
                    Text(doc, i, "ip_address", ScNs, a);
                    Text(doc, i, "mac_address", ScNs, mac);
                }

            var collected = El(doc, sc, "collected_objects", ScNs);
            foreach (var o in objects.Values)
            {
                var oe = El(doc, collected, "object", ScNs);
                oe.SetAttribute("id", o.ObjectId);
                oe.SetAttribute("version", version(o.ObjectId));
                oe.SetAttribute("flag", FlagText(o.Flag));
                foreach (var m in o.Messages.Take(20))
                {
                    var me = Text(doc, oe, "message", ScNs, m);
                    me.SetAttribute("level", o.Flag == CollectedFlag.Error ? "error" : "info");
                }
                foreach (var i in o.Items)
                {
                    var re = El(doc, oe, "reference", ScNs);
                    re.SetAttribute("item_ref", i.Id.ToString(CultureInfo.InvariantCulture));
                }
            }
            var data = El(doc, sc, "system_data", ScNs);
            foreach (var i in items.Values.OrderBy(x => x.Id)) data.AppendChild(Item(doc, i));
            return doc;
        }

        /// <summary>The adapter that holds an IPv4 address: its name and MAC (XX-XX-XX-XX-XX-XX).</summary>
        static void Adapter(string ip, out string name, out string mac)
        {
            name = "unknown";
            mac = "00-00-00-00-00-00";
            try
            {
                foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (!nic.GetIPProperties().UnicastAddresses.Any(u => u.Address.ToString() == ip)) continue;
                    name = nic.Name;
                    var bytes = nic.GetPhysicalAddress().GetAddressBytes();
                    if (bytes.Length == 6) mac = string.Join("-", bytes.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
                    return;
                }
            }
            catch (System.Net.NetworkInformation.NetworkInformationException) { }
        }

        static XmlElement Item(XmlDocument doc, OvalItem i)
        {
            string ns = IndependentItems.Contains(i.ItemType) ? IndScNs : WinScNs;
            var e = doc.CreateElement(ns == WinScNs ? "win-sc" : "ind-sc", i.ItemType, ns);
            e.SetAttribute("id", i.Id.ToString(CultureInfo.InvariantCulture));
            if (i.Status != ItemStatus.Exists) e.SetAttribute("status", StatusText(i.Status));
            foreach (var m in i.Messages.Take(5))
            {
                var me = doc.CreateElement("oval-sc", "message", ScNs);
                me.SetAttribute("level", i.Status == ItemStatus.Error ? "error" : "info");
                me.InnerText = Clean(m);
                e.AppendChild(me);
            }
            string[] order;
            IEnumerable<OvalEntity> entities = i.Entities;
            if (EntityOrder.TryGetValue(i.ItemType, out order))
                entities = i.Entities.Where(x => Array.IndexOf(order, x.Name) >= 0)
                    .Select((x, n) => new { x, n }).OrderBy(t => Array.IndexOf(order, t.x.Name)).ThenBy(t => t.n).Select(t => t.x);
            foreach (var ent in entities)
            {
                var x = doc.CreateElement(e.Prefix, ent.Name, ns);
                if (!string.IsNullOrEmpty(ent.Datatype) && ent.Datatype != "string") x.SetAttribute("datatype", ent.Datatype);
                if (ent.Status != ItemStatus.Exists) x.SetAttribute("status", StatusText(ent.Status));
                if (ent.Datatype == "record")
                    foreach (var f in ent.Fields)
                    {
                        var fe = doc.CreateElement("oval-sc", "field", ScNs);
                        fe.SetAttribute("name", f.Name);
                        if (!string.IsNullOrEmpty(f.Datatype) && f.Datatype != "string") fe.SetAttribute("datatype", f.Datatype);
                        if (f.Status != ItemStatus.Exists) fe.SetAttribute("status", StatusText(f.Status));
                        else fe.InnerText = Clean(f.Value);
                        x.AppendChild(fe);
                    }
                // An empty value stays an empty element: a text node would let the indented output add whitespace.
                else if (ent.Status == ItemStatus.Exists && !string.IsNullOrEmpty(ent.Value)) x.InnerText = Clean(ent.Value);
                e.AppendChild(x);
            }
            return e;
        }

        /// <summary>Collected text can hold characters XML 1.0 cannot carry (registry binaries, console output).</summary>
        static string Clean(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            var sb = new System.Text.StringBuilder(s.Length);
            foreach (char c in s) sb.Append(XmlConvert.IsXmlChar(c) ? c : '?');
            return sb.ToString();
        }

        static XmlElement Generator(XmlDocument doc, string ns, DateTime when)
        {
            var g = doc.CreateElement("generator", ns);
            Text(doc, g, "product_name", CommonNs, "PowerSCAP").Prefix = "oval";
            Text(doc, g, "product_version", CommonNs, EngineInfo.Version).Prefix = "oval";
            Text(doc, g, "schema_version", CommonNs, "5.12.3").Prefix = "oval";
            Text(doc, g, "timestamp", CommonNs, when.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture)).Prefix = "oval";
            return g;
        }

        static XmlElement El(XmlDocument doc, XmlElement parent, string name, string ns)
        {
            var e = doc.CreateElement(name, ns);
            parent.AppendChild(e);
            return e;
        }

        static XmlElement Text(XmlDocument doc, XmlElement parent, string name, string ns, string text)
        {
            var e = El(doc, parent, name, ns);
            e.InnerText = Clean(text ?? "");
            return e;
        }

        static string StatusText(ItemStatus s)
        {
            switch (s)
            {
                case ItemStatus.DoesNotExist: return "does not exist";
                case ItemStatus.Error: return "error";
                case ItemStatus.NotCollected: return "not collected";
                default: return "exists";
            }
        }

        static string FlagText(CollectedFlag f)
        {
            switch (f)
            {
                case CollectedFlag.DoesNotExist: return "does not exist";
                case CollectedFlag.NotCollected: return "not collected";
                case CollectedFlag.NotApplicable: return "not applicable";
                case CollectedFlag.Incomplete: return "incomplete";
                case CollectedFlag.Error: return "error";
                default: return "complete";
            }
        }
    }
}
