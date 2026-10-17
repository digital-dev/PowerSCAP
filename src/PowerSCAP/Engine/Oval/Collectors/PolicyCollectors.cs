using System;
using System.Collections.Generic;
using System.Globalization;
using PowerScap.Engine.Native;

namespace PowerScap.Engine.Oval
{
    /// <summary>windows-def passwordpolicy_object → passwordpolicy_item.</summary>
    public class PasswordPolicyCollector : ICollector
    {
        public string ObjectType { get { return "passwordpolicy_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var p = Netapi.GetPasswordPolicy();
            var item = new OvalItem(ctx.NextItemId(), "passwordpolicy_item");
            item.Add("max_passwd_age", N(p.MaxPasswordAge), "int");
            item.Add("min_passwd_age", N(p.MinPasswordAge), "int");
            item.Add("min_passwd_len", N(p.MinPasswordLength), "int");
            item.Add("password_hist_len", N(p.PasswordHistoryLength), "int");
            AddBool(item, "password_complexity", p.Complexity);
            AddBool(item, "reversible_encryption", p.ReversibleEncryption);
            string anon = SecurityPolicy.Get("System Access", "LSAAnonymousNameLookup");
            AddBool(item, "anonymous_name_lookup", anon == null ? (bool?)null : anon.Trim() == "1");
            var r = new CollectedObject(spec.ObjectId);
            r.Items.Add(item);
            return r;
        }

        static string N(long v) { return v.ToString(CultureInfo.InvariantCulture); }

        static void AddBool(OvalItem item, string name, bool? value)
        {
            if (!value.HasValue)
            {
                var e = new OvalEntity(name, null, "boolean");
                e.Status = ItemStatus.Error;
                item.Entities.Add(e);
                item.Messages.Add("Could not read " + name + " from the SAM.");
                return;
            }
            item.Add(name, value.Value ? "1" : "0", "boolean");
        }
    }

    /// <summary>Local security policy values exported by secedit (requires administrator).</summary>
    public static class SecurityPolicy
    {
        public static string Get(string section, string key)
        {
            string file = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "powerscap_secpol_" + Guid.NewGuid().ToString("N") + ".inf");
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo(System.IO.Path.Combine(Environment.SystemDirectory, "secedit.exe"),
                    "/export /cfg \"" + file + "\" /areas SECURITYPOLICY /quiet")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
                using (var p = System.Diagnostics.Process.Start(psi))
                {
                    p.StandardOutput.ReadToEnd();
                    p.WaitForExit(60000);
                }
                if (!System.IO.File.Exists(file)) return null;
                string current = null;
                foreach (var raw in System.IO.File.ReadAllLines(file))
                {
                    string line = raw.Trim();
                    if (line.StartsWith("[")) { current = line.Trim('[', ']'); continue; }
                    int eq = line.IndexOf('=');
                    if (eq < 0 || !string.Equals(current, section, StringComparison.OrdinalIgnoreCase)) continue;
                    if (string.Equals(line.Substring(0, eq).Trim(), key, StringComparison.OrdinalIgnoreCase))
                        return line.Substring(eq + 1).Trim();
                }
                return null;
            }
            finally
            {
                try { System.IO.File.Delete(file); } catch (Exception) { }
            }
        }
    }

    /// <summary>windows-def lockoutpolicy_object → lockoutpolicy_item.</summary>
    public class LockoutPolicyCollector : ICollector
    {
        public string ObjectType { get { return "lockoutpolicy_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var p = Netapi.GetPasswordPolicy();
            var item = new OvalItem(ctx.NextItemId(), "lockoutpolicy_item");
            item.Add("force_logoff", p.ForceLogoff.ToString(CultureInfo.InvariantCulture), "int");
            item.Add("lockout_duration", p.LockoutDuration.ToString(CultureInfo.InvariantCulture), "int");
            item.Add("lockout_observation_window", p.LockoutObservationWindow.ToString(CultureInfo.InvariantCulture), "int");
            item.Add("lockout_threshold", p.LockoutThreshold.ToString(CultureInfo.InvariantCulture), "int");
            var r = new CollectedObject(spec.ObjectId);
            r.Items.Add(item);
            return r;
        }
    }

    /// <summary>windows-def auditeventpolicysubcategories_object → one item with one entity per subcategory.</summary>
    public class AuditEventPolicySubcategoriesCollector : ICollector
    {
        public string ObjectType { get { return "auditeventpolicysubcategories_object"; } }

        /// <summary>Subcategory GUID suffix 0CCE92xx-69AE-11D9-BED3-505054503030 → OVAL entity name.</summary>
        static readonly Dictionary<int, string> Names = new Dictionary<int, string>
        {
            { 0x10, "security_state_change" }, { 0x11, "security_system_extension" }, { 0x12, "system_integrity" },
            { 0x13, "ipsec_driver" }, { 0x14, "other_system_events" }, { 0x15, "logon" }, { 0x16, "logoff" },
            { 0x17, "account_lockout" }, { 0x18, "ipsec_main_mode" }, { 0x19, "ipsec_quick_mode" },
            { 0x1A, "ipsec_extended_mode" }, { 0x1B, "special_logon" }, { 0x1C, "other_logon_logoff_events" },
            { 0x1D, "file_system" }, { 0x1E, "registry" }, { 0x1F, "kernel_object" }, { 0x20, "sam" },
            { 0x21, "certification_services" }, { 0x22, "application_generated" }, { 0x23, "handle_manipulation" },
            { 0x24, "file_share" }, { 0x25, "filtering_platform_packet_drop" }, { 0x26, "filtering_platform_connection" },
            { 0x27, "other_object_access_events" }, { 0x28, "sensitive_privilege_use" }, { 0x29, "non_sensitive_privilege_use" },
            { 0x2A, "other_privilege_use_events" }, { 0x2B, "process_creation" }, { 0x2C, "process_termination" },
            { 0x2D, "dpapi_activity" }, { 0x2E, "rpc_events" }, { 0x2F, "audit_policy_change" },
            { 0x30, "authentication_policy_change" }, { 0x31, "authorization_policy_change" },
            { 0x32, "mpssvc_rule_level_policy_change" }, { 0x33, "filtering_platform_policy_change" },
            { 0x34, "other_policy_change_events" }, { 0x35, "user_account_management" },
            { 0x36, "computer_account_management" }, { 0x37, "security_group_management" },
            { 0x38, "distribution_group_management" }, { 0x39, "application_group_management" },
            { 0x3A, "other_account_management_events" }, { 0x3B, "directory_service_access" },
            { 0x3C, "directory_service_changes" }, { 0x3D, "directory_service_replication" },
            { 0x3E, "detailed_directory_service_replication" }, { 0x3F, "credential_validation" },
            { 0x40, "kerberos_service_ticket_operations" }, { 0x41, "other_account_logon_events" },
            { 0x42, "kerberos_authentication_service" }, { 0x43, "network_policy_server" },
            { 0x44, "detailed_file_share" }, { 0x45, "removable_storage" }, { 0x46, "central_access_policy_staging" },
            { 0x47, "user_device_claims" }, { 0x48, "pnp_activity" }, { 0x49, "group_membership" },
            { 0x4A, "audit_detailedtracking_tokenrightadjusted" }
        };

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var policy = Advapi.QueryAuditPolicy();
            var item = new OvalItem(ctx.NextItemId(), "auditeventpolicysubcategories_item");
            foreach (var kv in policy)
            {
                string name = EntityName(kv.Key);
                if (name == null) continue;
                item.Add(name, Text(kv.Value));
            }
            var r = new CollectedObject(spec.ObjectId);
            r.Items.Add(item);
            return r;
        }

        /// <summary>OVAL entity name for an audit subcategory GUID, or null for subcategories OVAL does not define.</summary>
        public static string EntityName(Guid subcategory)
        {
            byte[] b = subcategory.ToByteArray();
            string name;
            bool known = b[1] == 0x92 && b[2] == 0xCE && b[3] == 0x0C;
            return known && Names.TryGetValue(b[0], out name) ? name : null;
        }

        static string Text(uint info)
        {
            bool s = (info & 0x1) != 0, f = (info & 0x2) != 0;
            if (s && f) return "AUDIT_SUCCESS_FAILURE";
            if (s) return "AUDIT_SUCCESS";
            if (f) return "AUDIT_FAILURE";
            return "AUDIT_NONE";
        }
    }
}
