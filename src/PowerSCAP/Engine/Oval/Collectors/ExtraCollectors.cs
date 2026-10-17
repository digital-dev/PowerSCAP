using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using PowerScap.Engine.Native;

namespace PowerScap.Engine.Oval
{
    /// <summary>windows-def userright_object → userright_item (one item per trustee holding the right).</summary>
    public class UserRightCollector : ICollector
    {
        public string ObjectType { get { return "userright_object"; } }

        /// <summary>winnt.h SE_*_NAME constants → LSA right/privilege names.</summary>
        static readonly Dictionary<string, string> Names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "SE_ASSIGNPRIMARYTOKEN_NAME", "SeAssignPrimaryTokenPrivilege" }, { "SE_AUDIT_NAME", "SeAuditPrivilege" },
            { "SE_BACKUP_NAME", "SeBackupPrivilege" }, { "SE_CHANGE_NOTIFY_NAME", "SeChangeNotifyPrivilege" },
            { "SE_CREATE_GLOBAL_NAME", "SeCreateGlobalPrivilege" }, { "SE_CREATE_PAGEFILE_NAME", "SeCreatePagefilePrivilege" },
            { "SE_CREATE_PERMANENT_NAME", "SeCreatePermanentPrivilege" }, { "SE_CREATE_SYMBOLIC_LINK_NAME", "SeCreateSymbolicLinkPrivilege" },
            { "SE_CREATE_TOKEN_NAME", "SeCreateTokenPrivilege" }, { "SE_DEBUG_NAME", "SeDebugPrivilege" },
            { "SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME", "SeDelegateSessionUserImpersonatePrivilege" },
            { "SE_ENABLE_DELEGATION_NAME", "SeEnableDelegationPrivilege" }, { "SE_IMPERSONATE_NAME", "SeImpersonatePrivilege" },
            { "SE_INC_BASE_PRIORITY_NAME", "SeIncreaseBasePriorityPrivilege" }, { "SE_INCREASE_QUOTA_NAME", "SeIncreaseQuotaPrivilege" },
            { "SE_INC_WORKING_SET_NAME", "SeIncreaseWorkingSetPrivilege" }, { "SE_LOAD_DRIVER_NAME", "SeLoadDriverPrivilege" },
            { "SE_LOCK_MEMORY_NAME", "SeLockMemoryPrivilege" }, { "SE_MACHINE_ACCOUNT_NAME", "SeMachineAccountPrivilege" },
            { "SE_MANAGE_VOLUME_NAME", "SeManageVolumePrivilege" }, { "SE_PROF_SINGLE_PROCESS_NAME", "SeProfileSingleProcessPrivilege" },
            { "SE_RELABEL_NAME", "SeRelabelPrivilege" }, { "SE_REMOTE_SHUTDOWN_NAME", "SeRemoteShutdownPrivilege" },
            { "SE_RESTORE_NAME", "SeRestorePrivilege" }, { "SE_SECURITY_NAME", "SeSecurityPrivilege" },
            { "SE_SHUTDOWN_NAME", "SeShutdownPrivilege" }, { "SE_SYNC_AGENT_NAME", "SeSyncAgentPrivilege" },
            { "SE_SYSTEM_ENVIRONMENT_NAME", "SeSystemEnvironmentPrivilege" }, { "SE_SYSTEM_PROFILE_NAME", "SeSystemProfilePrivilege" },
            { "SE_SYSTEMTIME_NAME", "SeSystemtimePrivilege" }, { "SE_TAKE_OWNERSHIP_NAME", "SeTakeOwnershipPrivilege" },
            { "SE_TCB_NAME", "SeTcbPrivilege" }, { "SE_TIME_ZONE_NAME", "SeTimeZonePrivilege" },
            { "SE_TRUSTED_CREDMAN_ACCESS_NAME", "SeTrustedCredManAccessPrivilege" }, { "SE_UNDOCK_NAME", "SeUndockPrivilege" },
            { "SE_UNSOLICITED_INPUT_NAME", "SeUnsolicitedInputPrivilege" },
            { "SE_BATCH_LOGON_NAME", "SeBatchLogonRight" }, { "SE_INTERACTIVE_LOGON_NAME", "SeInteractiveLogonRight" },
            { "SE_NETWORK_LOGON_NAME", "SeNetworkLogonRight" }, { "SE_REMOTE_INTERACTIVE_LOGON_NAME", "SeRemoteInteractiveLogonRight" },
            { "SE_SERVICE_LOGON_NAME", "SeServiceLogonRight" }, { "SE_DENY_BATCH_LOGON_NAME", "SeDenyBatchLogonRight" },
            { "SE_DENY_INTERACTIVE_LOGON_NAME", "SeDenyInteractiveLogonRight" }, { "SE_DENY_NETWORK_LOGON_NAME", "SeDenyNetworkLogonRight" },
            { "SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME", "SeDenyRemoteInteractiveLogonRight" }, { "SE_DENY_SERVICE_LOGON_NAME", "SeDenyServiceLogonRight" }
        };

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion c;
            spec.Entities.TryGetValue("userright", out c);
            IList<string> rights = CollectorUtil.LiteralValues(c) ?? Names.Keys.Where(n => CollectorUtil.Satisfies(c, n)).ToList();
            foreach (var right in rights)
            {
                string lsa;
                if (!Names.TryGetValue(right, out lsa)) { r.Messages.Add("Unknown user right " + right); continue; }
                var holders = Advapi.GetAccountsWithRight(lsa);
                if (holders.Count == 0)
                {
                    // Nobody holds the right: one item with empty trustee fields (DISA "None" states compare against "").
                    var empty = new OvalItem(ctx.NextItemId(), "userright_item");
                    empty.Add("userright", right).Add("trustee_sid", "").Add("trustee_name", "");
                    r.Items.Add(empty);
                    continue;
                }
                foreach (var sid in holders)
                {
                    string name = Accounts.NameOf(sid);
                    var item = new OvalItem(ctx.NextItemId(), "userright_item");
                    item.Add("userright", right).Add("trustee_sid", sid.Value).Add("trustee_name", name == null ? sid.Value : Accounts.Bare(name));
                    r.Items.Add(item);
                }
            }
            if (r.Items.Count == 0) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }
    }

    /// <summary>windows-def wmi_object (pre-5.7 form) → wmi_item with one string result per returned object.</summary>
    public class WmiCollector : ICollector
    {
        public string ObjectType { get { return "wmi_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion nsC, wqlC;
            spec.Entities.TryGetValue("namespace", out nsC);
            spec.Entities.TryGetValue("wql", out wqlC);
            foreach (var ns in nsC.Values)
                foreach (var wql in wqlC.Values)
                {
                    var item = new OvalItem(ctx.NextItemId(), "wmi_item");
                    item.Add("namespace", ns).Add("wql", wql);
                    int count = 0;
                    using (var s = new ManagementObjectSearcher(new ManagementScope(ns), new ObjectQuery(wql)))
                        foreach (ManagementBaseObject mo in s.Get())
                        {
                            // A single-property SELECT: the result is that property's value.
                            var p = mo.Properties.Cast<PropertyData>().FirstOrDefault(x => !x.Name.StartsWith("__"));
                            if (p == null || p.Value == null) continue;
                            item.Add("result", Convert.ToString(p.Value, CultureInfo.InvariantCulture));
                            count++;
                        }
                    if (count > 0) r.Items.Add(item); // no rows: nothing exists
                }
            if (r.Items.Count == 0) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }
    }

    /// <summary>windows-def ntuser_object → ntuser_item: the key/value in every local user profile hive (NTUSER.DAT).</summary>
    public class NtUserCollector : ICollector
    {
        public string ObjectType { get { return "ntuser_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion keyC, nameC;
            spec.Entities.TryGetValue("key", out keyC);
            spec.Entities.TryGetValue("name", out nameC);
            IList<string> keys = CollectorUtil.LiteralValues(keyC);
            if (keys == null) { r.Flag = CollectedFlag.NotCollected; r.Messages.Add("ntuser_object: only literal keys are supported."); return r; }

            var users = Netapi.GetLocalUsers();
            using (var lm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var profiles = lm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"))
            using (var hku = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64))
            {
                foreach (var sid in profiles.GetSubKeyNames().Where(s => s.StartsWith("S-1-5-21-")))
                {
                    string profilePath;
                    using (var p = profiles.OpenSubKey(sid)) profilePath = p == null ? null : p.GetValue("ProfileImagePath") as string;
                    if (profilePath == null) continue;
                    string hiveFile = Path.Combine(Environment.ExpandEnvironmentVariables(profilePath), "NTUSER.DAT");
                    bool loaded = hku.GetSubKeyNames().Contains(sid, StringComparer.OrdinalIgnoreCase);
                    string mount = loaded ? sid : "PowerSCAP_" + sid;
                    if (!loaded)
                    {
                        if (!File.Exists(hiveFile)) continue;
                        try { Hive.Load(mount, hiveFile); }
                        catch (Exception ex)
                        {
                            var err = new OvalItem(ctx.NextItemId(), "ntuser_item");
                            err.Add("sid", sid);
                            err.Status = ItemStatus.Error;
                            err.Messages.Add("Could not load " + hiveFile + ": " + ex.Message);
                            r.Items.Add(err);
                            r.Flag = CollectedFlag.Error;
                            continue;
                        }
                    }
                    try
                    {
                        var account = new SecurityIdentifier(sid);
                        var user = users.FirstOrDefault(u => u.Sid != null && u.Sid.Equals(account));
                        string name = Accounts.NameOf(account);
                        foreach (var key in keys)
                            using (var k = hku.OpenSubKey(mount + "\\" + key))
                            {
                                if (k == null) continue;
                                IEnumerable<string> names = CollectorUtil.LiteralValues(nameC) ?? k.GetValueNames().Where(n => CollectorUtil.SatisfiesIgnoreCase(nameC, n)).ToList();
                                foreach (var valueName in names)
                                {
                                    var item = new OvalItem(ctx.NextItemId(), "ntuser_item");
                                    item.Add("key", key).Add("name", valueName).Add("sid", sid);
                                    item.Add("username", name == null ? sid : Accounts.Bare(name));
                                    item.Add("account_type", user != null ? "local" : "domain");
                                    item.Add("logged_on", loaded ? "1" : "0", "boolean");
                                    if (user != null) item.Add("enabled", user.Enabled ? "1" : "0", "boolean");
                                    else item.Entities.Add(OvalEntity.Missing("enabled"));
                                    item.Add("filepath", hiveFile);
                                    if (!k.GetValueNames().Contains(valueName, StringComparer.OrdinalIgnoreCase))
                                    {
                                        item.Status = ItemStatus.DoesNotExist;
                                        item.Entities.Add(OvalEntity.Missing("value"));
                                    }
                                    else
                                    {
                                        AddValue(item, k.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames), k.GetValueKind(valueName));
                                    }
                                    r.Items.Add(item);
                                }
                            }
                    }
                    finally { if (!loaded) Hive.Unload(mount); }
                }
            }
            if (r.Items.Count == 0 && r.Flag == CollectedFlag.Complete) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }

        static void AddValue(OvalItem item, object raw, RegistryValueKind kind)
        {
            switch (kind)
            {
                case RegistryValueKind.DWord: item.Add("type", "reg_dword").Add("value", unchecked((uint)(int)raw).ToString(CultureInfo.InvariantCulture), "int"); break;
                case RegistryValueKind.QWord: item.Add("type", "reg_qword").Add("value", unchecked((ulong)(long)raw).ToString(CultureInfo.InvariantCulture), "int"); break;
                case RegistryValueKind.MultiString: item.Add("type", "reg_multi_sz"); foreach (var s in (string[])raw) item.Add("value", s); break;
                case RegistryValueKind.ExpandString: item.Add("type", "reg_expand_sz").Add("value", (string)raw); break;
                case RegistryValueKind.Binary: item.Add("type", "reg_binary").Add("value", BitConverter.ToString((byte[])raw).Replace("-", ""), "binary"); break;
                default: item.Add("type", "reg_sz").Add("value", Convert.ToString(raw, CultureInfo.InvariantCulture)); break;
            }
        }
    }
}
