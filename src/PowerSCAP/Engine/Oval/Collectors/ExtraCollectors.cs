using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Management.Automation;
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

    /// <summary>windows-def cmdlet_object → cmdlet_item: runs the cmdlet in an isolated runspace, one value record per output object.</summary>
    public class CmdletCollector : ICollector
    {
        public string ObjectType { get { return "cmdlet_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion module, verb, noun;
            spec.Entities.TryGetValue("module_name", out module);
            spec.Entities.TryGetValue("verb", out verb);
            spec.Entities.TryGetValue("noun", out noun);
            var parameters = RecordFields(spec, "parameters");
            var select = RecordFields(spec, "select");
            string command = verb.Values[0] + "-" + noun.Values[0];

            var item = new OvalItem(ctx.NextItemId(), "cmdlet_item");
            if (module != null && !module.IsNil) item.Add("module_name", module.Values[0]); else item.Entities.Add(OvalEntity.Missing("module_name"));
            item.Entities.Add(OvalEntity.Missing("module_id"));
            item.Entities.Add(OvalEntity.Missing("module_version"));
            item.Add("verb", verb.Values[0]).Add("noun", noun.Values[0]);
            item.Entities.Add(Record("parameters", parameters));
            item.Entities.Add(Record("select", select));

            using (var ps = PowerShell.Create())
            {
                if (module != null && !module.IsNil)
                    ps.AddCommand("Import-Module").AddParameter("Name", module.Values[0]).AddParameter("ErrorAction", "SilentlyContinue").AddStatement();
                ps.AddCommand(command);
                foreach (var kv in parameters) ps.AddParameter(kv.Key, kv.Value);
                string[] props = null;
                string propList;
                if (select.TryGetValue("property", out propList))
                {
                    props = propList.Split(',').Select(p => p.Trim()).Where(p => p.Length > 0).ToArray();
                    ps.AddCommand("Select-Object").AddParameter("Property", props);
                }
                var output = ps.Invoke();
                foreach (var o in output.Where(o => o != null))
                {
                    var value = new OvalEntity("value", null, "record");
                    foreach (var p in o.Properties)
                    {
                        if (props != null && !props.Contains(p.Name, StringComparer.OrdinalIgnoreCase)) continue;
                        object v;
                        try { v = p.Value; } catch (Exception) { continue; }
                        value.Fields.Add(new OvalEntity(p.Name.ToLowerInvariant(), v == null ? "" : Convert.ToString(v, CultureInfo.InvariantCulture)));
                    }
                    item.Entities.Add(value);
                }
                if (output.Count == 0)
                {
                    item.Entities.Add(OvalEntity.Missing("value"));
                    if (ps.HadErrors)
                    {
                        foreach (var e in ps.Streams.Error) item.Messages.Add(e.ToString());
                        r.Messages.AddRange(item.Messages);
                    }
                }
            }
            r.Items.Add(item);
            return r;
        }

        static Dictionary<string, string> RecordFields(ObjectSpec spec, string entity)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (System.Xml.XmlNode n in spec.Element.ChildNodes)
            {
                if (n.LocalName != entity) continue;
                foreach (System.Xml.XmlNode f in n.ChildNodes)
                {
                    var fe = f as System.Xml.XmlElement;
                    if (fe != null && fe.LocalName == "field") map[fe.GetAttribute("name")] = fe.InnerText;
                }
            }
            return map;
        }

        static OvalEntity Record(string name, Dictionary<string, string> fields)
        {
            var e = new OvalEntity(name, null, "record");
            foreach (var kv in fields) e.Fields.Add(new OvalEntity(kv.Key, kv.Value));
            return e;
        }
    }

    /// <summary>independent shellcommand_object → shellcommand_item (one item per output line matching the pattern).</summary>
    public class ShellCommandCollector : ICollector
    {
        public string ObjectType { get { return "shellcommand_object"; } }
        const int TimeoutMs = 300000;

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion shellC, commandC, patternC;
            spec.Entities.TryGetValue("shell", out shellC);
            spec.Entities.TryGetValue("command", out commandC);
            spec.Entities.TryGetValue("pattern", out patternC);
            string shell = shellC != null && shellC.Values.Count > 0 ? shellC.Values[0] : "cmd";
            foreach (var command in commandC.Values)
            {
                int exit;
                string stdout, stderr;
                Run(shell, command, out exit, out stdout, out stderr);
                // Lines as a line reader sees them: the final newline does not start another (empty) line.
                var lines = stdout.Replace("\r\n", "\n").TrimEnd('\n').Split('\n');
                if (stdout.Length == 0) lines = new string[0];
                foreach (var pattern in (patternC == null ? new List<string> { ".*" } : patternC.Values))
                {
                    // One item per command run; each matching output line is a stdout_line entity.
                    var rx = OvalOps.ToRegex(pattern);
                    var item = new OvalItem(ctx.NextItemId(), "shellcommand_item");
                    item.Add("shell", shell).Add("command", command).Add("exit_status", exit.ToString(CultureInfo.InvariantCulture), "int");
                    item.Add("pattern", pattern);
                    foreach (var line in lines)
                    {
                        Match m = rx.Match(line);
                        if (!m.Success) continue;
                        item.Add("stdout_line", line);
                        for (int g = 1; g < m.Groups.Count; g++) item.Add("subexpression", m.Groups[g].Value);
                    }
                    foreach (var errLine in stderr.Replace("\r\n", "\n").TrimEnd('\n').Split('\n'))
                        if (errLine.Length > 0) item.Add("stderr_line", errLine);
                    r.Items.Add(item);
                }
            }
            return r;
        }

        static void Run(string shell, string command, out int exit, out string stdout, out string stderr)
        {
            if (shell.Equals("powershell", StringComparison.OrdinalIgnoreCase) || shell.Equals("pwsh", StringComparison.OrdinalIgnoreCase))
            {
                RunInProcess(command, out exit, out stdout, out stderr);
                return;
            }
            RunCmd(command, out exit, out stdout, out stderr);
        }

        /// <summary>
        /// Runs PowerShell content in a private runspace inside this process. No child powershell.exe and no
        /// encoded command lines, which antivirus heuristics treat as suspicious. Output is rendered as the
        /// console would show it.
        /// </summary>
        static void RunInProcess(string command, out int exit, out string stdout, out string stderr)
        {
            using (var ps = PowerShell.Create())
            {
                ps.AddScript(command).AddCommand("Out-String").AddParameter("Stream").AddParameter("Width", 4096);
                var async = ps.BeginInvoke();
                if (!async.AsyncWaitHandle.WaitOne(TimeoutMs))
                {
                    ps.Stop();
                    throw new TimeoutException("Command timed out: " + command);
                }
                var output = ps.EndInvoke(async);
                stdout = string.Join("\n", output.Select(o => o == null ? "" : o.ToString()));
                if (output.Count > 0) stdout += "\n";
                stderr = string.Join("\n", ps.Streams.Error.Select(e => e.ToString()));
                object last = ps.Runspace.SessionStateProxy.GetVariable("LASTEXITCODE");
                if (last is int && (int)last != 0) exit = (int)last;
                else exit = ps.HadErrors ? 1 : 0;
            }
        }

        static void RunCmd(string command, out int exit, out string stdout, out string stderr)
        {
            var psi = new ProcessStartInfo
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            psi.FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            psi.Arguments = "/d /c " + command;
            using (var p = Process.Start(psi))
            {
                var errTask = p.StandardError.ReadToEndAsync();
                stdout = p.StandardOutput.ReadToEnd();
                if (!p.WaitForExit(TimeoutMs)) { try { p.Kill(); } catch (Exception) { } throw new TimeoutException("Command timed out: " + command); }
                stderr = errTask.Result;
                exit = p.ExitCode;
            }
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
