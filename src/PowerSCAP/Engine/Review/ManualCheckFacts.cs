using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
using PowerScap.Engine.Native;

namespace PowerScap.Engine.Review
{
    public class ShareInfo
    {
        public string Name { get; set; }
        /// <summary>Win32_Share Type; the 0x80000000 bit marks administrative (system-created) shares.</summary>
        public uint Type { get; set; }
        public string Path { get; set; }
        public bool IsSystem { get { return (Type & 0x80000000u) != 0 || Name == "IPC$"; } }
    }

    /// <summary>
    /// What the manual checks need to know about the machine. <see cref="Collect"/> reads it natively (registry, WMI,
    /// NetAPI); tests fill it by hand. A fact that could not be read is null, with the reason in <see cref="Errors"/>.
    /// </summary>
    public class ManualCheckFacts
    {
        public ManualCheckFacts()
        {
            Errors = new Dictionary<string, string>(StringComparer.Ordinal);
            GroupMembers = new Dictionary<string, IList<string>>(StringComparer.OrdinalIgnoreCase);
            PolicyLists = new Dictionary<string, IList<string>>(StringComparer.OrdinalIgnoreCase);
            Now = DateTime.Now;
        }

        public DateTime Now { get; set; }
        public bool? DomainJoined { get; set; }
        /// <summary>Win32_OperatingSystem ProductType other than 1 (workstation): a server or domain controller.</summary>
        public bool? IsServer { get; set; }
        public IList<LocalUser> LocalUsers { get; set; }
        /// <summary>Members (DOMAIN\name) of local groups by well-known SID: S-1-5-32-544 Administrators, -551 Backup Operators, -578 Hyper-V Administrators.</summary>
        public IDictionary<string, IList<string>> GroupMembers { get; private set; }
        public IList<ShareInfo> Shares { get; set; }
        /// <summary>Interface descriptions of all network adapters, hidden ones included (Get-NetAdapter -IncludeHidden).</summary>
        public IList<string> NetworkAdapters { get; set; }
        /// <summary>AppLocker rule collections (Exe, Dll, Script, Msi, Appx) that are enforced and have rules.</summary>
        public IList<string> AppLockerEnforced { get; set; }
        /// <summary>Windows Defender Application Control user-mode policy enforced (Win32_DeviceGuard UMCI status 2).</summary>
        public bool? WdacUserModeEnforced { get; set; }
        /// <summary>Hosted hypervisors found: Hyper-V, VMware Workstation, VirtualBox.</summary>
        public IList<string> Hypervisors { get; set; }
        /// <summary>Policy list values by "HKLM\...\Key" (null entry: the key does not exist).</summary>
        public IDictionary<string, IList<string>> PolicyLists { get; private set; }

        public const string Administrators = "S-1-5-32-544";
        public const string BackupOperators = "S-1-5-32-551";
        public const string HyperVAdministrators = "S-1-5-32-578";

        /// <summary>Policy keys whose values the checks list (allowlists configured through Group Policy).</summary>
        public static readonly string[] PolicyListKeys =
        {
            @"SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains",
            @"SOFTWARE\Policies\Microsoft\Edge\PopupsAllowedForUrls",
            @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist",
            @"SOFTWARE\Policies\Microsoft\Edge\AutoplayAllowlist",
            @"SOFTWARE\Policies\Google\Chrome\AutoplayAllowlist"
        };

        public static ManualCheckFacts Collect()
        {
            var f = new ManualCheckFacts();
            f.Read("domain", () =>
            {
                foreach (ManagementBaseObject o in Query(@"root\cimv2", "SELECT PartOfDomain FROM Win32_ComputerSystem", null))
                    f.DomainJoined = o["PartOfDomain"] is bool && (bool)o["PartOfDomain"];
            });
            f.Read("product type", () =>
            {
                foreach (ManagementBaseObject o in Query(@"root\cimv2", "SELECT ProductType FROM Win32_OperatingSystem", null))
                    f.IsServer = Convert.ToUInt32(o["ProductType"]) != 1;
            });
            f.Read("local users", () => f.LocalUsers = Netapi.GetLocalUsers());
            foreach (var sid in new[] { Administrators, BackupOperators, HyperVAdministrators })
            {
                string s = sid;
                f.Read("group " + s, () =>
                {
                    string name;
                    try { name = ((NTAccount)new SecurityIdentifier(s).Translate(typeof(NTAccount))).Value; }
                    catch (IdentityNotMappedException) { f.GroupMembers[s] = new List<string>(); return; }  // group not present (Hyper-V not installed)
                    int slash = name.IndexOf('\\');
                    f.GroupMembers[s] = Netapi.GetGroupMembers(slash >= 0 ? name.Substring(slash + 1) : name).Select(m => m.Name).ToList();
                });
            }
            f.Read("shares", () =>
            {
                var list = new List<ShareInfo>();
                foreach (ManagementBaseObject o in Query(@"root\cimv2", "SELECT Name, Type, Path FROM Win32_Share", null))
                    list.Add(new ShareInfo { Name = Convert.ToString(o["Name"]), Type = Convert.ToUInt32(o["Type"]), Path = Convert.ToString(o["Path"]) });
                f.Shares = list;
            });
            f.Read("network adapters", () =>
            {
                // MSFT_NetAdapter with the IncludeHidden context, as Get-NetAdapter -IncludeHidden queries it.
                var ctx = new ManagementNamedValueCollection();
                ctx.Add("IncludeHidden", true);
                var list = new List<string>();
                foreach (ManagementBaseObject o in Query(@"root\StandardCimv2", "SELECT InterfaceDescription FROM MSFT_NetAdapter", ctx))
                    list.Add(Convert.ToString(o["InterfaceDescription"]));
                f.NetworkAdapters = list;
            });
            f.Read("AppLocker", () =>
            {
                var enforced = new List<string>();
                using (var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var srp = b.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\SrpV2"))
                    if (srp != null)
                        foreach (var name in srp.GetSubKeyNames())
                            using (var c = srp.OpenSubKey(name))
                            {
                                object mode = c == null ? null : c.GetValue("EnforcementMode");
                                if (mode is int && (int)mode == 1 && c.SubKeyCount > 0) enforced.Add(name);
                            }
                f.AppLockerEnforced = enforced;
            });
            f.Read("Device Guard", () =>
            {
                f.WdacUserModeEnforced = false;
                foreach (ManagementBaseObject o in Query(@"root\Microsoft\Windows\DeviceGuard", "SELECT UsermodeCodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard", null))
                    f.WdacUserModeEnforced = o["UsermodeCodeIntegrityPolicyEnforcementStatus"] != null && Convert.ToUInt32(o["UsermodeCodeIntegrityPolicyEnforcementStatus"]) == 2;
            });
            f.Read("hypervisors", () =>
            {
                var found = new List<string>();
                if (ServiceController.GetServices().Any(s => { using (s) return s.ServiceName.Equals("vmms", StringComparison.OrdinalIgnoreCase); }))
                    found.Add("Hyper-V");
                foreach (var p in InstalledPrograms())
                    if (p.StartsWith("VMware Workstation", StringComparison.OrdinalIgnoreCase) || p.StartsWith("VMware Player", StringComparison.OrdinalIgnoreCase)
                        || p.IndexOf("VirtualBox", StringComparison.OrdinalIgnoreCase) >= 0)
                        if (!found.Contains(p)) found.Add(p);
                f.Hypervisors = found;
            });
            foreach (var key in PolicyListKeys)
            {
                string k = key;
                f.Read("policy " + k, () =>
                {
                    using (var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                    using (var r = b.OpenSubKey(k))
                        f.PolicyLists[@"HKLM\" + k] = r == null ? null : r.GetValueNames().Select(n => n + " = " + Convert.ToString(r.GetValue(n))).ToList();
                });
            }
            return f;
        }

        void Read(string what, Action read)
        {
            try { read(); }
            catch (Exception e)
            {
                if (e is OutOfMemoryException) throw;
                Errors[what] = e.Message;
            }
        }

        static IEnumerable<ManagementBaseObject> Query(string ns, string wql, ManagementNamedValueCollection context)
        {
            var options = new EnumerationOptions { Timeout = TimeSpan.FromSeconds(20), ReturnImmediately = false };
            if (context != null) options.Context = context;
            using (var searcher = new ManagementObjectSearcher(new ManagementScope(ns), new ObjectQuery(wql), options))
                return searcher.Get().Cast<ManagementBaseObject>().ToList();
        }

        static IEnumerable<string> InstalledPrograms()
        {
            var names = new List<string>();
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                using (var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                using (var k = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                    if (k != null)
                        foreach (var sub in k.GetSubKeyNames())
                            using (var s = k.OpenSubKey(sub))
                            {
                                var n = s == null ? null : s.GetValue("DisplayName") as string;
                                if (!string.IsNullOrEmpty(n)) names.Add(n);
                            }
            return names;
        }

        /// <summary>Why a fact is missing, for evidence text ("could not read shares: access denied").</summary>
        public Dictionary<string, string> Errors { get; private set; }
    }
}
