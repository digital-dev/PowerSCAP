using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using Microsoft.Win32;

namespace PowerScap.Engine.Profile
{
    public class DetectedProduct
    {
        public string Name { get; set; }
        public string Version { get; set; }
        /// <summary>The NCP checklist target this product corresponds to (exact NCP spelling).</summary>
        public string NcpTarget { get; set; }
        /// <summary>Where the detection came from, e.g. a registry path.</summary>
        public string Evidence { get; set; }

        public override string ToString() { return Name + (string.IsNullOrEmpty(Version) ? "" : " " + Version); }
    }

    /// <summary>What this machine is and which STIG-relevant products it has. Registry, WMI and services only.</summary>
    public class SystemProfile
    {
        public SystemProfile()
        {
            Products = new List<DetectedProduct>();
        }

        public string ComputerName { get; set; }
        public string OsCaption { get; set; }
        public string OsBuild { get; set; }
        public string OsEdition { get; set; }
        public string Architecture { get; set; }
        public bool DomainJoined { get; set; }
        public string DomainOrWorkgroup { get; set; }
        public IList<DetectedProduct> Products { get; private set; }

        const string Uninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

        public static SystemProfile Collect()
        {
            var p = new SystemProfile { ComputerName = Environment.MachineName, Architecture = Environment.Is64BitOperatingSystem ? "x64" : "x86" };
            Try(() =>
            {
                using (var s = new ManagementObjectSearcher("SELECT Caption, Version, OSArchitecture FROM Win32_OperatingSystem"))
                    foreach (ManagementBaseObject o in s.Get())
                    {
                        p.OsCaption = Convert.ToString(o["Caption"], CultureInfo.InvariantCulture);
                        p.OsBuild = Convert.ToString(o["Version"], CultureInfo.InvariantCulture);
                    }
            });
            Try(() =>
            {
                using (var s = new ManagementObjectSearcher("SELECT PartOfDomain, Domain, Workgroup FROM Win32_ComputerSystem"))
                    foreach (ManagementBaseObject o in s.Get())
                    {
                        p.DomainJoined = o["PartOfDomain"] is bool && (bool)o["PartOfDomain"];
                        p.DomainOrWorkgroup = Convert.ToString(p.DomainJoined ? o["Domain"] : o["Workgroup"], CultureInfo.InvariantCulture);
                    }
            });
            Try(() => p.OsEdition = Value(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID") as string);

            string caption = p.OsCaption ?? "";
            if (caption.Contains("Windows 11")) p.Add("Windows 11", Value(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion") as string, "Microsoft Windows 11", "Win32_OperatingSystem.Caption");
            else if (caption.Contains("Windows 10")) p.Add("Windows 10", Value(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion") as string, "Microsoft Windows 10", "Win32_OperatingSystem.Caption");

            Try(() =>
            {
                const string edge = @"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}";
                var pv = Value(RegistryHive.LocalMachine, edge, "pv") as string;
                if (!string.IsNullOrEmpty(pv)) p.Add("Microsoft Edge", pv, "Microsoft Edge", @"HKLM\" + edge);
            });

            var programs = InstalledPrograms();
            Try(() =>
            {
                var chrome = programs.FirstOrDefault(x => x.Key == "Google Chrome");
                if (chrome.Key != null) p.Add("Google Chrome", chrome.Value, "Google Chrome", @"Uninstall\Google Chrome");
            });
            Try(() =>
            {
                var firefox = programs.FirstOrDefault(x => x.Key.StartsWith("Mozilla Firefox", StringComparison.Ordinal));
                if (firefox.Key != null) p.Add("Mozilla Firefox", firefox.Value, "Mozilla Firefox", @"Uninstall\" + firefox.Key);
            });
            Try(() =>
            {
                const string ndp = @"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full";
                if (Value(RegistryHive.LocalMachine, ndp, "Release") != null)
                    p.Add(".NET Framework 4", Value(RegistryHive.LocalMachine, ndp, "Version") as string, "Microsoft .NET Framework 4.0", @"HKLM\" + ndp);
            });
            Try(() => { if (ServiceExists("WinDefend")) p.Add("Microsoft Defender Antivirus", null, "Microsoft Windows Defender", "service WinDefend"); });
            Try(() => { if (ServiceExists("mpssvc")) p.Add("Windows Defender Firewall", null, "Windows Firewall", "service mpssvc"); });
            return p;
        }

        void Add(string name, string version, string target, string evidence)
        {
            Products.Add(new DetectedProduct { Name = name, Version = version, NcpTarget = target, Evidence = evidence });
        }

        static void Try(Action a)
        {
            try { a(); }
            catch (Exception ex)
            {
                if (ex is OutOfMemoryException || ex is StackOverflowException) throw;
            }
        }

        static object Value(RegistryHive hive, string key, string name)
        {
            using (var b = RegistryKey.OpenBaseKey(hive, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default))
            using (var k = b.OpenSubKey(key))
                return k == null ? null : k.GetValue(name);
        }

        /// <summary>DisplayName → DisplayVersion from the machine (64/32-bit) and current-user Uninstall keys.</summary>
        static List<KeyValuePair<string, string>> InstalledPrograms()
        {
            var list = new List<KeyValuePair<string, string>>();
            var roots = new[]
            {
                new KeyValuePair<RegistryHive, string>(RegistryHive.LocalMachine, Uninstall),
                new KeyValuePair<RegistryHive, string>(RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                new KeyValuePair<RegistryHive, string>(RegistryHive.CurrentUser, Uninstall)
            };
            foreach (var root in roots)
                Try(() =>
                {
                    using (var b = RegistryKey.OpenBaseKey(root.Key, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default))
                    using (var k = b.OpenSubKey(root.Value))
                    {
                        if (k == null) return;
                        foreach (var sub in k.GetSubKeyNames())
                            using (var s = k.OpenSubKey(sub))
                            {
                                var name = s == null ? null : s.GetValue("DisplayName") as string;
                                if (!string.IsNullOrEmpty(name)) list.Add(new KeyValuePair<string, string>(name, s.GetValue("DisplayVersion") as string));
                            }
                    }
                });
            return list;
        }

        static bool ServiceExists(string name)
        {
            return ServiceController.GetServices().Any(s => { using (s) return s.ServiceName.Equals(name, StringComparison.OrdinalIgnoreCase); });
        }
    }
}
