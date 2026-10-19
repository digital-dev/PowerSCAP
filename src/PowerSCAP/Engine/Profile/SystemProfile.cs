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
            string osTarget = OperatingSystemTarget(caption);
            if (osTarget != null)
            {
                string release = Value(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion") as string;
                string name = osTarget.StartsWith("Microsoft Windows 1", StringComparison.Ordinal) ? osTarget.Substring(10) : caption.Replace("Microsoft ", "").Trim();
                p.Add(name, release, osTarget, "Win32_OperatingSystem.Caption");
            }

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
                // The sync client installs per machine or per user; NCP files its STIG under the 2016 business name.
                const string onedrive = @"SOFTWARE\Microsoft\OneDrive";
                var machine = Value(RegistryHive.LocalMachine, onedrive, "Version") as string;
                var user = Value(RegistryHive.CurrentUser, onedrive, "Version") as string;
                if (!string.IsNullOrEmpty(machine) || !string.IsNullOrEmpty(user))
                    p.Add("Microsoft OneDrive", machine ?? user, "Microsoft One Drive for Business 2016", (machine != null ? @"HKLM\" : @"HKCU\") + onedrive);
            });
            Try(() =>
            {
                const string ndp = @"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full";
                if (Value(RegistryHive.LocalMachine, ndp, "Release") != null)
                    p.Add(".NET Framework 4", Value(RegistryHive.LocalMachine, ndp, "Version") as string, "Microsoft .NET Framework 4.0", @"HKLM\" + ndp);
            });
            Try(() => { if (ServiceExists("WinDefend")) p.Add("Microsoft Defender Antivirus", null, "Microsoft Windows Defender", "service WinDefend"); });
            Try(() => { if (ServiceExists("mpssvc")) p.Add("Windows Defender Firewall", null, "Windows Firewall", "service mpssvc"); });

            Try(() =>
            {
                const string c2r = @"SOFTWARE\Microsoft\Office\ClickToRun\Configuration";
                string ids = Value(RegistryHive.LocalMachine, c2r, "ProductReleaseIds") as string;
                string target = OfficeTarget(ids);
                if (target != null)
                    p.Add("Microsoft 365 Apps (" + ids + ")", Value(RegistryHive.LocalMachine, c2r, "VersionToReport") as string, target, @"HKLM\" + c2r);
            });
            Try(() =>
            {
                foreach (var root in new[] { @"SOFTWARE\Microsoft\Office\15.0\Common\InstallRoot", @"SOFTWARE\WOW6432Node\Microsoft\Office\15.0\Common\InstallRoot" })
                    if (Value(RegistryHive.LocalMachine, root, "Path") != null) { p.Add("Microsoft Office 2013", "15.0", "Microsoft Office 2013", @"HKLM\" + root); break; }
            });
            Try(() =>
            {
                const string inetstp = @"SOFTWARE\Microsoft\InetStp";
                object major = Value(RegistryHive.LocalMachine, inetstp, "MajorVersion"), minor = Value(RegistryHive.LocalMachine, inetstp, "MinorVersion");
                if (major is int && ServiceExists("W3SVC"))
                {
                    string target = IisTarget((int)major, minor is int ? (int)minor : 0);
                    if (target != null) p.Add("IIS", major + "." + (minor ?? 0), target, @"HKLM\" + inetstp + ", service W3SVC");
                }
            });
            Try(() =>
            {
                const string names = @"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL";
                using (var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default))
                using (var k = b.OpenSubKey(names))
                {
                    if (k == null) return;
                    foreach (var instance in k.GetValueNames())
                    {
                        string setup = @"SOFTWARE\Microsoft\Microsoft SQL Server\" + k.GetValue(instance) + @"\Setup";
                        string version = Value(RegistryHive.LocalMachine, setup, "Version") as string;
                        string target = SqlServerTarget(version);
                        if (target != null && !p.Products.Any(x => x.NcpTarget == target))
                            p.Add("SQL Server (" + instance + ")", version, target, @"HKLM\" + setup);
                    }
                }
            });
            Try(() =>
            {
                const string exchange = @"SOFTWARE\Microsoft\ExchangeServer\v15\Setup";
                object major = Value(RegistryHive.LocalMachine, exchange, "MsiProductMajor"), minor = Value(RegistryHive.LocalMachine, exchange, "MsiProductMinor");
                string target = major is int && minor is int ? ExchangeTarget((int)major, (int)minor) : null;
                if (target != null) p.Add("Exchange Server", major + "." + minor, target, @"HKLM\" + exchange);
            });
            Try(() => { if (ServiceExists("NTDS")) p.Add("Active Directory domain controller", null, "Microsoft Active Directory", "service NTDS"); });
            Try(() =>
            {
                // IE 11 is retired on Windows 11 (iexplore.exe remains but opens Edge); its STIG applies to Windows 10 and Server.
                if (osTarget == null || osTarget == "Microsoft Windows 11") return;
                string ie = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Internet Explorer\iexplore.exe");
                if (!System.IO.File.Exists(ie)) return;
                var v = System.Diagnostics.FileVersionInfo.GetVersionInfo(ie);
                if (v.FileMajorPart == 11) p.Add("Internet Explorer 11", v.ProductVersion, "Microsoft Internet Explorer 11", ie);
            });
            Try(() =>
            {
                foreach (var d in ProductsFromPrograms(programs))
                    if (!p.Products.Any(x => x.NcpTarget == d.NcpTarget)) p.Products.Add(d);
                if (!p.Products.Any(x => x.NcpTarget == "Apache HTTP Server 2.4.0") && ServiceExists("Apache2.4"))
                    p.Add("Apache HTTP Server 2.4", null, "Apache HTTP Server 2.4.0", "service Apache2.4");
            });
            return p;
        }

        /// <summary>
        /// The NCP target for a Windows caption ("Microsoft Windows Server 2022 Datacenter" -> "Microsoft Windows Server 2022"),
        /// spelled as NCP spells it; null for systems with no Windows SCAP content on NCP.
        /// </summary>
        public static string OperatingSystemTarget(string caption)
        {
            if (string.IsNullOrEmpty(caption)) return null;
            if (caption.Contains("Windows 11")) return "Microsoft Windows 11";
            if (caption.Contains("Windows 10")) return "Microsoft Windows 10";
            var m = System.Text.RegularExpressions.Regex.Match(caption, @"Windows Server (\d{4})( R2)?\b");
            if (!m.Success) return null;
            string year = m.Groups[1].Value, r2 = m.Groups[2].Success ? " R2" : "";
            switch (year + r2)
            {
                case "2025": return "Microsoft Windows server 2025";
                case "2022":
                case "2019":
                case "2016":
                case "2012":
                case "2012 R2":
                case "2008":
                case "2008 R2": return "Microsoft Windows Server " + year + r2;
                default: return null;
            }
        }

        /// <summary>
        /// The Click-to-Run products the "Microsoft Office 365 ProPlus" STIG applies to, using the content's own platform
        /// test (ProductReleaseIds pattern ".*O365ProPlus.*|.*ProPlus20.+"): Microsoft 365 Apps for enterprise and
        /// Office Professional Plus 2019/2021/2024. Home, Personal and Business editions are not covered; the
        /// benchmark reports every rule not applicable on them.
        /// </summary>
        public static string OfficeTarget(string productReleaseIds)
        {
            if (string.IsNullOrEmpty(productReleaseIds)) return null;
            return System.Text.RegularExpressions.Regex.IsMatch(productReleaseIds, "O365ProPlus|ProPlus20.")
                ? "Microsoft Office 365 ProPlus" : null;
        }

        public static string IisTarget(int major, int minor)
        {
            if (major == 10) return "Microsoft IIS 10";
            if (major == 8 && minor == 5) return "IIS 8.5";
            return null;
        }

        /// <summary>SQL Server by its Setup version: 13.x is 2016, 16.x is 2022 (the releases with NCP SCAP content).</summary>
        public static string SqlServerTarget(string version)
        {
            if (string.IsNullOrEmpty(version)) return null;
            if (version.StartsWith("13.", StringComparison.Ordinal)) return "Microsoft SQL Server 2016";
            if (version.StartsWith("16.", StringComparison.Ordinal)) return "Microsoft SQL Server 2022";
            return null;
        }

        /// <summary>Exchange 2019 is product version 15.2.</summary>
        public static string ExchangeTarget(int major, int minor)
        {
            return major == 15 && minor == 2 ? "Microsoft Exchange Server 2019" : null;
        }

        /// <summary>Products recognized by their Programs and Features name (DisplayName, DisplayVersion pairs).</summary>
        public static IList<DetectedProduct> ProductsFromPrograms(IEnumerable<KeyValuePair<string, string>> programs)
        {
            var found = new List<DetectedProduct>();
            Action<string, string, string> add = (name, version, target) =>
            {
                if (!found.Any(x => x.NcpTarget == target))
                    found.Add(new DetectedProduct { Name = name, Version = version, NcpTarget = target, Evidence = @"Uninstall\" + name });
            };
            foreach (var pr in programs)
            {
                string n = pr.Key ?? "";
                // "Adobe Acrobat Reader DC", "Adobe Acrobat Reader - 64-bit"; the unified installer is "Adobe Acrobat (64-bit)" or "Adobe Acrobat DC".
                if (n.StartsWith("Adobe Acrobat Reader", StringComparison.OrdinalIgnoreCase)) add(n, pr.Value, "Adobe Acrobat Reader");
                else if (System.Text.RegularExpressions.Regex.IsMatch(n, @"^Adobe Acrobat( Pro)?( DC)?( \(64-bit\))?$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                    add(n, pr.Value, "Adobe Acrobat Pro DC Continuous Track");
                else if (n.StartsWith("Apache HTTP Server 2.4", StringComparison.OrdinalIgnoreCase)) add(n, pr.Value, "Apache HTTP Server 2.4.0");
                else if (n.StartsWith("McAfee VirusScan Enterprise", StringComparison.OrdinalIgnoreCase) && (pr.Value ?? "").StartsWith("8.8", StringComparison.Ordinal))
                    add(n, pr.Value, "Mcafee Virusscan Enterprise 8.8.0");
            }
            return found;
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
