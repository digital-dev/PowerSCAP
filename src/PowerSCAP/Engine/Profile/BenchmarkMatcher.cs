using System;
using System.Collections.Generic;
using System.Linq;
using PowerScap.Engine.Ncp;

namespace PowerScap.Engine.Profile
{
    public class BenchmarkMatch
    {
        public NcpChecklist Checklist { get; set; }
        public NcpResource Resource { get; set; }
        public DetectedProduct Product { get; set; }

        public override string ToString() { return Checklist.Name + " (for " + Product.Name + ")"; }
    }

    /// <summary>
    /// Pre-selects the NCP checklists for the detected products (target name equality). A convenience only:
    /// the content's own CPE applicability still decides at scan time.
    /// </summary>
    public static class BenchmarkMatcher
    {
        /// <summary>
        /// NCP targets that name an operating system ("Microsoft Windows 11", "Microsoft Windows Server 2008"),
        /// as opposed to components such as "Microsoft Windows Defender" or "Windows Firewall".
        /// </summary>
        static readonly System.Text.RegularExpressions.Regex OsTarget = new System.Text.RegularExpressions.Regex(
            @"^(Microsoft )?Windows (\d[\d.]*|Server|XP|Vista|NT|Me|2000|Millennium)\b|linux|red hat|rhel|ubuntu|suse|macos|mac os|solaris|aix|hp-ux|oracle linux|centos|debian",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        public static bool IsOperatingSystem(string target)
        {
            return !string.IsNullOrEmpty(target) && OsTarget.IsMatch(target);
        }

        public static IList<BenchmarkMatch> Match(SystemProfile profile, IList<NcpChecklist> catalog)
        {
            var result = new List<BenchmarkMatch>();
            foreach (var c in catalog)
            {
                var product = ProductFor(profile, c.Targets);
                if (product == null) continue;
                var resource = NcpClient.PickScapResource(c);
                if (resource == null) continue;
                result.Add(new BenchmarkMatch { Checklist = c, Resource = resource, Product = product });
            }
            return result.OrderBy(m => m.Checklist.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>The detected product a checklist with these NCP targets is for, or null.</summary>
        public static DetectedProduct ProductFor(SystemProfile profile, IList<string> targets)
        {
            if (profile == null || targets == null) return null;
            var hostOs = new HashSet<string>(profile.Products.Where(p => IsOperatingSystem(p.NcpTarget)).Select(p => p.NcpTarget), StringComparer.OrdinalIgnoreCase);
            // NCP target lists are loose: the Windows 2008 STIG lists "Microsoft Windows Defender". A checklist
            // that targets an operating system is for that operating system only.
            var osTargets = targets.Where(IsOperatingSystem).ToList();
            if (osTargets.Count > 0 && !osTargets.Any(hostOs.Contains)) return null;
            return profile.Products.FirstOrDefault(p => targets.Any(t => string.Equals(t, p.NcpTarget, StringComparison.OrdinalIgnoreCase)));
        }
    }
}
