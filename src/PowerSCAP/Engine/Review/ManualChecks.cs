using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using PowerScap.Engine.Reports;
using PowerScap.Engine.Xccdf;

namespace PowerScap.Engine.Review
{
    /// <summary>What a manual check found: a status (decided) or NotChecked with evidence for the reviewer.</summary>
    public class ManualCheckOutcome
    {
        public XccdfResult Status { get; set; }
        public string Evidence { get; set; }

        public static ManualCheckOutcome Decided(XccdfResult status, string evidence) { return new ManualCheckOutcome { Status = status, Evidence = evidence }; }
        public static ManualCheckOutcome Evidence_(string evidence) { return new ManualCheckOutcome { Status = XccdfResult.NotChecked, Evidence = evidence }; }
    }

    /// <summary>
    /// A PowerSCAP native check for a rule the SCAP content leaves manual (design layer 2). Each follows its STIG check
    /// text literally: it decides only where the text states the outcome, and otherwise gathers evidence for the
    /// reviewer. Keyed by STIG ID, which is stable across releases.
    /// </summary>
    public abstract class ManualCheck
    {
        public abstract string[] StigIds { get; }
        public abstract ManualCheckOutcome Check(ManualCheckFacts facts);

        protected static string Missing(ManualCheckFacts f, string what)
        {
            string why;
            return "Could not read " + what + (f.Errors.TryGetValue(what, out why) ? ": " + why : ".");
        }

        protected static string List(IEnumerable<string> items)
        {
            var l = items.ToList();
            return l.Count == 0 ? "(none)" : string.Join("\n", l.Select(x => "  " + x));
        }
    }

    /// <summary>The checks PowerSCAP ships, and how they are applied to a scanned benchmark.</summary>
    public static class ManualCheckLibrary
    {
        public static readonly ManualCheck[] All =
        {
            new WifiDirectAdapters(), new UnusedAccounts(), new LocalAccountsInDomain(), new NonSystemShares(),
            new BackupOperators(), new ApplicationAllowlisting(), new HostedHypervisors(), new FirewallInboundDomainOnly(),
            new OptionalAllowlist("EDGE-00-000004", @"HKLM\SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains"),
            new OptionalAllowlist("EDGE-00-000039", @"HKLM\SOFTWARE\Policies\Microsoft\Edge\PopupsAllowedForUrls"),
            new OptionalAllowlist("EDGE-00-000042", @"HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist"),
            new OptionalAllowlist("EDGE-00-000064", @"HKLM\SOFTWARE\Policies\Microsoft\Edge\AutoplayAllowlist"),
            new OptionalAllowlist("DTBC-0065", @"HKLM\SOFTWARE\Policies\Google\Chrome\AutoplayAllowlist"),
            new AdministratorsMembers()
        };

        public static ManualCheck For(string stigId)
        {
            return All.FirstOrDefault(c => c.StigIds.Contains(stigId ?? "", StringComparer.OrdinalIgnoreCase));
        }

        /// <summary>True when any manual rule of the report has a check (so facts are worth collecting).</summary>
        public static bool AppliesTo(BenchmarkReport report)
        {
            return report.Rules.Any(r => r.IsManual && For(r.StigId) != null);
        }

        /// <summary>Runs the checks on the report's manual rules; SCAP-decided rules are never touched.</summary>
        public static int Apply(BenchmarkReport report, ManualCheckFacts facts, DateTime when)
        {
            int n = 0;
            foreach (var rule in report.Rules.Where(r => r.IsManual))
            {
                var check = For(rule.StigId);
                if (check == null) continue;
                ManualCheckOutcome o;
                try { o = check.Check(facts); }
                catch (Exception e)
                {
                    if (e is OutOfMemoryException) throw;
                    o = ManualCheckOutcome.Evidence_("The PowerSCAP check failed: " + e.Message);
                }
                rule.Review = new RuleReview { Status = o.Status, Source = RuleReview.Script, Author = "PowerSCAP", When = when, Evidence = o.Evidence };
                n++;
            }
            return n;
        }
    }

    /// <summary>WN11-00-000400: "If any Wi-Fi Direct adapters are listed [Get-NetAdapter -InterfaceDescription "Microsoft Wi-Fi Direct*" -IncludeHidden], this is a finding."</summary>
    public class WifiDirectAdapters : ManualCheck
    {
        public override string[] StigIds { get { return new[] { "WN11-00-000400" }; } }
        public override ManualCheckOutcome Check(ManualCheckFacts f)
        {
            if (f.NetworkAdapters == null) return ManualCheckOutcome.Evidence_(Missing(f, "network adapters"));
            var direct = f.NetworkAdapters.Where(a => a != null && a.StartsWith("Microsoft Wi-Fi Direct", StringComparison.OrdinalIgnoreCase)).ToList();
            return direct.Count > 0
                ? ManualCheckOutcome.Decided(XccdfResult.Fail, "Wi-Fi Direct adapters (hidden included):\n" + List(direct))
                : ManualCheckOutcome.Decided(XccdfResult.Pass, "No Wi-Fi Direct adapters (hidden included).");
        }
    }

    /// <summary>WN11-00-000065: enabled local accounts, other than the built-in 500/501/503, not logged on within 35 days.</summary>
    public class UnusedAccounts : ManualCheck
    {
        public override string[] StigIds { get { return new[] { "WN11-00-000065", "WN10-00-000065" }; } }
        public override ManualCheckOutcome Check(ManualCheckFacts f)
        {
            if (f.LocalUsers == null) return ManualCheckOutcome.Evidence_(Missing(f, "local users"));
            var rows = new List<string>();
            var stale = new List<string>();
            foreach (var u in f.LocalUsers)
            {
                string sid = u.Sid == null ? "" : u.Sid.Value;
                bool builtin = sid.EndsWith("-500") || sid.EndsWith("-501") || sid.EndsWith("-503");
                string last = u.LastLogon.HasValue ? u.LastLogon.Value.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) : "Never";
                rows.Add(string.Format("{0}  last logon {1}  {2}{3}", u.Name, last, u.Enabled ? "enabled" : "disabled", builtin ? "  (built-in, excluded)" : ""));
                if (u.Enabled && !builtin && (!u.LastLogon.HasValue || (f.Now - u.LastLogon.Value).TotalDays > 35)) stale.Add(u.Name);
            }
            string evidence = "Local accounts:\n" + List(rows);
            return stale.Count > 0
                ? ManualCheckOutcome.Decided(XccdfResult.Fail, evidence + "\nEnabled and not logged on within 35 days: " + string.Join(", ", stale) +
                    ". Accounts the ISSO documented as required can be answered as Not a Finding.")
                : ManualCheckOutcome.Decided(XccdfResult.Pass, evidence + "\nEvery enabled account logged on within the past 35 days.");
        }
    }

    /// <summary>WN11-00-000085: "For standalone or nondomain-joined systems, this is Not Applicable."</summary>
    public class LocalAccountsInDomain : ManualCheck
    {
        public override string[] StigIds { get { return new[] { "WN11-00-000085", "WN10-00-000085" }; } }
        public override ManualCheckOutcome Check(ManualCheckFacts f)
        {
            if (f.DomainJoined == null) return ManualCheckOutcome.Evidence_(Missing(f, "domain"));
            if (f.DomainJoined == false) return ManualCheckOutcome.Decided(XccdfResult.NotApplicable, "The system is not joined to a domain.");
            if (f.LocalUsers == null) return ManualCheckOutcome.Evidence_(Missing(f, "local users"));
            var admins = new HashSet<string>((f.GroupMembers.ContainsKey(ManualCheckFacts.Administrators) ? f.GroupMembers[ManualCheckFacts.Administrators] : new List<string>())
                .Select(Accounts.BareName), StringComparer.OrdinalIgnoreCase);
            var others = f.LocalUsers.Where(u =>
            {
                string sid = u.Sid == null ? "" : u.Sid.Value;
                bool builtin = sid.EndsWith("-500") || sid.EndsWith("-501") || sid.EndsWith("-503") || sid.EndsWith("-504") ||
                    u.Name.Equals("defaultuser0", StringComparison.OrdinalIgnoreCase);
                return !builtin && !admins.Contains(u.Name);
            }).Select(u => u.Name).ToList();
            return others.Count > 0
                ? ManualCheckOutcome.Decided(XccdfResult.Fail, "Domain-joined; local accounts other than the built-in and local administrator accounts:\n" + List(others))
                : ManualCheckOutcome.Decided(XccdfResult.Pass, "Domain-joined; only built-in and local administrator accounts exist.");
        }
    }

    /// <summary>WN11-00-000060: "If only system-created shares exist on the system, this is NA." Otherwise their permissions need review.</summary>
    public class NonSystemShares : ManualCheck
    {
        public override string[] StigIds { get { return new[] { "WN11-00-000060", "WN10-00-000060" }; } }
        public override ManualCheckOutcome Check(ManualCheckFacts f)
        {
            if (f.Shares == null) return ManualCheckOutcome.Evidence_(Missing(f, "shares"));
            var other = f.Shares.Where(s => !s.IsSystem).ToList();
            if (other.Count == 0)
                return ManualCheckOutcome.Decided(XccdfResult.NotApplicable, "Only system-created shares exist: " +
                    (f.Shares.Count == 0 ? "(none; the Server service may be stopped)" : string.Join(", ", f.Shares.Select(s => s.Name))) + ".");
            return ManualCheckOutcome.Evidence_("Shares that are not system-created (review their share and NTFS permissions):\n" +
                List(other.Select(s => s.Name + "  " + s.Path)));
        }
    }

    /// <summary>WN11-00-000075: "If the group contains no accounts, this is not a finding." Otherwise the members need review.</summary>
    public class BackupOperators : ManualCheck
    {
        public override string[] StigIds { get { return new[] { "WN11-00-000075", "WN10-00-000075" }; } }
        public override ManualCheckOutcome Check(ManualCheckFacts f)
        {
            IList<string> members;
            if (!f.GroupMembers.TryGetValue(ManualCheckFacts.BackupOperators, out members)) return ManualCheckOutcome.Evidence_(Missing(f, "group " + ManualCheckFacts.BackupOperators));
            return members.Count == 0
                ? ManualCheckOutcome.Decided(XccdfResult.Pass, "The Backup Operators group has no members.")
                : ManualCheckOutcome.Evidence_("Backup Operators members (each must be specifically for backup functions):\n" + List(members));
        }
    }

    /// <summary>WN11-00-000035: "If an application allowlisting program is not in use on the system, this is a finding."</summary>
    public class ApplicationAllowlisting : ManualCheck
    {
        public override string[] StigIds { get { return new[] { "WN11-00-000035", "WN10-00-000035" }; } }
        public override ManualCheckOutcome Check(ManualCheckFacts f)
        {
            if (f.AppLockerEnforced == null) return ManualCheckOutcome.Evidence_(Missing(f, "AppLocker"));
            if (f.WdacUserModeEnforced == null) return ManualCheckOutcome.Evidence_(Missing(f, "Device Guard"));
            string evidence = "AppLocker enforced collections: " + (f.AppLockerEnforced.Count == 0 ? "none" : string.Join(", ", f.AppLockerEnforced)) +
                "\nWindows Defender Application Control user-mode policy enforced: " + (f.WdacUserModeEnforced.Value ? "yes" : "no");
            if (f.AppLockerEnforced.Count == 0 && !f.WdacUserModeEnforced.Value)
                return ManualCheckOutcome.Decided(XccdfResult.Fail, evidence + "\nNo application allowlisting program is in use.");
            return ManualCheckOutcome.Evidence_(evidence + "\nVerify the policy is deny-all, permit-by-exception and covers packaged apps.");
        }
    }

    /// <summary>WN11-00-000080: applies only "if a hosted hypervisor (Hyper-V, VMware Workstation, etc.) is installed".</summary>
    public class HostedHypervisors : ManualCheck
    {
        public override string[] StigIds { get { return new[] { "WN11-00-000080", "WN10-00-000080" }; } }
        public override ManualCheckOutcome Check(ManualCheckFacts f)
        {
            if (f.Hypervisors == null) return ManualCheckOutcome.Evidence_(Missing(f, "hypervisors"));
            if (f.Hypervisors.Count == 0) return ManualCheckOutcome.Decided(XccdfResult.NotApplicable, "No hosted hypervisor (Hyper-V, VMware Workstation or Player, VirtualBox) is installed.");
            IList<string> hv;
            f.GroupMembers.TryGetValue(ManualCheckFacts.HyperVAdministrators, out hv);
            return ManualCheckOutcome.Evidence_("Hosted hypervisors installed:\n" + List(f.Hypervisors) +
                (hv == null ? "" : "\nHyper-V Administrators members:\n" + List(hv)) +
                "\nVerify only authorized, documented accounts can create or run virtual machines.");
        }
    }

    /// <summary>WNFWA-000100: "This requirement is NA for servers and non domain workstations."</summary>
    public class FirewallInboundDomainOnly : ManualCheck
    {
        public override string[] StigIds { get { return new[] { "WNFWA-000100" }; } }
        public override ManualCheckOutcome Check(ManualCheckFacts f)
        {
            if (f.IsServer == null) return ManualCheckOutcome.Evidence_(Missing(f, "product type"));
            if (f.IsServer.Value) return ManualCheckOutcome.Decided(XccdfResult.NotApplicable, "The system is a server.");
            if (f.DomainJoined == null) return ManualCheckOutcome.Evidence_(Missing(f, "domain"));
            if (!f.DomainJoined.Value) return ManualCheckOutcome.Decided(XccdfResult.NotApplicable, "The system is a workstation that is not joined to a domain.");
            return ManualCheckOutcome.Evidence_("Domain workstation: review inbound firewall exceptions for authorized management hosts.");
        }
    }

    /// <summary>
    /// Optional allowlists ("This requirement ... is not required; this is optional"; titled "... if used"): not
    /// configured is Not Applicable; a configured list needs a reviewer to confirm it is administrator-approved.
    /// </summary>
    public class OptionalAllowlist : ManualCheck
    {
        readonly string stigId, key;
        public OptionalAllowlist(string stigId, string key) { this.stigId = stigId; this.key = key; }
        public override string[] StigIds { get { return new[] { stigId }; } }
        public override ManualCheckOutcome Check(ManualCheckFacts f)
        {
            IList<string> values;
            if (!f.PolicyLists.TryGetValue(key, out values)) return ManualCheckOutcome.Evidence_(Missing(f, "policy " + key.Substring(5)));
            if (values == null || values.Count == 0)
                return ManualCheckOutcome.Decided(XccdfResult.NotApplicable, key + " has no entries: the optional allowlist is not used.");
            return ManualCheckOutcome.Evidence_(key + " is configured:\n" + List(values) + "\nVerify every entry is administrator-approved.");
        }
    }

    /// <summary>WN11-00-000070: evidence only; whether each member may administer the system is a person's call.</summary>
    public class AdministratorsMembers : ManualCheck
    {
        public override string[] StigIds { get { return new[] { "WN11-00-000070", "WN10-00-000070" }; } }
        public override ManualCheckOutcome Check(ManualCheckFacts f)
        {
            IList<string> members;
            if (!f.GroupMembers.TryGetValue(ManualCheckFacts.Administrators, out members)) return ManualCheckOutcome.Evidence_(Missing(f, "group " + ManualCheckFacts.Administrators));
            return ManualCheckOutcome.Evidence_("Administrators members:\n" + List(members));
        }
    }

    static class Accounts
    {
        public static string BareName(string qualified)
        {
            int i = (qualified ?? "").LastIndexOf('\\');
            return i >= 0 ? qualified.Substring(i + 1) : qualified ?? "";
        }
    }
}
