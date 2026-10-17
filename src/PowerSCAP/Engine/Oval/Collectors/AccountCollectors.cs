using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using PowerScap.Engine.Native;

namespace PowerScap.Engine.Oval
{
    /// <summary>Name/SID helpers shared by account collectors (local machine only).</summary>
    public static class Accounts
    {
        public static string NameOf(SecurityIdentifier sid)
        {
            try { return ((NTAccount)sid.Translate(typeof(NTAccount))).Value; }
            catch (Exception) { return null; }
        }

        public static SecurityIdentifier SidOf(string name)
        {
            try { return (SecurityIdentifier)new NTAccount(name).Translate(typeof(SecurityIdentifier)); }
            catch (Exception) { return null; }
        }

        public static SecurityIdentifier ParseSid(string text)
        {
            try { return new SecurityIdentifier(text); }
            catch (Exception) { return null; }
        }

        public static string Domain(string qualified)
        {
            int i = qualified.IndexOf('\\');
            return i < 0 ? string.Empty : qualified.Substring(0, i);
        }

        /// <summary>
        /// Trustee name as OVAL interpreters report it: the domain is dropped for BUILTIN, NT AUTHORITY and the
        /// local computer, and kept otherwise (SCC: "RESTRICTED SERVICES\PrintSpoolerService").
        /// </summary>
        public static string Bare(string qualified)
        {
            int i = qualified.IndexOf('\\');
            if (i < 0) return qualified;
            string domain = qualified.Substring(0, i);
            if (domain.Equals("BUILTIN", StringComparison.OrdinalIgnoreCase) || domain.Equals("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) ||
                domain.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                return qualified.Substring(i + 1);
            return qualified;
        }

        /// <summary>Accounts worth enumerating for pattern matches: local users, local groups, rights holders, well-known SIDs.</summary>
        public static IList<SecurityIdentifier> Candidates(bool includeRightHolders, IList<string> messages)
        {
            var set = new Dictionary<string, SecurityIdentifier>();
            Action<SecurityIdentifier> add = s => { if (s != null) set[s.Value] = s; };
            foreach (var u in Netapi.GetLocalUsers()) add(u.Sid);
            foreach (var g in Netapi.GetLocalGroups()) add(SidOf(g));
            foreach (var wk in new[] { "S-1-1-0", "S-1-5-11", "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-6", "S-1-5-4", "S-1-5-2", "S-1-5-113", "S-1-5-114" })
                add(ParseSid(wk));
            if (includeRightHolders)
            {
                foreach (var right in AccessTokenCollector.Rights)
                {
                    try { foreach (var s in Advapi.GetAccountsWithRight(right.Key)) add(s); }
                    catch (Exception ex) { messages.Add("Could not enumerate holders of " + right.Key + ": " + ex.Message); break; }
                }
            }
            return set.Values.ToList();
        }
    }

    /// <summary>windows-def sid_object (by trustee_name) → sid_item.</summary>
    public class SidCollector : ICollector
    {
        public string ObjectType { get { return "sid_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion nameC;
            spec.Entities.TryGetValue("trustee_name", out nameC);
            IList<string> literal = CollectorUtil.LiteralValues(nameC);
            var sids = literal != null
                ? literal.Select(Accounts.SidOf).Where(s => s != null)
                : Accounts.Candidates(false, r.Messages).Where(s => { string n = Accounts.NameOf(s); return n != null && CollectorUtil.SatisfiesIgnoreCase(nameC, n); });
            foreach (var sid in sids) r.Items.Add(SidItem(ctx, "sid_item", sid));
            if (r.Items.Count == 0) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }

        public static OvalItem SidItem(OvalContext ctx, string itemType, SecurityIdentifier sid)
        {
            string name = Accounts.NameOf(sid) ?? sid.Value;
            var item = new OvalItem(ctx.NextItemId(), itemType);
            item.Add("trustee_sid", sid.Value).Add("trustee_name", name).Add("trustee_domain", Accounts.Domain(name));
            return item;
        }
    }

    /// <summary>windows-def sid_sid_object (by trustee_sid) → sid_sid_item.</summary>
    public class SidSidCollector : ICollector
    {
        public string ObjectType { get { return "sid_sid_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion sidC;
            spec.Entities.TryGetValue("trustee_sid", out sidC);
            IList<string> literal = CollectorUtil.LiteralValues(sidC);
            var sids = literal != null
                ? literal.Select(Accounts.ParseSid).Where(s => s != null && Accounts.NameOf(s) != null)
                : Accounts.Candidates(false, r.Messages).Where(s => CollectorUtil.Satisfies(sidC, s.Value));
            foreach (var sid in sids) r.Items.Add(SidCollector.SidItem(ctx, "sid_sid_item", sid));
            if (r.Items.Count == 0) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }
    }

    /// <summary>windows-def user_object → user_item; user_sid55_object → user_sid_item.</summary>
    public class UserCollector : ICollector
    {
        readonly bool bySid;
        public UserCollector(bool bySid) { this.bySid = bySid; }
        public string ObjectType { get { return bySid ? "user_sid55_object" : "user_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion c;
            spec.Entities.TryGetValue(bySid ? "user_sid" : "user", out c);
            foreach (var u in Netapi.GetLocalUsers())
            {
                bool match = bySid
                    ? u.Sid != null && CollectorUtil.Satisfies(c, u.Sid.Value)
                    : CollectorUtil.SatisfiesIgnoreCase(c, u.Name) || CollectorUtil.SatisfiesIgnoreCase(c, Environment.MachineName + "\\" + u.Name);
                if (!match) continue;
                var item = new OvalItem(ctx.NextItemId(), bySid ? "user_sid_item" : "user_item");
                if (bySid) item.Add("user_sid", u.Sid.Value); else item.Add("user", u.Name);
                item.Add("enabled", u.Enabled ? "1" : "0", "boolean");
                var groups = Netapi.GetUserLocalGroups(u.Name);
                if (groups.Count == 0) item.Entities.Add(OvalEntity.Missing(bySid ? "group_sid" : "group"));
                foreach (var g in groups)
                {
                    if (!bySid) { item.Add("group", g); continue; }
                    var gs = Accounts.SidOf(g);
                    if (gs != null) item.Add("group_sid", gs.Value);
                }
                r.Items.Add(item);
            }
            if (r.Items.Count == 0) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }
    }

    /// <summary>windows-def group_object → group_item; group_sid_object → group_sid_item.</summary>
    public class GroupCollector : ICollector
    {
        readonly bool bySid;
        public GroupCollector(bool bySid) { this.bySid = bySid; }
        public string ObjectType { get { return bySid ? "group_sid_object" : "group_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion c;
            spec.Entities.TryGetValue(bySid ? "group_sid" : "group", out c);
            foreach (var g in Netapi.GetLocalGroups())
            {
                var gsid = Accounts.SidOf(g);
                bool match = bySid ? gsid != null && CollectorUtil.Satisfies(c, gsid.Value) : CollectorUtil.SatisfiesIgnoreCase(c, g);
                if (!match) continue;
                var item = new OvalItem(ctx.NextItemId(), bySid ? "group_sid_item" : "group_item");
                if (bySid) item.Add("group_sid", gsid.Value); else item.Add("group", g);
                var members = Netapi.GetGroupMembers(g);
                var users = members.Where(m => !m.IsGroup).ToList();
                var subgroups = members.Where(m => m.IsGroup).ToList();
                string userName = bySid ? "user_sid" : "user", subName = bySid ? "subgroup_sid" : "subgroup";
                if (users.Count == 0) item.Entities.Add(OvalEntity.Missing(userName));
                foreach (var m in users) item.Add(userName, bySid ? m.Sid.Value : m.Name);
                if (subgroups.Count == 0) item.Entities.Add(OvalEntity.Missing(subName));
                foreach (var m in subgroups) item.Add(subName, bySid ? m.Sid.Value : m.Name);
                r.Items.Add(item);
            }
            if (r.Items.Count == 0) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }
    }

    /// <summary>windows-def accesstoken_object → accesstoken_item (one boolean entity per right/privilege).</summary>
    public class AccessTokenCollector : ICollector
    {
        public string ObjectType { get { return "accesstoken_object"; } }

        /// <summary>LSA right name → OVAL entity name.</summary>
        public static readonly Dictionary<string, string> Rights = new[]
        {
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege",
            "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege",
            "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege",
            "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege",
            "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege",
            "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege", "SeDelegateSessionUserImpersonatePrivilege",
            "SeBatchLogonRight", "SeInteractiveLogonRight", "SeNetworkLogonRight", "SeRemoteInteractiveLogonRight",
            "SeServiceLogonRight", "SeDenyBatchLogonRight", "SeDenyInteractiveLogonRight", "SeDenyNetworkLogonRight",
            "SeDenyRemoteInteractiveLogonRight", "SeDenyServiceLogonRight"
        }.ToDictionary(n => n, n => n.ToLowerInvariant(), StringComparer.OrdinalIgnoreCase);

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion pc;
            spec.Entities.TryGetValue("security_principle", out pc);
            bool includeGroup = spec.Behavior("include_group", "true") != "false";

            IList<string> literal = CollectorUtil.LiteralValues(pc);
            var principals = new List<KeyValuePair<string, SecurityIdentifier>>();
            if (literal != null)
            {
                foreach (var name in literal)
                {
                    var sid = Accounts.SidOf(name) ?? Accounts.ParseSid(name);
                    if (sid != null) principals.Add(new KeyValuePair<string, SecurityIdentifier>(name, sid));
                }
            }
            else
            {
                foreach (var sid in Accounts.Candidates(true, r.Messages))
                {
                    string name = Accounts.NameOf(sid) ?? sid.Value;
                    if (CollectorUtil.SatisfiesIgnoreCase(pc, name)) principals.Add(new KeyValuePair<string, SecurityIdentifier>(name, sid));
                }
            }

            var users = Netapi.GetLocalUsers();
            foreach (var p in principals)
            {
                var held = new HashSet<string>(Advapi.GetAccountRights(p.Value), StringComparer.OrdinalIgnoreCase);
                var user = users.FirstOrDefault(u => u.Sid != null && u.Sid.Equals(p.Value));
                if (includeGroup && user != null)
                {
                    var groupSids = Netapi.GetUserLocalGroups(user.Name).Select(Accounts.SidOf).Where(s => s != null).ToList();
                    groupSids.Add(new SecurityIdentifier("S-1-1-0"));
                    groupSids.Add(new SecurityIdentifier("S-1-5-11"));
                    foreach (var gs in groupSids) foreach (var right in Advapi.GetAccountRights(gs)) held.Add(right);
                }
                var item = new OvalItem(ctx.NextItemId(), "accesstoken_item");
                item.Add("security_principle", p.Key);
                foreach (var right in Rights) item.Add(right.Value, held.Contains(right.Key) ? "1" : "0", "boolean");
                r.Items.Add(item);
            }
            if (r.Items.Count == 0 && r.Flag == CollectedFlag.Complete) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }
    }
}
