using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace PowerScap.Engine.Native
{
    public class LocalGroupMember
    {
        public SecurityIdentifier Sid { get; set; }
        public string Name { get; set; }       // DOMAIN\name
        public bool IsGroup { get; set; }
    }

    public class LocalUser
    {
        public string Name { get; set; }
        public bool Enabled { get; set; }
        public SecurityIdentifier Sid { get; set; }
        /// <summary>Last interactive logon recorded on this machine; null when the account never logged on.</summary>
        public DateTime? LastLogon { get; set; }
    }

    public class PasswordPolicy
    {
        public long MinPasswordLength, MaxPasswordAge, MinPasswordAge, PasswordHistoryLength, ForceLogoff;
        public long LockoutDuration, LockoutObservationWindow, LockoutThreshold;
        public bool? Complexity, ReversibleEncryption;
    }

    /// <summary>NetAPI (accounts, groups, user modals) and SAM password properties for the local machine.</summary>
    public static class Netapi
    {
        [StructLayout(LayoutKind.Sequential)]
        struct USER_MODALS_INFO_0 { public uint min_passwd_len, max_passwd_age, min_passwd_age, force_logoff, password_hist_len; }
        [StructLayout(LayoutKind.Sequential)]
        struct USER_MODALS_INFO_3 { public uint lockout_duration, lockout_observation_window, lockout_threshold; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct USER_INFO_1 { public string name, password; public uint password_age, priv; public string home_dir, comment; public uint flags; public string script_path; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct USER_INFO_2
        {
            public string name, password; public uint password_age, priv; public string home_dir, comment; public uint flags; public string script_path;
            public uint auth_flags; public string full_name, usr_comment, parms, workstations;
            public uint last_logon, last_logoff, acct_expires, max_storage, units_per_week; public IntPtr logon_hours;
            public uint bad_pw_count, num_logons; public string logon_server; public uint country_code, code_page;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct LOCALGROUP_INFO_0 { public string name; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct LOCALGROUP_USERS_INFO_0 { public string name; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct LOCALGROUP_MEMBERS_INFO_2 { public IntPtr sid; public int sidusage; public string domainandname; }
        [StructLayout(LayoutKind.Sequential)]
        struct DOMAIN_PASSWORD_INFORMATION { public ushort MinPasswordLength, PasswordHistoryLength; public uint PasswordProperties; public long MaxPasswordAge, MinPasswordAge; }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserModalsGet(string server, int level, out IntPtr buffer);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserEnum(string server, int level, int filter, out IntPtr buffer, int prefmax, out int read, out int total, ref int resume);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupEnum(string server, int level, out IntPtr buffer, int prefmax, out int read, out int total, ref IntPtr resume);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupGetMembers(string server, string group, int level, out IntPtr buffer, int prefmax, out int read, out int total, ref IntPtr resume);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserGetLocalGroups(string server, string user, int level, int flags, out IntPtr buffer, int prefmax, out int read, out int total);
        [DllImport("netapi32.dll")]
        static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("samlib.dll")]
        static extern uint SamConnect(IntPtr serverName, out IntPtr server, uint access, IntPtr objectAttributes);
        [DllImport("samlib.dll")]
        static extern uint SamOpenDomain(IntPtr server, uint access, byte[] domainSid, out IntPtr domain);
        [DllImport("samlib.dll")]
        static extern uint SamQueryInformationDomain(IntPtr domain, int infoClass, out IntPtr buffer);
        [DllImport("samlib.dll")]
        static extern uint SamFreeMemory(IntPtr buffer);
        [DllImport("samlib.dll")]
        static extern uint SamCloseHandle(IntPtr handle);

        const int MAX_PREFERRED_LENGTH = -1;
        const uint TIMEQ_FOREVER = 0xFFFFFFFF;
        const int FILTER_NORMAL_ACCOUNT = 2;
        const int LG_INCLUDE_INDIRECT = 1;
        const uint UF_ACCOUNTDISABLE = 0x2;

        static void Check(int status)
        {
            if (status != 0) throw new Win32Exception(status);
        }

        static long Seconds(uint value)
        {
            return value == TIMEQ_FOREVER ? -1L : (long)value;
        }

        static IEnumerable<T> Read<T>(IntPtr buffer, int count)
        {
            int size = Marshal.SizeOf(typeof(T));
            for (int i = 0; i < count; i++)
                yield return (T)Marshal.PtrToStructure(new IntPtr(buffer.ToInt64() + i * size), typeof(T));
        }

        public static PasswordPolicy GetPasswordPolicy()
        {
            var p = new PasswordPolicy();
            IntPtr buf;
            Check(NetUserModalsGet(null, 0, out buf));
            try
            {
                var m0 = (USER_MODALS_INFO_0)Marshal.PtrToStructure(buf, typeof(USER_MODALS_INFO_0));
                p.MinPasswordLength = m0.min_passwd_len;
                p.MaxPasswordAge = Seconds(m0.max_passwd_age);
                p.MinPasswordAge = Seconds(m0.min_passwd_age);
                p.ForceLogoff = Seconds(m0.force_logoff);
                p.PasswordHistoryLength = m0.password_hist_len;
            }
            finally { NetApiBufferFree(buf); }

            Check(NetUserModalsGet(null, 3, out buf));
            try
            {
                var m3 = (USER_MODALS_INFO_3)Marshal.PtrToStructure(buf, typeof(USER_MODALS_INFO_3));
                p.LockoutDuration = Seconds(m3.lockout_duration);
                p.LockoutObservationWindow = Seconds(m3.lockout_observation_window);
                p.LockoutThreshold = m3.lockout_threshold;
            }
            finally { NetApiBufferFree(buf); }

            uint props;
            if (TryGetPasswordProperties(out props))
            {
                p.Complexity = (props & 0x1) != 0;
                p.ReversibleEncryption = (props & 0x10) != 0;
            }
            return p;
        }

        /// <summary>DOMAIN_PASSWORD_INFORMATION.PasswordProperties of the local account domain.</summary>
        static bool TryGetPasswordProperties(out uint properties)
        {
            properties = 0;
            // The account domain SID is the prefix of every local account SID (Administrator/Guest always exist).
            SecurityIdentifier domainSid = null;
            foreach (var u in GetLocalUsers())
                if (u.Sid != null && u.Sid.AccountDomainSid != null) { domainSid = u.Sid.AccountDomainSid; break; }
            if (domainSid == null) return false;
            var sidBytes = new byte[domainSid.BinaryLength];
            domainSid.GetBinaryForm(sidBytes, 0);

            IntPtr server = IntPtr.Zero, domain = IntPtr.Zero, info = IntPtr.Zero;
            try
            {
                if (SamConnect(IntPtr.Zero, out server, 0x1 | 0x20, IntPtr.Zero) != 0) return false;
                if (SamOpenDomain(server, 0x1, sidBytes, out domain) != 0) return false;
                if (SamQueryInformationDomain(domain, 1, out info) != 0) return false;
                var dpi = (DOMAIN_PASSWORD_INFORMATION)Marshal.PtrToStructure(info, typeof(DOMAIN_PASSWORD_INFORMATION));
                properties = dpi.PasswordProperties;
                return true;
            }
            finally
            {
                if (info != IntPtr.Zero) SamFreeMemory(info);
                if (domain != IntPtr.Zero) SamCloseHandle(domain);
                if (server != IntPtr.Zero) SamCloseHandle(server);
            }
        }

        public static IList<LocalUser> GetLocalUsers()
        {
            var users = new List<LocalUser>();
            IntPtr buf;
            int read, total, resume = 0;
            // Level 2 adds the last logon (seconds since 1970, 0 when the account never logged on).
            Check(NetUserEnum(null, 2, FILTER_NORMAL_ACCOUNT, out buf, MAX_PREFERRED_LENGTH, out read, out total, ref resume));
            try
            {
                foreach (var u in Read<USER_INFO_2>(buf, read))
                {
                    var lu = new LocalUser
                    {
                        Name = u.name,
                        Enabled = (u.flags & UF_ACCOUNTDISABLE) == 0,
                        LastLogon = u.last_logon == 0 ? (DateTime?)null : new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(u.last_logon).ToLocalTime()
                    };
                    try { lu.Sid = (SecurityIdentifier)new NTAccount(Environment.MachineName, u.name).Translate(typeof(SecurityIdentifier)); }
                    catch (Exception) { }
                    users.Add(lu);
                }
            }
            finally { NetApiBufferFree(buf); }
            return users;
        }

        public static IList<string> GetLocalGroups()
        {
            var groups = new List<string>();
            IntPtr buf, resume = IntPtr.Zero;
            int read, total;
            Check(NetLocalGroupEnum(null, 0, out buf, MAX_PREFERRED_LENGTH, out read, out total, ref resume));
            try
            {
                foreach (var g in Read<LOCALGROUP_INFO_0>(buf, read)) groups.Add(g.name);
            }
            finally { NetApiBufferFree(buf); }
            return groups;
        }

        public static IList<LocalGroupMember> GetGroupMembers(string group)
        {
            var members = new List<LocalGroupMember>();
            IntPtr buf, resume = IntPtr.Zero;
            int read, total;
            Check(NetLocalGroupGetMembers(null, group, 2, out buf, MAX_PREFERRED_LENGTH, out read, out total, ref resume));
            try
            {
                foreach (var m in Read<LOCALGROUP_MEMBERS_INFO_2>(buf, read))
                {
                    // SID_NAME_USE: 2 = Group, 4 = Alias, 5 = WellKnownGroup
                    members.Add(new LocalGroupMember
                    {
                        Sid = new SecurityIdentifier(m.sid),
                        Name = m.domainandname,
                        IsGroup = m.sidusage == 2 || m.sidusage == 4 || m.sidusage == 5
                    });
                }
            }
            finally { NetApiBufferFree(buf); }
            return members;
        }

        /// <summary>Local groups the user belongs to, directly or through nested membership.</summary>
        public static IList<string> GetUserLocalGroups(string user)
        {
            var groups = new List<string>();
            IntPtr buf;
            int read, total;
            Check(NetUserGetLocalGroups(null, user, 0, LG_INCLUDE_INDIRECT, out buf, MAX_PREFERRED_LENGTH, out read, out total));
            try
            {
                foreach (var g in Read<LOCALGROUP_USERS_INFO_0>(buf, read)) groups.Add(g.name);
            }
            finally { NetApiBufferFree(buf); }
            return groups;
        }
    }
}
