using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace PowerScap.Engine.Native
{
    /// <summary>LSA user-rights and advanced audit policy queries.</summary>
    public static class Advapi
    {
        [StructLayout(LayoutKind.Sequential)]
        struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct AUDIT_POLICY_INFORMATION
        {
            public Guid AuditSubCategoryGuid;
            public uint AuditingInformation;
            public Guid AuditCategoryGuid;
        }

        [DllImport("advapi32.dll")]
        static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attributes, uint access, out IntPtr policy);
        [DllImport("advapi32.dll")]
        static extern uint LsaEnumerateAccountRights(IntPtr policy, byte[] sid, out IntPtr rights, out uint count);
        [DllImport("advapi32.dll")]
        static extern uint LsaEnumerateAccountsWithUserRight(IntPtr policy, ref LSA_UNICODE_STRING right, out IntPtr buffer, out uint count);
        [DllImport("advapi32.dll")]
        static extern uint LsaFreeMemory(IntPtr buffer);
        [DllImport("advapi32.dll")]
        static extern uint LsaClose(IntPtr handle);
        [DllImport("advapi32.dll")]
        static extern int LsaNtStatusToWinError(uint status);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        static extern bool AuditEnumerateSubCategories(IntPtr category, [MarshalAs(UnmanagedType.U1)] bool all, out IntPtr subcategories, out uint count);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        static extern bool AuditQuerySystemPolicy([In] Guid[] subcategories, uint count, out IntPtr policy);
        [DllImport("advapi32.dll")]
        static extern void AuditFree(IntPtr buffer);

        const uint POLICY_VIEW_LOCAL_INFORMATION = 0x1;
        const uint POLICY_LOOKUP_NAMES = 0x800;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001A;

        static IntPtr OpenPolicy(uint access)
        {
            var attrs = new LSA_OBJECT_ATTRIBUTES();
            attrs.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            IntPtr handle;
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attrs, access, out handle);
            if (status != 0) throw new Win32Exception(LsaNtStatusToWinError(status));
            return handle;
        }

        static byte[] SidBytes(SecurityIdentifier sid)
        {
            var b = new byte[sid.BinaryLength];
            sid.GetBinaryForm(b, 0);
            return b;
        }

        static string ReadUnicode(LSA_UNICODE_STRING s)
        {
            return s.Buffer == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUni(s.Buffer, s.Length / 2);
        }

        /// <summary>Rights and privileges held directly by the account (e.g. "SeDebugPrivilege").</summary>
        public static IList<string> GetAccountRights(SecurityIdentifier sid)
        {
            var result = new List<string>();
            IntPtr policy = OpenPolicy(POLICY_LOOKUP_NAMES);
            try
            {
                IntPtr rights;
                uint count;
                uint status = LsaEnumerateAccountRights(policy, SidBytes(sid), out rights, out count);
                if (status == STATUS_OBJECT_NAME_NOT_FOUND) return result;
                if (status != 0) throw new Win32Exception(LsaNtStatusToWinError(status));
                try
                {
                    int size = Marshal.SizeOf(typeof(LSA_UNICODE_STRING));
                    for (int i = 0; i < count; i++)
                    {
                        var s = (LSA_UNICODE_STRING)Marshal.PtrToStructure(new IntPtr(rights.ToInt64() + i * size), typeof(LSA_UNICODE_STRING));
                        result.Add(ReadUnicode(s));
                    }
                }
                finally { LsaFreeMemory(rights); }
            }
            finally { LsaClose(policy); }
            return result;
        }

        /// <summary>All accounts holding a right (requires administrator).</summary>
        public static IList<SecurityIdentifier> GetAccountsWithRight(string right)
        {
            var result = new List<SecurityIdentifier>();
            IntPtr policy = OpenPolicy(POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION);
            IntPtr text = Marshal.StringToHGlobalUni(right);
            try
            {
                var us = new LSA_UNICODE_STRING();
                us.Buffer = text;
                us.Length = (ushort)(right.Length * 2);
                us.MaximumLength = (ushort)(right.Length * 2 + 2);
                IntPtr buffer;
                uint count;
                uint status = LsaEnumerateAccountsWithUserRight(policy, ref us, out buffer, out count);
                // STATUS_NO_SUCH_PRIVILEGE: a right this Windows no longer defines (SeUnsolicitedInputPrivilege) has no holders.
                if (status == STATUS_NO_MORE_ENTRIES || status == STATUS_OBJECT_NAME_NOT_FOUND || status == 0xC0000060) return result;
                if (status != 0) throw new Win32Exception(LsaNtStatusToWinError(status));
                try
                {
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr sidPtr = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                        result.Add(new SecurityIdentifier(sidPtr));
                    }
                }
                finally { LsaFreeMemory(buffer); }
            }
            finally
            {
                Marshal.FreeHGlobal(text);
                LsaClose(policy);
            }
            return result;
        }

        /// <summary>Advanced audit policy per subcategory GUID: bit 1 = success, bit 2 = failure. Requires SeSecurityPrivilege.</summary>
        public static IDictionary<Guid, uint> QueryAuditPolicy()
        {
            IntPtr subs;
            uint count;
            if (!AuditEnumerateSubCategories(IntPtr.Zero, true, out subs, out count))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var guids = new Guid[count];
            try
            {
                int gsize = Marshal.SizeOf(typeof(Guid));
                for (int i = 0; i < count; i++)
                    guids[i] = (Guid)Marshal.PtrToStructure(new IntPtr(subs.ToInt64() + i * gsize), typeof(Guid));
            }
            finally { AuditFree(subs); }

            IntPtr policy;
            if (!AuditQuerySystemPolicy(guids, count, out policy))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var result = new Dictionary<Guid, uint>();
            try
            {
                int size = Marshal.SizeOf(typeof(AUDIT_POLICY_INFORMATION));
                for (int i = 0; i < count; i++)
                {
                    var info = (AUDIT_POLICY_INFORMATION)Marshal.PtrToStructure(new IntPtr(policy.ToInt64() + i * size), typeof(AUDIT_POLICY_INFORMATION));
                    result[info.AuditSubCategoryGuid] = info.AuditingInformation;
                }
            }
            finally { AuditFree(policy); }
            return result;
        }
    }
}
