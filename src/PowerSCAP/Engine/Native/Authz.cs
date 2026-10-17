using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace PowerScap.Engine.Native
{
    /// <summary>Effective rights of a trustee against a DACL (GetEffectiveRightsFromAcl, group membership included).</summary>
    public static class Authz
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct TRUSTEE
        {
            public IntPtr pMultipleTrustee;
            public int MultipleTrusteeOperation;
            public int TrusteeForm;   // TRUSTEE_IS_SID = 0
            public int TrusteeType;   // TRUSTEE_IS_UNKNOWN = 0
            public IntPtr ptstrName;  // PSID when TrusteeForm = TRUSTEE_IS_SID
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int GetEffectiveRightsFromAclW(byte[] acl, ref TRUSTEE trustee, out uint accessRights);

        public static uint EffectiveRights(RawAcl dacl, SecurityIdentifier trustee)
        {
            if (dacl == null) return 0x1F01FF | 0xF003F; // NULL DACL grants everything
            var aclBytes = new byte[dacl.BinaryLength];
            dacl.GetBinaryForm(aclBytes, 0);
            var sidBytes = new byte[trustee.BinaryLength];
            trustee.GetBinaryForm(sidBytes, 0);
            IntPtr sid = Marshal.AllocHGlobal(sidBytes.Length);
            try
            {
                Marshal.Copy(sidBytes, 0, sid, sidBytes.Length);
                var t = new TRUSTEE { TrusteeForm = 0, TrusteeType = 0, ptstrName = sid };
                uint mask;
                int rc = GetEffectiveRightsFromAclW(aclBytes, ref t, out mask);
                if (rc != 0) throw new Win32Exception(rc);
                return mask;
            }
            finally { Marshal.FreeHGlobal(sid); }
        }
    }
}
