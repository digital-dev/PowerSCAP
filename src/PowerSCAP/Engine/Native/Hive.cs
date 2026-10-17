using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace PowerScap.Engine.Native
{
    /// <summary>Temporarily loads an offline user hive (NTUSER.DAT) under HKEY_USERS. Needs SeBackup/SeRestore (administrator).</summary>
    public static class Hive
    {
        static readonly UIntPtr HKEY_USERS = new UIntPtr(0x80000003u);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegLoadKey(UIntPtr hKey, string subKey, string file);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegUnLoadKey(UIntPtr hKey, string subKey);

        [StructLayout(LayoutKind.Sequential)]
        struct LUID { public uint Low; public int High; }
        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES { public int Count; public LUID Luid; public int Attributes; }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES state, int length, IntPtr previous, IntPtr returnLength);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);

        /// <summary>Enables a privilege held (but disabled) in the process token; false when not held.</summary>
        public static bool EnablePrivilege(string name)
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, out token)) return false;
            try
            {
                LUID luid;
                if (!LookupPrivilegeValue(null, name, out luid)) return false;
                var tp = new TOKEN_PRIVILEGES { Count = 1, Luid = luid, Attributes = 0x2 };
                if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
                return Marshal.GetLastWin32Error() == 0; // ERROR_NOT_ALL_ASSIGNED (1300) when not held
            }
            finally { CloseHandle(token); }
        }

        public static void Load(string mountName, string file)
        {
            EnablePrivilege("SeRestorePrivilege");
            EnablePrivilege("SeBackupPrivilege");
            int rc = RegLoadKey(HKEY_USERS, mountName, file);
            if (rc != 0) throw new Win32Exception(rc);
        }

        public static void Unload(string mountName)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            RegUnLoadKey(HKEY_USERS, mountName);
        }
    }
}
