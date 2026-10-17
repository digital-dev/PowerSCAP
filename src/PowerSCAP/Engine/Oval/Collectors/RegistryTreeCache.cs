using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace PowerScap.Engine.Oval
{
    /// <summary>
    /// Subkey listings for one scan. Unanchored key patterns (e.g. "SOFTWARE\\Microsoft\\...\\\S+") can match
    /// anywhere in a key path, so OVAL requires walking the whole hive. The first request for a branch walks it
    /// natively (each key opened relative to its parent, RegEnumKeyEx); later objects reuse the listings.
    /// </summary>
    public class RegistryTreeCache
    {
        class Listing
        {
            public string[] Names;
            public string Error;
        }

        readonly Dictionary<string, Listing> listings = new Dictionary<string, Listing>(StringComparer.OrdinalIgnoreCase);
        readonly object gate = new object();

        /// <summary>How many keys were actually read from the registry.</summary>
        public int KeysRead { get; private set; }

        /// <summary>
        /// Subkey names of root\path. Null with an error message when the key cannot be read; null without
        /// an error when it does not exist.
        /// </summary>
        public string[] Subkeys(RegistryKey root, RegistryView view, string path, out string error)
        {
            string prefix = root.Name + "|" + view + "|";
            Listing l;
            lock (gate)
            {
                if (!listings.TryGetValue(prefix + path, out l))
                {
                    WalkBranch(root, view, path, prefix);
                    listings.TryGetValue(prefix + path, out l);
                }
            }
            error = l == null ? null : l.Error;
            return l == null ? null : l.Names;
        }

        const int KEY_READ = 0x20019, KEY_WOW64_64KEY = 0x0100, KEY_WOW64_32KEY = 0x0200;
        const int ERROR_SUCCESS = 0, ERROR_ACCESS_DENIED = 5, ERROR_FILE_NOT_FOUND = 2, ERROR_NO_MORE_ITEMS = 259, ERROR_MORE_DATA = 234;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegOpenKeyExW(SafeRegistryHandle parent, string subKey, int options, int samDesired, out SafeRegistryHandle result);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegEnumKeyExW(SafeRegistryHandle key, int index, StringBuilder name, ref int nameLength, IntPtr reserved, IntPtr cls, IntPtr clsLength, IntPtr lastWrite);

        /// <summary>Walks root\start and everything below it once, recording each key's subkey names.</summary>
        void WalkBranch(RegistryKey root, RegistryView view, string start, string prefix)
        {
            // KEY_READ, as RegistryKey.OpenSubKey uses: a key listed here must also open for value reads.
            int access = KEY_READ | (view == RegistryView.Registry32 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);
            SafeRegistryHandle first;
            int rc = RegOpenKeyExW(HiveHandle(root), start.Length == 0 ? null : start, 0, access, out first);
            if (rc != ERROR_SUCCESS)
            {
                Record(prefix + start, rc == ERROR_FILE_NOT_FOUND ? null : new Listing { Error = Denied(root, start, rc) });
                return;
            }
            using (first) Walk(root, first, start, prefix, access, new StringBuilder(256));
        }

        /// <summary>Depth-first; each child is opened relative to its parent and closed when its subtree is done.</summary>
        void Walk(RegistryKey root, SafeRegistryHandle key, string path, string prefix, int access, StringBuilder name)
        {
            var names = new List<string>();
            for (int i = 0; ; i++)
            {
                name.Length = 0;
                int len = name.Capacity;
                int e = RegEnumKeyExW(key, i, name, ref len, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (e == ERROR_MORE_DATA) { name.Capacity = Math.Max(name.Capacity * 2, len + 1); i--; continue; }
                if (e != ERROR_SUCCESS) break; // ERROR_NO_MORE_ITEMS
                names.Add(name.ToString(0, len));
            }
            Record(prefix + path, new Listing { Names = names.ToArray() });
            foreach (var n in names)
            {
                string childPath = path.Length == 0 ? n : path + "\\" + n;
                if (listings.ContainsKey(prefix + childPath)) continue;
                SafeRegistryHandle child;
                int c = RegOpenKeyExW(key, n, 0, access, out child);
                if (c != ERROR_SUCCESS)
                {
                    Record(prefix + childPath, c == ERROR_FILE_NOT_FOUND ? null : new Listing { Error = Denied(root, childPath, c) });
                    continue;
                }
                using (child) Walk(root, child, childPath, prefix, access, name);
            }
        }

        /// <summary>The predefined handle for a hive's base key (RegistryKey.Handle throws for base keys).</summary>
        static SafeRegistryHandle HiveHandle(RegistryKey root)
        {
            uint hkey;
            switch (root.Name.ToUpperInvariant())
            {
                case "HKEY_CLASSES_ROOT": hkey = 0x80000000; break;
                case "HKEY_CURRENT_USER": hkey = 0x80000001; break;
                case "HKEY_LOCAL_MACHINE": hkey = 0x80000002; break;
                case "HKEY_USERS": hkey = 0x80000003; break;
                case "HKEY_CURRENT_CONFIG": hkey = 0x80000005; break;
                default: throw new ArgumentException("Not a registry hive: " + root.Name);
            }
            return new SafeRegistryHandle(new IntPtr(unchecked((int)hkey)), false);
        }

        void Record(string id, Listing l)
        {
            KeysRead++;
            listings[id] = l;
        }

        static string Denied(RegistryKey root, string path, int code)
        {
            return code == ERROR_ACCESS_DENIED
                ? "Access is denied: " + root.Name + "\\" + path
                : new System.ComponentModel.Win32Exception(code).Message + ": " + root.Name + "\\" + path;
        }
    }
}
