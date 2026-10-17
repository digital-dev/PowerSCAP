using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PowerScap.Engine.Oval
{
    /// <summary>One directory's contents: subdirectory names (reparse points excluded) and file names.</summary>
    public class DirectoryListing
    {
        public string[] Directories { get; set; }
        public string[] Files { get; set; }
        /// <summary>Why the directory could not be read, or null.</summary>
        public string Error { get; set; }
    }

    /// <summary>
    /// Directory listings for one scan. Every folder is read once, with a single FindFirstFileEx enumeration
    /// that returns subfolders and files together; later objects (the .NET STIG walks the whole drive a
    /// dozen times) reuse the listing. A scan is a point-in-time snapshot, so reuse does not change results.
    /// </summary>
    public class FileSystemCache
    {
        readonly Dictionary<string, DirectoryListing> listings = new Dictionary<string, DirectoryListing>(StringComparer.OrdinalIgnoreCase);
        readonly object gate = new object();

        /// <summary>How many directories were actually read from disk.</summary>
        public int DirectoriesRead { get; private set; }

        /// <summary>How many listings were requested (cached or not).</summary>
        public int Lookups { get; private set; }

        /// <summary>Lists a physical directory path (already redirected for the 32-bit view).</summary>
        public DirectoryListing List(string physicalPath)
        {
            DirectoryListing l;
            lock (gate)
            {
                Lookups++;
                if (listings.TryGetValue(physicalPath, out l)) return l;
            }
            l = Read(physicalPath);
            lock (gate)
            {
                DirectoriesRead++;
                listings[physicalPath] = l;
            }
            return l;
        }

        readonly HashSet<string> prefetched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Lists every directory under a physical root, several directories at a time (one level per round).
        /// A whole-drive walk is I/O-bound on directory reads, which parallelize well on SSDs.
        /// </summary>
        public void Prefetch(string physicalRoot)
        {
            lock (gate) if (!prefetched.Add(physicalRoot)) return;
            var level = new List<string> { physicalRoot };
            var options = new System.Threading.Tasks.ParallelOptions { MaxDegreeOfParallelism = Math.Min(8, Environment.ProcessorCount) };
            while (level.Count > 0)
            {
                var next = new System.Collections.Concurrent.ConcurrentBag<string>();
                System.Threading.Tasks.Parallel.ForEach(level, options, dir =>
                {
                    var l = List(dir);
                    foreach (var d in l.Directories) next.Add(System.IO.Path.Combine(dir, d));
                });
                level = next.ToList();
            }
        }

        const int FindExInfoBasic = 1, FindExSearchNameMatch = 0, FindFirstExLargeFetch = 2;
        const uint FileAttributeDirectory = 0x10, FileAttributeReparsePoint = 0x400;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WIN32_FIND_DATAW
        {
            public uint dwFileAttributes;
            public uint ftCreationTimeLow, ftCreationTimeHigh, ftLastAccessTimeLow, ftLastAccessTimeHigh, ftLastWriteTimeLow, ftLastWriteTimeHigh;
            public uint nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFindHandle FindFirstFileExW(string fileName, int infoLevel, out WIN32_FIND_DATAW data, int searchOp, IntPtr filter, int flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool FindNextFileW(SafeFindHandle handle, out WIN32_FIND_DATAW data);

        [DllImport("kernel32.dll")]
        static extern bool FindClose(IntPtr handle);

        sealed class SafeFindHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            SafeFindHandle() : base(true) { }
            protected override bool ReleaseHandle() { return FindClose(handle); }
        }

        static DirectoryListing Read(string path)
        {
            var dirs = new List<string>();
            var files = new List<string>();
            string pattern = path.EndsWith("\\") ? path + "*" : path + "\\*";
            if (!pattern.StartsWith("\\\\")) pattern = "\\\\?\\" + pattern; // long paths
            WIN32_FIND_DATAW data;
            using (var h = FindFirstFileExW(pattern, FindExInfoBasic, out data, FindExSearchNameMatch, IntPtr.Zero, FindFirstExLargeFetch))
            {
                if (h.IsInvalid)
                {
                    int error = Marshal.GetLastWin32Error();
                    return new DirectoryListing { Directories = new string[0], Files = new string[0], Error = Describe(error, path) };
                }
                do
                {
                    string name = data.cFileName;
                    if (name == "." || name == "..") continue;
                    if ((data.dwFileAttributes & FileAttributeDirectory) != 0)
                    {
                        if ((data.dwFileAttributes & FileAttributeReparsePoint) == 0) dirs.Add(name);
                    }
                    else files.Add(name);
                } while (FindNextFileW(h, out data));
            }
            return new DirectoryListing { Directories = dirs.ToArray(), Files = files.ToArray() };
        }

        /// <summary>The same wording .NET uses, so scan messages read as before.</summary>
        static string Describe(int error, string path)
        {
            switch (error)
            {
                case 5: return "Access to the path '" + path + "' is denied.";
                case 2:
                case 3: return "Could not find a part of the path '" + path + "'.";
                default: return new System.ComponentModel.Win32Exception(error).Message + " (" + path + ")";
            }
        }
    }
}
