using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace PowerScap.Engine.Oval
{
    public class FileHit
    {
        public string Path { get; set; }       // directory
        public string FileName { get; set; }   // null for a directory hit
        public string FullPath { get { return FileName == null ? Path : System.IO.Path.Combine(Path, FileName); } }
    }

    /// <summary>
    /// Resolves filepath / path+filename criteria plus OVAL file behaviors to concrete files.
    /// Iterative walk (no recursion stack); unreadable directories become messages, never failures.
    /// </summary>
    public static class FileSearch
    {
        public static IList<FileHit> Find(ObjectSpec spec, IList<string> messages)
        {
            EntityCriterion filepathC, pathC, filenameC;
            spec.Entities.TryGetValue("filepath", out filepathC);
            spec.Entities.TryGetValue("path", out pathC);
            spec.Entities.TryGetValue("filename", out filenameC);
            bool view32 = !CollectorUtil.Is64BitView(spec);
            var hits = new List<FileHit>();

            if (filepathC != null)
            {
                IList<string> literal = CollectorUtil.LiteralValues(filepathC);
                if (literal != null)
                {
                    foreach (var fp in literal)
                    {
                        string mapped = Redirect(fp, view32);
                        if (File.Exists(mapped)) hits.Add(new FileHit { Path = System.IO.Path.GetDirectoryName(fp), FileName = System.IO.Path.GetFileName(fp) });
                    }
                    return hits;
                }
                foreach (var dir in WalkFromPatterns(filepathC, view32, messages, -1))
                    foreach (var f in SafeFiles(dir, view32, messages))
                    {
                        string full = System.IO.Path.Combine(dir, f);
                        if (CollectorUtil.SatisfiesIgnoreCase(filepathC, full)) hits.Add(new FileHit { Path = dir, FileName = f });
                    }
                return hits;
            }

            if (pathC == null) return hits;
            var dirs = MatchDirectories(pathC, view32, messages);
            dirs = ApplyRecursion(spec, dirs, view32, messages);
            foreach (var dir in dirs)
            {
                if (filenameC == null || filenameC.IsNil)
                {
                    hits.Add(new FileHit { Path = dir });
                    continue;
                }
                IList<string> literalNames = CollectorUtil.LiteralValues(filenameC);
                if (literalNames != null)
                {
                    foreach (var n in literalNames)
                        if (File.Exists(Redirect(System.IO.Path.Combine(dir, n), view32))) hits.Add(new FileHit { Path = dir, FileName = n });
                }
                else
                {
                    foreach (var f in SafeFiles(dir, view32, messages))
                        if (CollectorUtil.SatisfiesIgnoreCase(filenameC, f)) hits.Add(new FileHit { Path = dir, FileName = f });
                }
            }
            return hits;
        }

        static List<string> MatchDirectories(EntityCriterion pathC, bool view32, IList<string> messages)
        {
            IList<string> literal = CollectorUtil.LiteralValues(pathC);
            if (literal != null)
                return literal.Where(p => Directory.Exists(Redirect(p, view32))).Select(p => p.TrimEnd('\\').Length == 2 ? p : p.TrimEnd('\\')).ToList();
            return WalkFromPatterns(pathC, view32, messages, -1).Where(d => CollectorUtil.SatisfiesIgnoreCase(pathC, d)).ToList();
        }

        /// <summary>All directories beneath the literal prefix of each pattern (all fixed drives when no prefix).</summary>
        static IEnumerable<string> WalkFromPatterns(EntityCriterion c, bool view32, IList<string> messages, int maxDepth)
        {
            var starts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var v in c.Values)
            {
                string prefix = c.Operation == "pattern match" ? CollectorUtil.LiteralPrefix(v) : string.Empty;
                int cut = prefix.LastIndexOf('\\');
                string start = cut >= 0 ? prefix.Substring(0, cut + 1) : string.Empty;
                if (start.Length == 0)
                    foreach (var d in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady)) starts.Add(d.RootDirectory.FullName);
                else
                    starts.Add(start);
            }
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var s in starts)
                foreach (var d in Walk(s, maxDepth, view32, messages))
                    if (seen.Add(d)) yield return d;
        }

        public static IEnumerable<string> Walk(string start, int maxDepth, bool view32, IList<string> messages)
        {
            var stack = new Stack<KeyValuePair<string, int>>();
            string first = start.Length > 3 ? start.TrimEnd('\\') : start;
            if (!Directory.Exists(Redirect(first, view32))) yield break;
            stack.Push(new KeyValuePair<string, int>(first, 0));
            while (stack.Count > 0)
            {
                var cur = stack.Pop();
                yield return cur.Key;
                if (maxDepth >= 0 && cur.Value >= maxDepth) continue;
                foreach (var sub in SafeSubdirectories(cur.Key, view32, messages))
                    stack.Push(new KeyValuePair<string, int>(sub, cur.Value + 1));
            }
        }

        static List<string> ApplyRecursion(ObjectSpec spec, List<string> dirs, bool view32, IList<string> messages)
        {
            string direction = spec.Behavior("recurse_direction", "none");
            if (direction == "none") return dirs;
            int maxDepth;
            if (!int.TryParse(spec.Behavior("max_depth", "-1"), out maxDepth)) maxDepth = -1;
            var result = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in dirs)
            {
                if (direction == "up")
                {
                    string cur = d;
                    int depth = 0;
                    while (cur != null && (maxDepth < 0 || depth <= maxDepth))
                    {
                        if (seen.Add(cur)) result.Add(cur);
                        cur = System.IO.Path.GetDirectoryName(cur);
                        depth++;
                    }
                }
                else
                {
                    foreach (var sub in Walk(d, maxDepth, view32, messages))
                        if (seen.Add(sub)) result.Add(sub);
                }
            }
            return result;
        }

        static IEnumerable<string> SafeSubdirectories(string dir, bool view32, IList<string> messages)
        {
            try
            {
                var info = new DirectoryInfo(Redirect(dir, view32));
                return info.GetDirectories()
                    .Where(d => (d.Attributes & FileAttributes.ReparsePoint) == 0)
                    .Select(d => System.IO.Path.Combine(dir, d.Name)).ToList();
            }
            catch (Exception ex)
            {
                if (!(ex is UnauthorizedAccessException || ex is IOException || ex is System.Security.SecurityException)) throw;
                lock (messages) messages.Add("Skipped unreadable directory " + dir + ": " + ex.Message);
                return new string[0];
            }
        }

        public static IList<string> SafeFiles(string dir, bool view32, IList<string> messages)
        {
            try
            {
                return new DirectoryInfo(Redirect(dir, view32)).GetFiles().Select(f => f.Name).ToList();
            }
            catch (Exception ex)
            {
                if (!(ex is UnauthorizedAccessException || ex is IOException || ex is System.Security.SecurityException)) throw;
                lock (messages) messages.Add("Skipped unreadable directory " + dir + ": " + ex.Message);
                return new string[0];
            }
        }

        /// <summary>Maps System32 to SysWOW64 for the 32-bit view (File System Redirector semantics).</summary>
        public static string Redirect(string path, bool view32)
        {
            if (!view32 || !Environment.Is64BitOperatingSystem || path == null) return SysNative(path);
            string sys32 = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
            if (path.StartsWith(sys32, StringComparison.OrdinalIgnoreCase))
                return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64") + path.Substring(sys32.Length);
            return path;
        }

        /// <summary>A 32-bit host sees System32 redirected; Sysnative reaches the real 64-bit folder.</summary>
        static string SysNative(string path)
        {
            if (path == null || Environment.Is64BitProcess || !Environment.Is64BitOperatingSystem) return path;
            string sys32 = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
            if (path.StartsWith(sys32, StringComparison.OrdinalIgnoreCase))
                return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Sysnative") + path.Substring(sys32.Length);
            return path;
        }
    }
}
