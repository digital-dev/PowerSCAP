using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace PowerScap.Engine.Cache
{
    /// <summary>
    /// The SCAP content an installed DISA/NIWC SCAP Compliance Checker carries. Some of it is published nowhere else:
    /// NIWC's Windows Updates benchmark (missing operating system patches) ships only with SCC. PowerSCAP only reads it;
    /// importing a file copies it into PowerSCAP's own cache.
    /// </summary>
    public static class SccContent
    {
        /// <summary>SCC's SCAP content folders, newest SCC first (for example ...\SCAP Compliance Checker 5.15\Resources\Content\SCAP12_Content).</summary>
        public static IList<string> Folders()
        {
            var roots = new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetEnvironmentVariable("ProgramW6432") }
                .Where(r => !string.IsNullOrEmpty(r) && Directory.Exists(r)).Distinct(StringComparer.OrdinalIgnoreCase);
            var found = new List<KeyValuePair<Version, string>>();
            foreach (var root in roots)
            {
                string[] dirs;
                try { dirs = Directory.GetDirectories(root, "SCAP Compliance Checker*"); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }
                foreach (var dir in dirs)
                {
                    string content = Path.Combine(dir, @"Resources\Content\SCAP12_Content");
                    if (!Directory.Exists(content) || found.Any(f => string.Equals(f.Value, content, StringComparison.OrdinalIgnoreCase))) continue;
                    found.Add(new KeyValuePair<Version, string>(VersionOf(Path.GetFileName(dir)), content));
                }
            }
            return found.OrderByDescending(f => f.Key).Select(f => f.Value).ToList();
        }

        /// <summary>The content files of the newest installed SCC (data streams and zips), or none.</summary>
        public static IList<string> Files()
        {
            var folder = Folders().FirstOrDefault();
            if (folder == null) return new List<string>();
            return Directory.GetFiles(folder)
                .Where(f => f.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                .OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>"SCAP Compliance Checker 5.15" is 5.15; a folder without a version sorts last.</summary>
        public static Version VersionOf(string folderName)
        {
            var m = System.Text.RegularExpressions.Regex.Match(folderName ?? "", @"(\d+(\.\d+)+)\s*$");
            Version v;
            return m.Success && Version.TryParse(m.Groups[1].Value, out v) ? v : new Version(0, 0);
        }
    }
}
