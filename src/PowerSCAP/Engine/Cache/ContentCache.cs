using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using System.Xml;
using PowerScap.Engine.Content;
using PowerScap.Engine.Ncp;

namespace PowerScap.Engine.Cache
{
    /// <summary>One cached content file: where it came from and what it holds.</summary>
    public class CacheEntry
    {
        /// <summary>First 16 hex digits of the file's SHA-256.</summary>
        public string Id { get; set; }
        public int? ChecklistId { get; set; }
        public string ChecklistName { get; set; }
        public string ChecklistVersion { get; set; }
        public DateTime? NcpLastModified { get; set; }
        public string SourceUrl { get; set; }
        public string ResourceType { get; set; }
        public string FileName { get; set; }
        public string Sha256 { get; set; }
        public string ETag { get; set; }
        public DateTime AddedUtc { get; set; }
        public string BenchmarkId { get; set; }
        public string BenchmarkVersion { get; set; }
        public string BenchmarkTitle { get; set; }
        public bool Imported { get; set; }
        /// <summary>XML signature check made when the file entered the cache.</summary>
        public SignatureReport Signature { get; set; }
        /// <summary>Path relative to the cache root.</summary>
        public string RelativePath { get; set; }

        /// <summary>The file is gone from disk (computed on List, never stored).</summary>
        [ScriptIgnore]
        public bool Missing { get; set; }

        public override string ToString() { return (BenchmarkTitle ?? FileName) + " " + BenchmarkVersion; }
    }

    public class CacheException : Exception
    {
        public CacheException(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>
    /// Versioned store of SCAP content under one root with a JSON manifest. Content is only ever added:
    /// a new release sits beside the old ones so earlier results stay reproducible. Listing is offline.
    /// </summary>
    public class ContentCache
    {
        readonly IHttpTransport http;
        readonly object gate = new object();

        public ContentCache(string root, IHttpTransport http)
        {
            Root = Path.GetFullPath(root);
            this.http = http;
        }

        public string Root { get; private set; }

        string ManifestPath { get { return Path.Combine(Root, "manifest.json"); } }
        string PartialDir { get { return Path.Combine(Root, ".partial"); } }

        /// <summary>%POWERSCAP_CACHEDIR%, else %ProgramData%\PowerSCAP\content.</summary>
        public static string DefaultRoot()
        {
            string env = Environment.GetEnvironmentVariable("POWERSCAP_CACHEDIR");
            if (!string.IsNullOrEmpty(env)) return env;
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"PowerSCAP\content");
        }

        public static ContentCache OpenDefault(IHttpTransport http)
        {
            return new ContentCache(DefaultRoot(), http);
        }

        public string PathOf(CacheEntry e)
        {
            return Path.Combine(Root, e.RelativePath);
        }

        /// <summary>Cached entries, newest first. Never touches the network.</summary>
        public IList<CacheEntry> List()
        {
            lock (gate)
            {
                var entries = Read();
                foreach (var e in entries) e.Missing = !File.Exists(PathOf(e));
                return entries.OrderByDescending(e => e.AddedUtc).ToList();
            }
        }

        /// <summary>Downloads a checklist resource, validates it as SCAP content and adds it to the cache.</summary>
        public CacheEntry Download(NcpChecklist checklist, NcpResource resource)
        {
            Directory.CreateDirectory(PartialDir);
            string temp = Path.Combine(PartialDir, Guid.NewGuid().ToString("N") + Path.GetExtension(resource.FileName ?? ".zip"));
            try
            {
                http.Download(resource.Location, temp);
                string etag = null;
                try { etag = http.Head(resource.Location).ETag; } catch (NcpException) { }
                var entry = new CacheEntry
                {
                    ChecklistId = checklist.Id,
                    ChecklistName = checklist.Name,
                    ChecklistVersion = checklist.Version,
                    NcpLastModified = checklist.LastModified == DateTime.MinValue ? (DateTime?)null : checklist.LastModified,
                    SourceUrl = resource.Location,
                    ResourceType = resource.TypeName,
                    FileName = resource.FileName,
                    ETag = etag
                };
                return Add(temp, entry, checklist.Id.ToString(CultureInfo.InvariantCulture));
            }
            finally
            {
                TryDelete(temp);
            }
        }

        /// <summary>Adds a local SCAP zip or data stream file.</summary>
        public CacheEntry Import(string path)
        {
            Directory.CreateDirectory(PartialDir);
            string temp = Path.Combine(PartialDir, Guid.NewGuid().ToString("N") + Path.GetExtension(path));
            try
            {
                File.Copy(path, temp);
                var entry = new CacheEntry { FileName = Path.GetFileName(path), SourceUrl = Path.GetFullPath(path), Imported = true };
                return Add(temp, entry, "imported");
            }
            finally
            {
                TryDelete(temp);
            }
        }

        CacheEntry Add(string temp, CacheEntry entry, string folder)
        {
            entry.Sha256 = Sha256(temp);
            entry.Id = entry.Sha256.Substring(0, 16);
            Describe(temp, entry);
            entry.Signature = SignatureVerifier.Verify(temp);
            lock (gate)
            {
                var entries = Read();
                var existing = entries.FirstOrDefault(e => e.Sha256 == entry.Sha256 && File.Exists(PathOf(e)));
                if (existing != null) return existing;
                entry.RelativePath = Path.Combine(folder, entry.Id + "_" + entry.FileName);
                string final = PathOf(entry);
                Directory.CreateDirectory(Path.GetDirectoryName(final));
                if (File.Exists(final)) File.Delete(final);
                File.Move(temp, final);
                entry.AddedUtc = DateTime.UtcNow;
                entries.RemoveAll(e => e.Sha256 == entry.Sha256);
                entries.Add(entry);
                Write(entries);
                return entry;
            }
        }

        /// <summary>Loads the file as SCAP content and records its benchmark; anything else is rejected.</summary>
        static void Describe(string file, CacheEntry entry)
        {
            ScapContent content;
            try { content = ScapContentLoader.Load(file); }
            catch (Exception ex)
            {
                throw new CacheException("Not usable SCAP content (" + (entry.FileName ?? file) + "): " + ex.Message, ex);
            }
            if (content.Benchmark == null || string.IsNullOrEmpty(content.BenchmarkId))
                throw new CacheException("Not usable SCAP content (" + (entry.FileName ?? file) + "): no XCCDF benchmark.", null);
            entry.BenchmarkId = content.BenchmarkId;
            var root = content.Benchmark.DocumentElement;
            entry.BenchmarkVersion = ChildText(root, "version");
            entry.BenchmarkTitle = ChildText(root, "title");
        }

        static string ChildText(XmlElement e, string name)
        {
            foreach (XmlNode n in e.ChildNodes)
                if (n.NodeType == XmlNodeType.Element && n.LocalName == name) return n.InnerText.Trim();
            return null;
        }

        List<CacheEntry> Read()
        {
            if (!File.Exists(ManifestPath)) return new List<CacheEntry>();
            try
            {
                var list = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Deserialize<List<CacheEntry>>(File.ReadAllText(ManifestPath));
                return list ?? new List<CacheEntry>();
            }
            catch (Exception ex)
            {
                if (!(ex is ArgumentException || ex is InvalidOperationException || ex is FormatException)) throw;
                // Keep the damaged manifest for inspection and rebuild from the files present.
                File.Move(ManifestPath, ManifestPath + ".bad-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture));
                var rebuilt = Rebuild();
                Write(rebuilt);
                return rebuilt;
            }
        }

        List<CacheEntry> Rebuild()
        {
            var list = new List<CacheEntry>();
            if (!Directory.Exists(Root)) return list;
            foreach (var dir in Directory.GetDirectories(Root))
            {
                string folder = Path.GetFileName(dir);
                if (folder == ".partial") continue;
                int id;
                bool numeric = int.TryParse(folder, NumberStyles.None, CultureInfo.InvariantCulture, out id);
                foreach (var file in Directory.GetFiles(dir).Where(f => f.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)))
                {
                    string name = Path.GetFileName(file);
                    int sep = name.IndexOf('_');
                    var e = new CacheEntry
                    {
                        ChecklistId = numeric ? (int?)id : null,
                        Imported = folder == "imported",
                        FileName = sep == 16 ? name.Substring(17) : name,
                        Sha256 = Sha256(file),
                        AddedUtc = File.GetCreationTimeUtc(file),
                        RelativePath = Path.Combine(folder, name)
                    };
                    e.Id = e.Sha256.Substring(0, 16);
                    try { Describe(file, e); } catch (CacheException) { continue; }
                    e.Signature = SignatureVerifier.Verify(file);
                    list.Add(e);
                }
            }
            return list;
        }

        void Write(List<CacheEntry> entries)
        {
            Directory.CreateDirectory(Root);
            string tmp = ManifestPath + ".tmp";
            File.WriteAllText(tmp, new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize(entries));
            if (File.Exists(ManifestPath)) File.Replace(tmp, ManifestPath, null);
            else File.Move(tmp, ManifestPath);
        }

        static string Sha256(string file)
        {
            using (var sha = SHA256.Create())
            using (var fs = File.OpenRead(file))
                return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
        }

        static void TryDelete(string file)
        {
            try { if (File.Exists(file)) File.Delete(file); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
}
