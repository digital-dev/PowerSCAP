using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Xml;

namespace PowerScap.Engine.Content
{
    public class ScapContent
    {
        public XmlDocument Benchmark { get; set; }
        public string BenchmarkId { get; set; }
        /// <summary>Check components keyed by the exact href used by XCCDF check-content-ref.</summary>
        public IDictionary<string, XmlDocument> CheckComponents { get; private set; }
        public XmlDocument CpeDictionary { get; set; }
        /// <summary>CPE check components (OVAL) keyed by the href used in the CPE dictionary.</summary>
        public IDictionary<string, XmlDocument> CpeChecks { get; private set; }
        public XmlDocument Ocil { get; set; }
        public string SourcePath { get; set; }

        public ScapContent()
        {
            CheckComponents = new Dictionary<string, XmlDocument>(StringComparer.Ordinal);
            CpeChecks = new Dictionary<string, XmlDocument>(StringComparer.Ordinal);
        }
    }

    public static class ScapContentLoader
    {
        public const string DsNs = "http://scap.nist.gov/schema/scap/source/1.2";
        public const string XlinkNs = "http://www.w3.org/1999/xlink";
        public const string CatNs = "urn:oasis:names:tc:entity:xmlns:xml:catalog";
        public const string XccdfNs = "http://checklists.nist.gov/xccdf/1.2";
        public const string OvalDefNs = "http://oval.mitre.org/XMLSchema/oval-definitions-5";
        public const string OcilNs = "http://scap.nist.gov/schema/ocil/2.0";

        public static ScapContent Load(string path)
        {
            return Load(path, null);
        }

        public static ScapContent Load(string path, string dataStreamId)
        {
            if (string.IsNullOrEmpty(path) || !(File.Exists(path) || Directory.Exists(path)))
                throw new FileNotFoundException("SCAP content not found: " + path, path);

            string xmlPath = path;
            if (Directory.Exists(path))
                xmlPath = FindContentXml(path);
            else if (path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                xmlPath = FindContentXml(ExtractZip(path));

            XmlDocument doc = LoadXml(xmlPath);
            ScapContent content;
            string root = doc.DocumentElement.LocalName;
            if (root == "data-stream-collection" && doc.DocumentElement.NamespaceURI == DsNs)
                content = LoadDataStream(doc, dataStreamId);
            else if (root == "Benchmark")
                content = LoadStandalone(doc, Path.GetDirectoryName(xmlPath));
            else
                throw new InvalidDataException("Not a SCAP data stream or XCCDF benchmark: " + xmlPath);

            content.SourcePath = path;
            return content;
        }

        public static XmlDocument LoadXml(string file)
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;
            var doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.PreserveWhitespace = false;
            using (var reader = XmlReader.Create(file, settings))
                doc.Load(reader);
            return doc;
        }

        static string ExtractZip(string zip)
        {
            string hash;
            using (var sha = SHA256.Create())
            using (var fs = File.OpenRead(zip))
                hash = BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
            string root = Environment.GetEnvironmentVariable("POWERSCAP_EXTRACTDIR");
            if (string.IsNullOrEmpty(root))
                root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PowerSCAP", "extract");
            string dir = Path.Combine(root, hash.Substring(0, 16));
            if (!Directory.Exists(dir))
            {
                string tmp = dir + ".tmp" + Guid.NewGuid().ToString("N");
                ZipFile.ExtractToDirectory(zip, tmp);
                try { Directory.Move(tmp, dir); }
                catch (IOException) { Directory.Delete(tmp, true); } // another process won the race
            }
            return dir;
        }

        static string FindContentXml(string dir)
        {
            string standalone = null;
            foreach (var f in Directory.GetFiles(dir, "*.xml", SearchOption.AllDirectories).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                string rootName = PeekRoot(f);
                if (rootName == "data-stream-collection") return f;
                if (rootName == "Benchmark" && standalone == null) standalone = f;
            }
            if (standalone != null) return standalone;
            throw new InvalidDataException("No SCAP data stream or XCCDF benchmark found in " + dir);
        }

        static string PeekRoot(string file)
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;
            try
            {
                using (var r = XmlReader.Create(file, settings))
                {
                    while (r.Read())
                        if (r.NodeType == XmlNodeType.Element) return r.LocalName;
                }
            }
            catch (XmlException) { }
            return null;
        }

        static XmlNamespaceManager Ns(XmlDocument doc)
        {
            var ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("ds", DsNs);
            ns.AddNamespace("xlink", XlinkNs);
            ns.AddNamespace("cat", CatNs);
            return ns;
        }

        static XmlDocument ToDocument(XmlElement element)
        {
            var d = new XmlDocument();
            d.XmlResolver = null;
            d.AppendChild(d.ImportNode(element, true));
            return d;
        }

        static ScapContent LoadDataStream(XmlDocument doc, string dataStreamId)
        {
            var ns = Ns(doc);
            XmlElement ds = dataStreamId == null
                ? (XmlElement)doc.SelectSingleNode("/ds:data-stream-collection/ds:data-stream", ns)
                : (XmlElement)doc.SelectSingleNode("/ds:data-stream-collection/ds:data-stream[@id='" + dataStreamId + "']", ns);
            if (ds == null) throw new InvalidDataException("Data stream not found: " + (dataStreamId ?? "(first)"));

            var components = new Dictionary<string, XmlElement>(StringComparer.Ordinal);
            foreach (XmlElement c in doc.SelectNodes("/ds:data-stream-collection/ds:component | /ds:data-stream-collection/ds:extended-component", ns))
                components[c.GetAttribute("id")] = c;
            var componentRefs = new Dictionary<string, XmlElement>(StringComparer.Ordinal);
            foreach (XmlElement r in ds.SelectNodes(".//ds:component-ref", ns))
                componentRefs[r.GetAttribute("id")] = r;

            var cache = new Dictionary<string, XmlDocument>(StringComparer.Ordinal);
            Func<string, XmlDocument> resolve = null;
            resolve = delegate(string uri)
            {
                if (string.IsNullOrEmpty(uri) || uri[0] != '#') return null;
                string id = uri.Substring(1);
                XmlDocument hit;
                if (cache.TryGetValue(id, out hit)) return hit;
                XmlElement cref;
                if (componentRefs.TryGetValue(id, out cref))
                    hit = resolve(cref.GetAttribute("href", XlinkNs));
                else
                {
                    XmlElement comp;
                    if (components.TryGetValue(id, out comp))
                    {
                        XmlElement payload = comp.ChildNodes.OfType<XmlElement>().FirstOrDefault();
                        if (payload != null) hit = ToDocument(payload);
                    }
                }
                cache[id] = hit;
                return hit;
            };

            var content = new ScapContent();

            XmlElement checklistRef = (XmlElement)ds.SelectSingleNode("ds:checklists/ds:component-ref", ns);
            if (checklistRef == null) throw new InvalidDataException("Data stream has no checklist.");
            content.Benchmark = resolve(checklistRef.GetAttribute("href", XlinkNs));
            if (content.Benchmark == null) throw new InvalidDataException("Checklist component could not be resolved.");
            content.BenchmarkId = content.Benchmark.DocumentElement.GetAttribute("id");
            AddCatalog(checklistRef, ns, resolve, content.CheckComponents);

            foreach (XmlElement r in ds.SelectNodes("ds:checks/ds:component-ref", ns))
            {
                XmlDocument d = resolve("#" + r.GetAttribute("id"));
                if (d == null) continue;
                string key = "#" + r.GetAttribute("id");
                if (!content.CheckComponents.ContainsKey(key)) content.CheckComponents[key] = d;
                if (content.Ocil == null && d.DocumentElement.LocalName == "ocil") content.Ocil = d;
            }

            XmlElement dictRef = (XmlElement)ds.SelectSingleNode("ds:dictionaries/ds:component-ref", ns);
            if (dictRef != null)
            {
                content.CpeDictionary = resolve(dictRef.GetAttribute("href", XlinkNs));
                AddCatalog(dictRef, ns, resolve, content.CpeChecks);
            }
            return content;
        }

        static void AddCatalog(XmlElement componentRef, XmlNamespaceManager ns, Func<string, XmlDocument> resolve, IDictionary<string, XmlDocument> target)
        {
            // By local name: NIWC's OneDrive data stream writes some catalog entries without the catalog namespace
            // (<uri> inside <cat:catalog>); SCC follows them, and they are the content's only link to its OVAL.
            foreach (XmlElement u in componentRef.SelectNodes("cat:catalog/*[local-name()='uri']", ns))
            {
                XmlDocument d = resolve(u.GetAttribute("uri"));
                if (d != null) target[u.GetAttribute("name")] = d;
            }
        }

        static ScapContent LoadStandalone(XmlDocument benchmark, string dir)
        {
            var content = new ScapContent();
            content.Benchmark = benchmark;
            content.BenchmarkId = benchmark.DocumentElement.GetAttribute("id");
            foreach (XmlElement r in benchmark.GetElementsByTagName("check-content-ref", benchmark.DocumentElement.NamespaceURI))
            {
                string href = r.GetAttribute("href");
                if (string.IsNullOrEmpty(href) || content.CheckComponents.ContainsKey(href)) continue;
                string file = Path.Combine(dir, href);
                if (!File.Exists(file)) continue;
                XmlDocument d = LoadXml(file);
                content.CheckComponents[href] = d;
                if (content.Ocil == null && d.DocumentElement.LocalName == "ocil") content.Ocil = d;
            }
            return content;
        }
    }
}
