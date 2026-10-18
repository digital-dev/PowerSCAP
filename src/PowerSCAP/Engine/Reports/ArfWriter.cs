using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Xml;

namespace PowerScap.Engine.Reports
{
    /// <summary>
    /// Asset Reporting Format 1.1: the source data stream (report request), this computer (asset), and the XCCDF
    /// TestResult and OVAL results (reports), each report linked to the asset with isAbout.
    /// </summary>
    public static class ArfWriter
    {
        public const string ArfNs = "http://scap.nist.gov/schema/asset-reporting-format/1.1";
        public const string CoreNs = "http://scap.nist.gov/schema/reporting-core/1.1";
        public const string AiNs = "http://scap.nist.gov/schema/asset-identification/1.1";
        const string XccdfNs = "http://checklists.nist.gov/xccdf/1.2";

        public static void Write(BenchmarkReport r, string xccdfResultsPath, IDictionary<string, XmlDocument> ovalResults, string path)
        {
            Build(r, xccdfResultsPath, ovalResults).Save(path);
        }

        public static XmlDocument Build(BenchmarkReport r, string xccdfResultsPath, IDictionary<string, XmlDocument> ovalResults)
        {
            var doc = new XmlDocument();
            doc.AppendChild(doc.CreateXmlDeclaration("1.0", "UTF-8", null));
            var root = doc.CreateElement("arf", "asset-report-collection", ArfNs);
            root.SetAttribute("xmlns:core", CoreNs);
            root.SetAttribute("xmlns:ai", AiNs);
            doc.AppendChild(root);

            var reportIds = new List<string>();
            var relationships = El(doc, root, "core", "relationships", CoreNs);
            relationships.SetAttribute("xmlns:arfvocab", "http://scap.nist.gov/specifications/arf/vocabulary/relationships/1.0#");

            var requests = El(doc, root, "arf", "report-requests", ArfNs);
            var request = El(doc, requests, "arf", "report-request", ArfNs);
            request.SetAttribute("id", "collection1");
            var requestContent = El(doc, request, "arf", "content", ArfNs);
            var source = LoadSource(r.ContentFile);
            if (source != null) requestContent.AppendChild(doc.ImportNode(source.DocumentElement, true));

            var assets = El(doc, root, "arf", "assets", ArfNs);
            var asset = El(doc, assets, "arf", "asset", ArfNs);
            asset.SetAttribute("id", "asset0");
            var device = El(doc, asset, "ai", "computing-device", AiNs);
            var connections = El(doc, device, "ai", "connections", AiNs);
            if (r.Target != null)
                foreach (var a in r.Target.Addresses)
                {
                    var c = El(doc, connections, "ai", "connection", AiNs);
                    var ip = El(doc, c, "ai", "ip-address", AiNs);
                    El(doc, ip, "ai", "ip-v4", AiNs).InnerText = a;
                }
            El(doc, device, "ai", "fqdn", AiNs).InnerText = r.Target == null ? "" : r.Target.Fqdn ?? "";
            El(doc, device, "ai", "hostname", AiNs).InnerText = r.Target == null ? "" : r.Target.HostName ?? "";

            var reports = El(doc, root, "arf", "reports", ArfNs);
            var xccdf = new XmlDocument();
            xccdf.Load(xccdfResultsPath);
            var testResult = xccdf.GetElementsByTagName("TestResult", XccdfNs).Cast<XmlElement>().LastOrDefault();
            if (testResult != null)
            {
                var rep = El(doc, reports, "arf", "report", ArfNs);
                rep.SetAttribute("id", "xccdf1");
                El(doc, rep, "arf", "content", ArfNs).AppendChild(doc.ImportNode(testResult, true));
                reportIds.Add("xccdf1");
            }
            int n = 0;
            foreach (var kv in ovalResults)
            {
                string id = "oval" + n++;
                var rep = El(doc, reports, "arf", "report", ArfNs);
                rep.SetAttribute("id", id);
                El(doc, rep, "arf", "content", ArfNs).AppendChild(doc.ImportNode(kv.Value.DocumentElement, true));
                reportIds.Add(id);
            }
            foreach (var id in reportIds)
            {
                var rel = El(doc, relationships, "core", "relationship", CoreNs);
                rel.SetAttribute("type", "arfvocab:isAbout");
                rel.SetAttribute("subject", id);
                El(doc, rel, "core", "ref", CoreNs).InnerText = "asset0";
            }
            return doc;
        }

        /// <summary>The source data stream: the XML inside a content zip, or the file itself.</summary>
        static XmlDocument LoadSource(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            var doc = new XmlDocument { XmlResolver = null };
            if (path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                using (var zip = ZipFile.OpenRead(path))
                {
                    var entry = zip.Entries.FirstOrDefault(e => e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase));
                    if (entry == null) return null;
                    using (var s = entry.Open())
                    using (var reader = XmlReader.Create(s, settings)) doc.Load(reader);
                }
                return doc;
            }
            using (var reader = XmlReader.Create(path, settings)) doc.Load(reader);
            return doc;
        }

        static XmlElement El(XmlDocument doc, XmlElement parent, string prefix, string name, string ns)
        {
            var e = doc.CreateElement(prefix, name, ns);
            parent.AppendChild(e);
            return e;
        }
    }
}
