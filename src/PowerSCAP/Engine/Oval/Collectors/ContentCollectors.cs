using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.XPath;

namespace PowerScap.Engine.Oval
{
    /// <summary>independent textfilecontent54_object → textfilecontent_item (one item per pattern match instance).</summary>
    public class TextFileContent54Collector : FileBasedCollector
    {
        public override string ObjectType { get { return "textfilecontent54_object"; } }
        protected override string ItemType { get { return "textfilecontent_item"; } }

        protected override void CollectFile(ObjectSpec spec, FileHit hit, string physicalPath, string viewText, OvalContext ctx, CollectedObject result)
        {
            if (hit.FileName == null) return;
            EntityCriterion patternC, instanceC;
            spec.Entities.TryGetValue("pattern", out patternC);
            spec.Entities.TryGetValue("instance", out instanceC);
            if (patternC == null || patternC.Values.Count == 0) return;

            var options = RegexOptions.CultureInvariant;
            if (spec.Behavior("multiline", "true") == "true") options |= RegexOptions.Multiline;
            if (spec.Behavior("singleline", "false") == "true") options |= RegexOptions.Singleline;
            if (spec.Behavior("ignore_case", "false") == "true") options |= RegexOptions.IgnoreCase;

            string text = File.ReadAllText(physicalPath).Replace("\r\n", "\n");
            foreach (var pattern in patternC.Values)
            {
                string translated = OvalOps.ToRegex(pattern).ToString();
                int instance = 0;
                foreach (Match m in new Regex(translated, options).Matches(text))
                {
                    instance++;
                    string inst = instance.ToString(CultureInfo.InvariantCulture);
                    if (instanceC != null && !CollectorUtil.Satisfies(instanceC, inst)) continue;
                    var item = new OvalItem(ctx.NextItemId(), ItemType);
                    AddLocation(item, hit);
                    item.Add("pattern", pattern);
                    item.Add("instance", inst, "int");
                    item.Add("text", m.Value);
                    for (int g = 1; g < m.Groups.Count; g++) item.Add("subexpression", m.Groups[g].Value);
                    item.Add("windows_view", viewText);
                    result.Items.Add(item);
                }
            }
        }
    }

    /// <summary>independent xmlfilecontent_object → xmlfilecontent_item (XPath 1.0 value_of).</summary>
    public class XmlFileContentCollector : FileBasedCollector
    {
        public override string ObjectType { get { return "xmlfilecontent_object"; } }
        protected override string ItemType { get { return "xmlfilecontent_item"; } }

        protected override void CollectFile(ObjectSpec spec, FileHit hit, string physicalPath, string viewText, OvalContext ctx, CollectedObject result)
        {
            if (hit.FileName == null) return;
            EntityCriterion xpathC;
            if (!spec.Entities.TryGetValue("xpath", out xpathC)) return;

            XmlDocument doc;
            try
            {
                var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null };
                doc = new XmlDocument { XmlResolver = null };
                using (var r = XmlReader.Create(physicalPath, settings)) doc.Load(r);
            }
            catch (XmlException ex)
            {
                // A file that is not an XML document has no XML content to collect. This matches SCC, which
                // passes the .NET rules on hosts with binary servicing deltas (WinSxS\...\r\*.exe.config).
                result.Messages.Add("Skipped " + hit.FullPath + ": not an XML document (" + ex.Message + ")");
                return;
            }

            foreach (var xpath in xpathC.Values)
            {
                var item = new OvalItem(ctx.NextItemId(), ItemType);
                AddLocation(item, hit);
                item.Add("xpath", xpath);
                object value = doc.CreateNavigator().Evaluate(xpath);
                var iterator = value as XPathNodeIterator;
                if (iterator != null)
                {
                    int count = 0;
                    while (iterator.MoveNext()) { item.Add("value_of", iterator.Current.Value); count++; }
                    if (count == 0)
                    {
                        // Nothing selected: the item does not exist (SCC reports "[ does not exist ] ... value_of does
                        // not exist"), so it is not compared with states.
                        item.Entities.Add(OvalEntity.Missing("value_of"));
                        item.Status = ItemStatus.DoesNotExist;
                    }
                }
                else if (value is double)
                    item.Add("value_of", ((double)value).ToString(CultureInfo.InvariantCulture));
                else if (value is bool)
                    item.Add("value_of", (bool)value ? "true" : "false");
                else
                    item.Add("value_of", Convert.ToString(value, CultureInfo.InvariantCulture));
                item.Add("windows_view", viewText);
                result.Items.Add(item);
            }
        }
    }

    /// <summary>independent filehash58_object → filehash58_item.</summary>
    public class FileHash58Collector : FileBasedCollector
    {
        public override string ObjectType { get { return "filehash58_object"; } }
        protected override string ItemType { get { return "filehash58_item"; } }

        protected override void CollectFile(ObjectSpec spec, FileHit hit, string physicalPath, string viewText, OvalContext ctx, CollectedObject result)
        {
            if (hit.FileName == null) return;
            EntityCriterion typeC;
            spec.Entities.TryGetValue("hash_type", out typeC);
            var types = typeC != null && typeC.Values.Count > 0 ? typeC.Values : new[] { "SHA-256" };
            foreach (var t in types)
            {
                var item = new OvalItem(ctx.NextItemId(), ItemType);
                AddLocation(item, hit);
                item.Add("hash_type", t);
                HashAlgorithm alg = Create(t);
                if (alg == null)
                {
                    var e = new OvalEntity("hash", null);
                    e.Status = ItemStatus.Error;
                    item.Entities.Add(e);
                    item.Messages.Add("Unsupported hash_type " + t);
                }
                else
                {
                    using (alg)
                    using (var fs = File.OpenRead(physicalPath))
                        item.Add("hash", BitConverter.ToString(alg.ComputeHash(fs)).Replace("-", "").ToLowerInvariant());
                }
                item.Add("windows_view", viewText);
                result.Items.Add(item);
            }
        }

        static HashAlgorithm Create(string type)
        {
            switch (type)
            {
                case "MD5": return MD5.Create();
                case "SHA-1": return SHA1.Create();
                case "SHA-256": return SHA256.Create();
                case "SHA-384": return SHA384.Create();
                case "SHA-512": return SHA512.Create();
                default: return null;
            }
        }
    }

    /// <summary>windows-def wmi57_object → wmi57_item (each WMI object becomes one record result).</summary>
    public class Wmi57Collector : ICollector
    {
        public string ObjectType { get { return "wmi57_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion nsC, wqlC;
            spec.Entities.TryGetValue("namespace", out nsC);
            spec.Entities.TryGetValue("wql", out wqlC);
            if (nsC == null || wqlC == null) { r.Flag = CollectedFlag.Error; r.Messages.Add("wmi57_object needs namespace and wql."); return r; }

            foreach (var ns in nsC.Values)
                foreach (var wql in wqlC.Values)
                {
                    var item = new OvalItem(ctx.NextItemId(), "wmi57_item");
                    item.Add("namespace", ns).Add("wql", wql);
                    try
                    {
                        using (var searcher = new ManagementObjectSearcher(new ManagementScope(ns), new ObjectQuery(wql)))
                        {
                            int rows = 0;
                            foreach (ManagementBaseObject mo in searcher.Get())
                            {
                                rows++;
                                var record = new OvalEntity("result", null, "record");
                                foreach (PropertyData p in mo.Properties)
                                {
                                    string field = p.Name.ToLowerInvariant();
                                    if (p.Value == null) { record.Fields.Add(OvalEntity.Missing(field)); continue; }
                                    var arr = p.Value as Array;
                                    if (arr != null && !(p.Value is byte[]))
                                        foreach (var v in arr) record.Fields.Add(new OvalEntity(field, Convert.ToString(v, CultureInfo.InvariantCulture), FieldType(p)));
                                    else
                                        record.Fields.Add(new OvalEntity(field, Convert.ToString(p.Value, CultureInfo.InvariantCulture), FieldType(p)));
                                }
                                item.Entities.Add(record);
                            }
                            if (rows == 0) continue; // no rows: nothing exists for this query
                        }
                    }
                    catch (Exception ex)
                    {
                        if (!(ex is ManagementException || ex is UnauthorizedAccessException || ex is System.Runtime.InteropServices.COMException)) throw;
                        item.Status = ItemStatus.Error;
                        item.Messages.Add(ex.Message);
                        r.Flag = CollectedFlag.Error;
                        r.Messages.Add("WMI query failed (" + ns + ": " + wql + "): " + ex.Message);
                    }
                    r.Items.Add(item);
                }
            if (r.Items.Count == 0 && r.Flag == CollectedFlag.Complete) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }

        static string FieldType(PropertyData p)
        {
            switch (p.Type)
            {
                case CimType.Boolean: return "boolean";
                case CimType.SInt8: case CimType.SInt16: case CimType.SInt32: case CimType.SInt64:
                case CimType.UInt8: case CimType.UInt16: case CimType.UInt32: case CimType.UInt64:
                    return "int";
                case CimType.Real32: case CimType.Real64: return "float";
                default: return "string";
            }
        }
    }
}
