using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace PowerScap.Engine.Oval
{
    /// <summary>
    /// windows-def cmdlet_object → cmdlet_item, one value record per output object. Cmdlets are implemented
    /// natively (NativeCmdlets); PowerSCAP never starts PowerShell during a scan, so an unimplemented cmdlet
    /// is reported as not collected.
    /// </summary>
    public class CmdletCollector : ICollector
    {
        public string ObjectType { get { return "cmdlet_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            EntityCriterion module, verb, noun;
            spec.Entities.TryGetValue("module_name", out module);
            spec.Entities.TryGetValue("verb", out verb);
            spec.Entities.TryGetValue("noun", out noun);
            var parameters = RecordFields(spec, "parameters");
            var select = RecordFields(spec, "select");
            string v = verb.Values[0], n = noun.Values[0];

            bool unique;
            IList<string> properties;
            var output = ParseSelect(select, out properties, out unique) ? NativeCmdlets.Invoke(v, n, parameters, properties) : null;
            if (output == null)
                return CollectedObject.WithFlag(spec.ObjectId, CollectedFlag.NotCollected,
                    "PowerSCAP has no native implementation of " + v + "-" + n + " with these parameters and does not run PowerShell.");

            var r = new CollectedObject(spec.ObjectId);
            var info = NativeCmdlets.ModuleOf(v, n);
            var item = new OvalItem(ctx.NextItemId(), "cmdlet_item");
            AddOrMissing(item, "module_name", info != null ? info.Name : (module != null && !module.IsNil ? module.Values[0] : null), "string");
            AddOrMissing(item, "module_id", info == null ? null : info.Id, "string");
            AddOrMissing(item, "module_version", info == null ? null : info.Version, "version");
            item.Add("verb", v).Add("noun", n);
            item.Entities.Add(parameters.Count > 0 ? Record("parameters", parameters) : OvalEntity.Missing("parameters"));
            item.Entities.Add(select.Count > 0 ? Record("select", select) : OvalEntity.Missing("select"));

            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var o in output.Objects)
            {
                var value = new OvalEntity("value", null, "record");
                foreach (var name in properties ?? o.Names)
                {
                    object raw;
                    o.Values.TryGetValue(name, out raw);
                    value.Fields.Add(new OvalEntity(name.ToLowerInvariant(), NativeCmdlets.Format(raw)));
                }
                if (unique && !seen.Add(string.Join("\u0001", value.Fields.Select(f => f.Value)))) continue;
                item.Entities.Add(value);
            }
            if (output.Objects.Count == 0)
            {
                // No output because the cmdlet failed (e.g. access denied) is a collection error, not absence.
                var value = OvalEntity.Missing("value");
                if (output.Errors.Count > 0)
                {
                    value.Status = ItemStatus.Error;
                    item.Status = ItemStatus.Error;
                    r.Flag = CollectedFlag.Error;
                }
                item.Entities.Add(value);
                item.Messages.AddRange(output.Errors);
                r.Messages.AddRange(output.Errors);
            }
            r.Items.Add(item);
            return r;
        }

        /// <summary>select fields: "property" (Select-Object -Property) or "unique" (the same, without duplicates).</summary>
        public static bool ParseSelect(IDictionary<string, string> select, out IList<string> properties, out bool unique)
        {
            properties = null;
            unique = false;
            foreach (var kv in select)
            {
                if (kv.Key.Equals("unique", StringComparison.OrdinalIgnoreCase)) unique = true;
                else if (!kv.Key.Equals("property", StringComparison.OrdinalIgnoreCase)) return false;
                properties = kv.Value.Split(',').Select(p => p.Trim()).Where(p => p.Length > 0).ToList();
            }
            return true;
        }

        static void AddOrMissing(OvalItem item, string name, string value, string datatype)
        {
            if (value != null) item.Add(name, value, datatype); else item.Entities.Add(OvalEntity.Missing(name));
        }

        public static Dictionary<string, string> RecordFields(ObjectSpec spec, string entity)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (System.Xml.XmlNode n in spec.Element.ChildNodes)
            {
                if (n.LocalName != entity) continue;
                foreach (System.Xml.XmlNode f in n.ChildNodes)
                {
                    var fe = f as System.Xml.XmlElement;
                    if (fe != null && fe.LocalName == "field") map[fe.GetAttribute("name")] = fe.InnerText;
                }
            }
            return map;
        }

        static OvalEntity Record(string name, Dictionary<string, string> fields)
        {
            var e = new OvalEntity(name, null, "record");
            foreach (var kv in fields) e.Fields.Add(new OvalEntity(kv.Key, kv.Value));
            return e;
        }
    }

    /// <summary>
    /// independent shellcommand_object → shellcommand_item (one item per command; each matching output line is a
    /// stdout_line). Output comes from NativeShell, which never starts a shell or script interpreter; a command
    /// it cannot reproduce is reported as not collected.
    /// </summary>
    public class ShellCommandCollector : ICollector
    {
        readonly CommandRunner runner;

        public ShellCommandCollector() : this(NativeShell.Run) { }

        public ShellCommandCollector(CommandRunner runner)
        {
            this.runner = runner;
        }

        public string ObjectType { get { return "shellcommand_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion shellC, commandC, patternC;
            spec.Entities.TryGetValue("shell", out shellC);
            spec.Entities.TryGetValue("command", out commandC);
            spec.Entities.TryGetValue("pattern", out patternC);
            string shell = shellC != null && shellC.Values.Count > 0 ? shellC.Values[0] : "cmd";
            foreach (var command in commandC.Values)
            {
                var output = runner(shell, command);
                if (!output.Handled)
                {
                    r.Flag = CollectedFlag.NotCollected;
                    r.Messages.AddRange(output.Stderr);
                    continue;
                }
                foreach (var pattern in (patternC == null ? new List<string> { ".*" } : patternC.Values))
                {
                    var rx = OvalOps.ToRegex(pattern);
                    var item = new OvalItem(ctx.NextItemId(), "shellcommand_item");
                    // exit_status is empty when no program ran (PowerShell's $LASTEXITCODE unset), as SCC reports it.
                    item.Add("shell", shell).Add("command", command).Add("exit_status", output.ExitStatus ?? "", "int");
                    item.Add("pattern", pattern);
                    foreach (var line in output.Stdout)
                    {
                        Match m = rx.Match(line);
                        if (!m.Success) continue;
                        item.Add("stdout_line", line);
                        for (int g = 1; g < m.Groups.Count; g++) item.Add("subexpression", m.Groups[g].Value);
                    }
                    foreach (var errLine in output.Stderr)
                        if (errLine.Length > 0) item.Add("stderr_line", errLine);
                    r.Items.Add(item);
                }
            }
            return r;
        }
    }
}
