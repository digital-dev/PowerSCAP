using System;
using System.Collections;
using System.Linq;

namespace PowerScap.Engine.Oval
{
    /// <summary>independent family_object → family_item (always "windows" on this platform).</summary>
    public class FamilyCollector : ICollector
    {
        public string ObjectType { get { return "family_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            r.Items.Add(new OvalItem(ctx.NextItemId(), "family_item").Add("family", "windows"));
            return r;
        }
    }

    /// <summary>independent environmentvariable58_object → environmentvariable58_item (current process when pid is nil).</summary>
    public class EnvironmentVariable58Collector : ICollector
    {
        public string ObjectType { get { return "environmentvariable58_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion pidC, nameC;
            spec.Entities.TryGetValue("pid", out pidC);
            spec.Entities.TryGetValue("name", out nameC);
            string pid = System.Diagnostics.Process.GetCurrentProcess().Id.ToString();
            if (pidC != null && !pidC.IsNil && !CollectorUtil.Satisfies(pidC, pid))
            {
                // Reading another process's environment is not supported.
                r.Flag = CollectedFlag.NotCollected;
                r.Messages.Add("environmentvariable58: only the current process environment can be read.");
                return r;
            }
            foreach (DictionaryEntry kv in Environment.GetEnvironmentVariables())
            {
                string name = (string)kv.Key;
                if (!CollectorUtil.SatisfiesIgnoreCase(nameC, name)) continue;
                var item = new OvalItem(ctx.NextItemId(), "environmentvariable58_item");
                item.Add("pid", pid, "int").Add("name", name).Add("value", (string)kv.Value);
                r.Items.Add(item);
            }
            if (r.Items.Count == 0) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }
    }

    /// <summary>independent variable_object → variable_item (values of the referenced OVAL variable).</summary>
    public class VariableCollector : ICollector
    {
        public string ObjectType { get { return "variable_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion refC;
            if (!spec.Entities.TryGetValue("var_ref", out refC) || refC.Values.Count == 0 || ctx.Variables == null)
            {
                r.Flag = CollectedFlag.Error;
                r.Messages.Add("variable_object without a resolvable var_ref.");
                return r;
            }
            foreach (var varId in refC.Values)
            {
                VariableResult v = ctx.Variables.Resolve(varId);
                r.Messages.AddRange(v.Messages);
                if (v.Flag == CollectedFlag.Error) { r.Flag = CollectedFlag.Error; continue; }
                var item = new OvalItem(ctx.NextItemId(), "variable_item");
                item.Add("var_ref", varId);
                foreach (var value in v.Values) item.Add("value", value);
                r.Items.Add(item);
            }
            return r;
        }
    }
}
