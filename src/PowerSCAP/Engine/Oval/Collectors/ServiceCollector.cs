using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management;
using Microsoft.Win32;

namespace PowerScap.Engine.Oval
{
    /// <summary>windows-def service_object → service_item (configuration from the SCM registry, state from WMI).</summary>
    public class ServiceCollector : ICollector
    {
        public string ObjectType { get { return "service_object"; } }

        const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion nameC;
            spec.Entities.TryGetValue("service_name", out nameC);
            var states = ServiceStates();

            using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var services = root.OpenSubKey(ServicesKey, false))
            {
                IList<string> literal = CollectorUtil.LiteralValues(nameC);
                IEnumerable<string> names = literal ?? services.GetSubKeyNames().Where(n => CollectorUtil.SatisfiesIgnoreCase(nameC, n)).ToList();
                foreach (var name in names)
                {
                    using (var key = services.OpenSubKey(name, false))
                    {
                        if (key == null || key.GetValue("Type") == null) continue;
                        r.Items.Add(Item(ctx, name, key, states));
                    }
                }
            }
            if (r.Items.Count == 0) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }

        static OvalItem Item(OvalContext ctx, string name, RegistryKey key, IDictionary<string, KeyValuePair<string, string>> states)
        {
            var item = new OvalItem(ctx.NextItemId(), "service_item");
            item.Add("service_name", name);
            AddString(item, "display_name", key.GetValue("DisplayName") as string);
            AddString(item, "description", key.GetValue("Description") as string);
            int type = Convert.ToInt32(key.GetValue("Type", 0), CultureInfo.InvariantCulture);
            item.Add("service_type", ServiceType(type));
            int start = Convert.ToInt32(key.GetValue("Start", 3), CultureInfo.InvariantCulture);
            item.Add("start_type", StartType(start));
            KeyValuePair<string, string> st;
            if (states.TryGetValue(name, out st))
            {
                item.Add("current_state", st.Key);
                item.Add("pid", st.Value, "int");
            }
            else
            {
                item.Add("current_state", "SERVICE_STOPPED");
                item.Entities.Add(OvalEntity.Missing("pid"));
            }
            AddString(item, "start_name", key.GetValue("ObjectName") as string);
            AddString(item, "path", key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string);
            var deps = key.GetValue("DependOnService") as string[];
            if (deps == null || deps.Length == 0) item.Entities.Add(OvalEntity.Missing("dependencies"));
            else foreach (var d in deps) item.Add("dependencies", d);
            return item;
        }

        static IDictionary<string, KeyValuePair<string, string>> ServiceStates()
        {
            var result = new Dictionary<string, KeyValuePair<string, string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var cls in new[] { "Win32_Service", "Win32_SystemDriver" })
            {
                try
                {
                    using (var s = new ManagementObjectSearcher("root\\cimv2", "SELECT Name, State, ProcessId FROM " + cls))
                        foreach (ManagementBaseObject mo in s.Get())
                        {
                            string pid = mo.Properties["ProcessId"] != null && mo["ProcessId"] != null ? Convert.ToString(mo["ProcessId"], CultureInfo.InvariantCulture) : "0";
                            result[(string)mo["Name"]] = new KeyValuePair<string, string>(State((string)mo["State"]), pid);
                        }
                }
                catch (ManagementException) { }
            }
            return result;
        }

        static string State(string wmi)
        {
            switch (wmi)
            {
                case "Running": return "SERVICE_RUNNING";
                case "Start Pending": return "SERVICE_START_PENDING";
                case "Stop Pending": return "SERVICE_STOP_PENDING";
                case "Continue Pending": return "SERVICE_CONTINUE_PENDING";
                case "Pause Pending": return "SERVICE_PAUSE_PENDING";
                case "Paused": return "SERVICE_PAUSED";
                default: return "SERVICE_STOPPED";
            }
        }

        static string StartType(int start)
        {
            switch (start)
            {
                case 0: return "SERVICE_BOOT_START";
                case 1: return "SERVICE_SYSTEM_START";
                case 2: return "SERVICE_AUTO_START";
                case 4: return "SERVICE_DISABLED";
                default: return "SERVICE_DEMAND_START";
            }
        }

        static string ServiceType(int type)
        {
            if ((type & 0x1) != 0) return "SERVICE_KERNEL_DRIVER";
            if ((type & 0x2) != 0) return "SERVICE_FILE_SYSTEM_DRIVER";
            if ((type & 0x10) != 0) return (type & 0x40) != 0 ? "SERVICE_USER_OWN_PROCESS" : "SERVICE_WIN32_OWN_PROCESS";
            if ((type & 0x20) != 0) return (type & 0x40) != 0 ? "SERVICE_USER_SHARE_PROCESS" : "SERVICE_WIN32_SHARE_PROCESS";
            return "SERVICE_WIN32";
        }

        static void AddString(OvalItem item, string name, string value)
        {
            if (string.IsNullOrEmpty(value)) item.Entities.Add(OvalEntity.Missing(name));
            else item.Add(name, value);
        }
    }
}
