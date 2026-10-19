using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace PowerScap.Engine.Oval
{
    /// <summary>One output object: property names in output order, values as PowerShell would hold them.</summary>
    public class CmdletObject
    {
        public CmdletObject()
        {
            Names = new List<string>();
            Values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        }

        public List<string> Names { get; private set; }
        public Dictionary<string, object> Values { get; private set; }

        public CmdletObject Set(string name, object value)
        {
            if (!Values.ContainsKey(name)) Names.Add(name);
            Values[name] = value;
            return this;
        }
    }

    public class CmdletOutput
    {
        public CmdletOutput()
        {
            Objects = new List<CmdletObject>();
            Errors = new List<string>();
        }

        public List<CmdletObject> Objects { get; private set; }
        public List<string> Errors { get; private set; }
    }

    /// <summary>The module a cmdlet comes from, read from its manifest under $PSHOME\Modules.</summary>
    public class CmdletModule
    {
        public string Name { get; set; }
        public string Id { get; set; }
        public string Version { get; set; }
    }

    /// <summary>
    /// Native implementations of the cmdlets cmdlet_object content asks for. Nothing here starts PowerShell:
    /// each cmdlet reads the same source the real cmdlet reads (WMI/CIM, certificate stores, firmware).
    /// </summary>
    public static class NativeCmdlets
    {
        delegate CmdletOutput Implementation(IDictionary<string, string> parameters, IList<string> properties);

        class Cmdlet
        {
            public string Module;
            public string[] Parameters;
            public Func<IDictionary<string, string>, IList<string>, bool> Accepts;
            public Implementation Run;
        }

        static readonly Dictionary<string, Cmdlet> Cmdlets = new Dictionary<string, Cmdlet>(StringComparer.OrdinalIgnoreCase)
        {
            { "Get-ChildItem", new Cmdlet { Module = "Microsoft.PowerShell.Management", Parameters = new[] { "path", "literalpath" }, Accepts = (p, s) => CertPath(p) != null, Run = GetCertificates } },
            { "Get-CimInstance", new Cmdlet { Module = "CimCmdlets", Parameters = new[] { "class", "classname", "namespace", "filter", "query" }, Accepts = (p, s) => Value(p, "class", "classname") != null || Value(p, "query") != null, Run = GetCimInstance } },
            { "Get-ComputerInfo", new Cmdlet { Module = "Microsoft.PowerShell.Management", Parameters = new string[0], Accepts = (p, s) => s != null && s.Count > 0 && s.All(ComputerInfo.ContainsKey), Run = GetComputerInfo } },
            { "Get-NetFirewallProfile", new Cmdlet { Module = "NetSecurity", Parameters = new[] { "policystore", "name", "profile" }, Accepts = (p, s) => true, Run = GetNetFirewallProfile } },
            { "Get-Tpm", new Cmdlet { Module = "TrustedPlatformModule", Parameters = new string[0], Accepts = (p, s) => true, Run = GetTpm } }
        };

        /// <summary>True when Invoke handles this cmdlet call natively. Executes nothing.</summary>
        public static bool IsSupported(string verb, string noun, IDictionary<string, string> parameters, IList<string> properties)
        {
            Cmdlet c;
            if (!Cmdlets.TryGetValue(verb + "-" + noun, out c)) return false;
            if (parameters.Keys.Any(k => !c.Parameters.Contains(k, StringComparer.OrdinalIgnoreCase))) return false;
            return c.Accepts(parameters, properties);
        }

        /// <summary>Runs the cmdlet natively; null when unsupported (see IsSupported).</summary>
        public static CmdletOutput Invoke(string verb, string noun, IDictionary<string, string> parameters, IList<string> properties)
        {
            if (!IsSupported(verb, noun, parameters, properties)) return null;
            return Cmdlets[verb + "-" + noun].Run(parameters, properties);
        }

        /// <summary>The module that provides the cmdlet, with the GUID and version from its manifest.</summary>
        public static CmdletModule ModuleOf(string verb, string noun)
        {
            Cmdlet c;
            if (!Cmdlets.TryGetValue(verb + "-" + noun, out c)) return null;
            var m = new CmdletModule { Name = c.Module };
            string manifest = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\Modules", c.Module, c.Module + ".psd1");
            if (!File.Exists(manifest)) return m;
            string text = File.ReadAllText(manifest);
            var guid = Regex.Match(text, @"^\s*GUID\s*=\s*['""]\{?([0-9a-fA-F-]{36})\}?['""]", RegexOptions.Multiline);
            var version = Regex.Match(text, @"^\s*ModuleVersion\s*=\s*['""]([^'""]+)['""]", RegexOptions.Multiline);
            if (guid.Success) m.Id = "{" + guid.Groups[1].Value.ToLowerInvariant() + "}";
            if (version.Success) m.Version = version.Groups[1].Value;
            return m;
        }

        /// <summary>A property value as text, the way SCAP interpreters report PowerShell values: arrays as {a,b}.</summary>
        public static string Format(object value)
        {
            if (value == null) return "";
            if (value is string) return (string)value;
            if (value is bool) return (bool)value ? "True" : "False";
            if (value is Enum) return value.ToString();
            var list = value as IEnumerable;
            if (list != null) return "{" + string.Join(",", list.Cast<object>().Select(Format)) + "}";
            var f = value as IFormattable;
            if (f != null) return f.ToString(null, CultureInfo.InvariantCulture);
            return value.ToString();
        }

        static string Value(IDictionary<string, string> p, params string[] names)
        {
            foreach (var n in names)
            {
                string v;
                if (p.TryGetValue(n, out v)) return v;
            }
            return null;
        }

        // ---- Get-ChildItem Cert:\ --------------------------------------------------------------------

        static string[] CertPath(IDictionary<string, string> p)
        {
            string path = Value(p, "path", "literalpath");
            if (path == null) return null;
            var m = Regex.Match(path, @"^Cert:\\(LocalMachine|CurrentUser)\\([^\\*?]+)\\?$", RegexOptions.IgnoreCase);
            return m.Success ? new[] { m.Groups[1].Value, m.Groups[2].Value } : null;
        }

        static CmdletOutput GetCertificates(IDictionary<string, string> p, IList<string> properties)
        {
            var o = new CmdletOutput();
            var path = CertPath(p);
            var location = path[0].Equals("LocalMachine", StringComparison.OrdinalIgnoreCase) ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
            var store = new X509Store(path[1], location);
            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                foreach (var cert in store.Certificates)
                {
                    var obj = new CmdletObject();
                    foreach (var prop in typeof(X509Certificate2).GetProperties(BindingFlags.Public | BindingFlags.Instance))
                    {
                        if (prop.GetIndexParameters().Length > 0) continue;
                        object v;
                        try { v = prop.GetValue(cert, null); } catch (Exception) { continue; }
                        obj.Set(prop.Name, v);
                    }
                    o.Objects.Add(obj);
                }
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                o.Errors.Add("Get-ChildItem : Cannot find path '" + Value(p, "path", "literalpath") + "' because it does not exist. " + ex.Message);
            }
            finally { store.Close(); }
            return o;
        }

        // ---- Get-CimInstance ---------------------------------------------------------------------------

        static CmdletOutput GetCimInstance(IDictionary<string, string> p, IList<string> properties)
        {
            string ns = Value(p, "namespace") ?? @"root\cimv2";
            string wql = Value(p, "query");
            if (wql == null)
            {
                wql = "SELECT * FROM " + Value(p, "class", "classname");
                string filter = Value(p, "filter");
                if (!string.IsNullOrEmpty(filter)) wql += " WHERE " + filter;
            }
            return Query(new ManagementScope(ns), wql, null, null);
        }

        /// <summary>Runs WQL; each instance becomes an object of its non-system properties, optionally mapped.</summary>
        static CmdletOutput Query(ManagementScope scope, string wql, System.Management.EnumerationOptions options, Func<string, object, object> map)
        {
            var o = new CmdletOutput();
            try
            {
                using (var s = options == null ? new ManagementObjectSearcher(scope, new ObjectQuery(wql)) : new ManagementObjectSearcher(scope, new ObjectQuery(wql), options))
                    foreach (ManagementBaseObject mo in s.Get())
                    {
                        var obj = new CmdletObject();
                        foreach (PropertyData pd in mo.Properties)
                            obj.Set(pd.Name, map == null ? pd.Value : map(pd.Name, pd.Value));
                        o.Objects.Add(obj);
                    }
            }
            catch (Exception ex)
            {
                if (!(ex is ManagementException || ex is UnauthorizedAccessException || ex is System.Runtime.InteropServices.COMException)) throw;
                o.Errors.Add(ex.Message);
            }
            return o;
        }

        // ---- Get-ComputerInfo --------------------------------------------------------------------------

        static readonly Dictionary<string, Func<object>> ComputerInfo = new Dictionary<string, Func<object>>(StringComparer.OrdinalIgnoreCase)
        {
            { "BiosFirmwareType", () => Firmware.Type() }
        };

        static CmdletOutput GetComputerInfo(IDictionary<string, string> p, IList<string> properties)
        {
            var o = new CmdletOutput();
            var obj = new CmdletObject();
            foreach (var name in properties) obj.Set(name, ComputerInfo[name]());
            o.Objects.Add(obj);
            return o;
        }

        // ---- Get-NetFirewallProfile --------------------------------------------------------------------

        static readonly HashSet<string> GpoBooleans = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Enabled", "AllowInboundRules", "AllowLocalFirewallRules", "AllowLocalIPsecRules", "AllowUserApps", "AllowUserPorts",
            "AllowUnicastResponseToMulticast", "NotifyOnListen", "EnableStealthModeForIPsec", "LogAllowed", "LogBlocked", "LogIgnored"
        };

        static object FirewallValue(string name, object value)
        {
            if (value == null) return null;
            if (GpoBooleans.Contains(name))
            {
                switch (Convert.ToInt32(value, CultureInfo.InvariantCulture))
                {
                    case 0: return "False";
                    case 1: return "True";
                    case 2: return "NotConfigured";
                }
            }
            if (name.Equals("DefaultInboundAction", StringComparison.OrdinalIgnoreCase) || name.Equals("DefaultOutboundAction", StringComparison.OrdinalIgnoreCase))
            {
                switch (Convert.ToInt32(value, CultureInfo.InvariantCulture))
                {
                    case 0: return "NotConfigured";
                    case 2: return "Allow";
                    case 4: return "Block";
                }
            }
            return value;
        }

        static CmdletOutput GetNetFirewallProfile(IDictionary<string, string> p, IList<string> properties)
        {
            // The policy store is a per-operation CIM option (a connection-level context is ignored).
            var options = new System.Management.EnumerationOptions();
            string store = Value(p, "policystore");
            if (store != null) options.Context.Add("PolicyStore", store);
            string wql = "SELECT * FROM MSFT_NetFirewallProfile";
            string name = Value(p, "name", "profile");
            if (name != null) wql += " WHERE Name = '" + name.Replace("'", "''") + "'";
            return Query(new ManagementScope(@"root\StandardCimv2"), wql, options, FirewallValue);
        }

        // ---- Get-Tpm -----------------------------------------------------------------------------------

        static CmdletOutput GetTpm(IDictionary<string, string> p, IList<string> properties)
        {
            var o = new CmdletOutput();
            try
            {
                using (var s = new ManagementObjectSearcher(new ManagementScope(@"root\cimv2\Security\MicrosoftTpm"), new ObjectQuery("SELECT * FROM Win32_Tpm")))
                {
                    var tpm = s.Get().Cast<ManagementObject>().FirstOrDefault();
                    var obj = new CmdletObject();
                    if (tpm == null)
                    {
                        obj.Set("TpmPresent", false).Set("TpmReady", false).Set("TpmEnabled", false).Set("TpmActivated", false).Set("TpmOwned", false);
                    }
                    else
                    {
                        using (tpm)
                        {
                            obj.Set("TpmPresent", true);
                            obj.Set("TpmReady", Method(tpm, "IsReady", "IsReady"));
                            obj.Set("TpmEnabled", Method(tpm, "IsEnabled", "IsEnabled"));
                            obj.Set("TpmActivated", Method(tpm, "IsActivated", "IsActivated"));
                            obj.Set("TpmOwned", Method(tpm, "IsOwned", "IsOwned"));
                            obj.Set("ManufacturerId", tpm["ManufacturerId"]);
                            obj.Set("ManufacturerVersion", tpm["ManufacturerVersion"]);
                        }
                    }
                    o.Objects.Add(obj);
                }
            }
            catch (Exception ex)
            {
                if (!(ex is ManagementException || ex is UnauthorizedAccessException || ex is System.Runtime.InteropServices.COMException)) throw;
                o.Errors.Add("Get-Tpm : " + ex.Message);
            }
            return o;
        }

        static object Method(ManagementObject mo, string method, string outName)
        {
            using (var result = mo.InvokeMethod(method, null, null))
                return result == null ? null : result[outName];
        }
    }
}
