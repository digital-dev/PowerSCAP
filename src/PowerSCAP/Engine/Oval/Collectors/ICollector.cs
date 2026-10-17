using System;
using System.Collections.Generic;

namespace PowerScap.Engine.Oval
{
    /// <summary>Collects system items for one OVAL object type. Must not throw; report failures via Flag/Messages.</summary>
    public interface ICollector
    {
        /// <summary>Object element local name, e.g. "registry_object".</summary>
        string ObjectType { get; }
        CollectedObject Collect(ObjectSpec spec, OvalContext ctx);
    }

    public class CollectorRegistry
    {
        readonly Dictionary<string, ICollector> collectors = new Dictionary<string, ICollector>(StringComparer.Ordinal);

        public void Register(ICollector c)
        {
            collectors[c.ObjectType] = c;
        }

        public ICollector Find(string objectType)
        {
            ICollector c;
            return collectors.TryGetValue(objectType, out c) ? c : null;
        }

        public IEnumerable<string> ObjectTypes { get { return collectors.Keys; } }

        /// <summary>Directory listings shared by every file-based collector in this scan.</summary>
        public FileSystemCache Files { get { return files; } }
        readonly FileSystemCache files = new FileSystemCache();

        /// <summary>Registry subkey listings shared by every registry_object in this scan.</summary>
        public RegistryTreeCache RegistryTree { get { return registryTree; } }
        readonly RegistryTreeCache registryTree = new RegistryTreeCache();

        /// <summary>All built-in Windows and independent collectors. Collector tasks add theirs here.</summary>
        public static CollectorRegistry CreateDefault()
        {
            var r = new CollectorRegistry();
            r.Register(new RegistryCollector());
            r.Register(new FamilyCollector());
            r.Register(new EnvironmentVariable58Collector());
            r.Register(new VariableCollector());
            r.Register(new FileCollector());
            r.Register(new TextFileContent54Collector());
            r.Register(new XmlFileContentCollector());
            r.Register(new FileHash58Collector());
            r.Register(new Wmi57Collector());
            r.Register(new PasswordPolicyCollector());
            r.Register(new LockoutPolicyCollector());
            r.Register(new AuditEventPolicySubcategoriesCollector());
            r.Register(new AccessTokenCollector());
            r.Register(new SidCollector());
            r.Register(new SidSidCollector());
            r.Register(new UserCollector(false));
            r.Register(new UserCollector(true));
            r.Register(new GroupCollector(false));
            r.Register(new GroupCollector(true));
            r.Register(new ServiceCollector());
            r.Register(new FileEffectiveRights53Collector());
            r.Register(new RegKeyEffectiveRights53Collector());
            r.Register(new SharedResourceCollector());
            r.Register(new WuaUpdateSearcherCollector());
            r.Register(new UserRightCollector());
            r.Register(new WmiCollector());
            r.Register(new CmdletCollector());
            r.Register(new ShellCommandCollector());
            r.Register(new NtUserCollector());
            return r;
        }
    }
}
