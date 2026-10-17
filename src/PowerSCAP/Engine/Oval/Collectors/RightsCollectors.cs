using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using PowerScap.Engine.Native;

namespace PowerScap.Engine.Oval
{
    static class RightsUtil
    {
        static readonly KeyValuePair<string, uint>[] Common =
        {
            new KeyValuePair<string, uint>("standard_delete", 0x00010000),
            new KeyValuePair<string, uint>("standard_read_control", 0x00020000),
            new KeyValuePair<string, uint>("standard_write_dac", 0x00040000),
            new KeyValuePair<string, uint>("standard_write_owner", 0x00080000),
            new KeyValuePair<string, uint>("standard_synchronize", 0x00100000),
            new KeyValuePair<string, uint>("access_system_security", 0x01000000),
            new KeyValuePair<string, uint>("generic_read", 0x80000000),
            new KeyValuePair<string, uint>("generic_write", 0x40000000),
            new KeyValuePair<string, uint>("generic_execute", 0x20000000),
            new KeyValuePair<string, uint>("generic_all", 0x10000000)
        };

        public static readonly KeyValuePair<string, uint>[] File =
        {
            new KeyValuePair<string, uint>("file_read_data", 0x1), new KeyValuePair<string, uint>("file_write_data", 0x2),
            new KeyValuePair<string, uint>("file_append_data", 0x4), new KeyValuePair<string, uint>("file_read_ea", 0x8),
            new KeyValuePair<string, uint>("file_write_ea", 0x10), new KeyValuePair<string, uint>("file_execute", 0x20),
            new KeyValuePair<string, uint>("file_delete_child", 0x40), new KeyValuePair<string, uint>("file_read_attributes", 0x80),
            new KeyValuePair<string, uint>("file_write_attributes", 0x100)
        };

        public static readonly KeyValuePair<string, uint>[] Key =
        {
            new KeyValuePair<string, uint>("key_query_value", 0x1), new KeyValuePair<string, uint>("key_set_value", 0x2),
            new KeyValuePair<string, uint>("key_create_sub_key", 0x4), new KeyValuePair<string, uint>("key_enumerate_sub_keys", 0x8),
            new KeyValuePair<string, uint>("key_notify", 0x10), new KeyValuePair<string, uint>("key_create_link", 0x20),
            new KeyValuePair<string, uint>("key_wow64_64key", 0x100), new KeyValuePair<string, uint>("key_wow64_32key", 0x200),
            new KeyValuePair<string, uint>("key_wow64_res", 0x300)
        };

        public static void AddMask(OvalItem item, uint mask, KeyValuePair<string, uint>[] specific)
        {
            foreach (var kv in Common.Concat(specific))
                item.Add(kv.Key, (mask & kv.Value) == kv.Value ? "1" : "0", "boolean");
        }

        /// <summary>Trustees to report: the literal SIDs asked for, or every SID in the DACL matching the pattern.</summary>
        public static IEnumerable<SecurityIdentifier> Trustees(EntityCriterion c, RawAcl dacl)
        {
            IList<string> literal = CollectorUtil.LiteralValues(c);
            if (literal != null)
                return literal.Select(Accounts.ParseSid).Where(s => s != null).ToList();
            var fromAcl = new Dictionary<string, SecurityIdentifier>();
            if (dacl != null)
                foreach (var ace in dacl.OfType<KnownAce>()) fromAcl[ace.SecurityIdentifier.Value] = ace.SecurityIdentifier;
            return fromAcl.Values.Where(s => CollectorUtil.Satisfies(c, s.Value)).ToList();
        }

        public static RawAcl Dacl(byte[] descriptor)
        {
            var sd = new RawSecurityDescriptor(descriptor, 0);
            return sd.DiscretionaryAcl;
        }
    }

    /// <summary>windows-def fileeffectiverights53_object → fileeffectiverights_item.</summary>
    public class FileEffectiveRights53Collector : FileBasedCollector
    {
        public override string ObjectType { get { return "fileeffectiverights53_object"; } }
        protected override string ItemType { get { return "fileeffectiverights_item"; } }

        protected override void CollectFile(ObjectSpec spec, FileHit hit, string physicalPath, string viewText, OvalContext ctx, CollectedObject result)
        {
            EntityCriterion trusteeC;
            spec.Entities.TryGetValue("trustee_sid", out trusteeC);
            FileSystemSecurity security = hit.FileName == null
                ? (FileSystemSecurity)new DirectoryInfo(physicalPath).GetAccessControl(AccessControlSections.Access)
                : new FileInfo(physicalPath).GetAccessControl(AccessControlSections.Access);
            RawAcl dacl = RightsUtil.Dacl(security.GetSecurityDescriptorBinaryForm());
            foreach (var sid in RightsUtil.Trustees(trusteeC, dacl))
            {
                var item = new OvalItem(ctx.NextItemId(), ItemType);
                AddLocation(item, hit);
                item.Add("trustee_sid", sid.Value);
                RightsUtil.AddMask(item, Authz.EffectiveRights(dacl, sid), RightsUtil.File);
                item.Add("windows_view", viewText);
                result.Items.Add(item);
            }
        }
    }

    /// <summary>windows-def regkeyeffectiverights53_object → regkeyeffectiverights_item.</summary>
    public class RegKeyEffectiveRights53Collector : ICollector
    {
        public string ObjectType { get { return "regkeyeffectiverights53_object"; } }

        static readonly Dictionary<string, RegistryHive> Hives = new Dictionary<string, RegistryHive>(StringComparer.OrdinalIgnoreCase)
        {
            { "HKEY_LOCAL_MACHINE", RegistryHive.LocalMachine }, { "HKEY_CURRENT_USER", RegistryHive.CurrentUser },
            { "HKEY_CLASSES_ROOT", RegistryHive.ClassesRoot }, { "HKEY_USERS", RegistryHive.Users },
            { "HKEY_CURRENT_CONFIG", RegistryHive.CurrentConfig }
        };

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion hiveC, keyC, trusteeC;
            spec.Entities.TryGetValue("hive", out hiveC);
            spec.Entities.TryGetValue("key", out keyC);
            spec.Entities.TryGetValue("trustee_sid", out trusteeC);
            RegistryView view = CollectorUtil.Is64BitView(spec) ? RegistryView.Registry64 : RegistryView.Registry32;
            IList<string> keys = CollectorUtil.LiteralValues(keyC);
            if (keys == null)
            {
                r.Flag = CollectedFlag.NotCollected;
                r.Messages.Add("regkeyeffectiverights53: only literal keys are supported.");
                return r;
            }
            foreach (var hive in Hives.Keys.Where(h => CollectorUtil.SatisfiesIgnoreCase(hiveC, h)))
                using (var root = RegistryKey.OpenBaseKey(Hives[hive], view))
                    foreach (var k in keys)
                    {
                        RegistryKey key;
                        try { key = root.OpenSubKey(k, RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadPermissions); }
                        catch (System.Security.SecurityException ex) { r.Flag = CollectedFlag.Error; r.Messages.Add("Access is denied: " + k + ": " + ex.Message); continue; }
                        if (key == null) continue;
                        using (key)
                        {
                            RawAcl dacl = RightsUtil.Dacl(key.GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorBinaryForm());
                            foreach (var sid in RightsUtil.Trustees(trusteeC, dacl))
                            {
                                var item = new OvalItem(ctx.NextItemId(), "regkeyeffectiverights_item");
                                item.Add("hive", hive).Add("key", k).Add("trustee_sid", sid.Value);
                                RightsUtil.AddMask(item, Authz.EffectiveRights(dacl, sid), RightsUtil.Key);
                                item.Add("windows_view", view == RegistryView.Registry64 ? "64_bit" : "32_bit");
                                r.Items.Add(item);
                            }
                        }
                    }
            if (r.Items.Count == 0 && r.Flag == CollectedFlag.Complete) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }
    }

    /// <summary>windows-def sharedresource_object → sharedresource_item (NetShareEnum).</summary>
    public class SharedResourceCollector : ICollector
    {
        public string ObjectType { get { return "sharedresource_object"; } }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SHARE_INFO_2 { public string netname; public uint type; public string remark; public uint permissions, max_uses, current_uses; public string path, passwd; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SHARE_INFO_1 { public string netname; public uint type; public string remark; }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetShareEnum(string server, int level, out IntPtr buffer, int prefmax, out int read, out int total, ref int resume);
        [DllImport("netapi32.dll")]
        static extern int NetApiBufferFree(IntPtr buffer);

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion nameC;
            spec.Entities.TryGetValue("netname", out nameC);
            IntPtr buf;
            int read, total, resume = 0;
            int level = 2;
            int rc = NetShareEnum(null, 2, out buf, -1, out read, out total, ref resume);
            if (rc == 5) { level = 1; resume = 0; rc = NetShareEnum(null, 1, out buf, -1, out read, out total, ref resume); }
            if (rc == 2114)
            {
                // NERR_ServerNotStarted: with the Server service off, no shares exist.
                r.Flag = CollectedFlag.DoesNotExist;
                r.Messages.Add("The Server (LanmanServer) service is not running; no shares exist.");
                return r;
            }
            if (rc != 0) throw new Win32Exception(rc);
            try
            {
                int size = Marshal.SizeOf(level == 2 ? typeof(SHARE_INFO_2) : typeof(SHARE_INFO_1));
                for (int i = 0; i < read; i++)
                {
                    IntPtr p = new IntPtr(buf.ToInt64() + i * size);
                    string name; uint type; string path = null; uint maxUses = 0, curUses = 0;
                    if (level == 2)
                    {
                        var s = (SHARE_INFO_2)Marshal.PtrToStructure(p, typeof(SHARE_INFO_2));
                        name = s.netname; type = s.type; path = s.path; maxUses = s.max_uses; curUses = s.current_uses;
                    }
                    else
                    {
                        var s = (SHARE_INFO_1)Marshal.PtrToStructure(p, typeof(SHARE_INFO_1));
                        name = s.netname; type = s.type;
                    }
                    if (!CollectorUtil.SatisfiesIgnoreCase(nameC, name)) continue;
                    var item = new OvalItem(ctx.NextItemId(), "sharedresource_item");
                    item.Add("netname", name).Add("share_type", ShareType(type));
                    if (level == 2)
                    {
                        item.Add("max_uses", maxUses == uint.MaxValue ? "-1" : maxUses.ToString(), "int");
                        item.Add("current_uses", curUses.ToString(), "int");
                        if (string.IsNullOrEmpty(path)) item.Entities.Add(OvalEntity.Missing("local_path")); else item.Add("local_path", path);
                    }
                    else
                    {
                        item.Messages.Add("Share details need administrator rights.");
                        foreach (var n in new[] { "max_uses", "current_uses", "local_path" })
                        {
                            var e = new OvalEntity(n, null);
                            e.Status = ItemStatus.NotCollected;
                            item.Entities.Add(e);
                        }
                    }
                    r.Items.Add(item);
                }
            }
            finally { NetApiBufferFree(buf); }
            if (r.Items.Count == 0) r.Flag = CollectedFlag.DoesNotExist;
            return r;
        }

        static string ShareType(uint type)
        {
            bool special = (type & 0x80000000) != 0;
            switch (type & 0xFF)
            {
                case 0: return special ? "STYPE_DISKTREE_SPECIAL" : "STYPE_DISKTREE";
                case 1: return special ? "STYPE_PRINTQ_SPECIAL" : "STYPE_PRINTQ";
                case 2: return special ? "STYPE_DEVICE_SPECIAL" : "STYPE_DEVICE";
                case 3: return special ? "STYPE_IPC_SPECIAL" : "STYPE_IPC";
                default: return "STYPE_DISKTREE";
            }
        }
    }

    /// <summary>windows-def wuaupdatesearcher_object → wuaupdatesearcher_item (Windows Update Agent COM API).</summary>
    public class WuaUpdateSearcherCollector : ICollector
    {
        public string ObjectType { get { return "wuaupdatesearcher_object"; } }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var r = new CollectedObject(spec.ObjectId);
            EntityCriterion critC;
            spec.Entities.TryGetValue("search_criteria", out critC);
            if (critC == null || critC.Values.Count == 0) { r.Flag = CollectedFlag.Error; r.Messages.Add("search_criteria missing."); return r; }

            Type sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session");
            object session = Activator.CreateInstance(sessionType);
            object searcher = Invoke(session, "CreateUpdateSearcher");
            string cab = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PowerSCAP", "wsusscn2.cab");
            if (File.Exists(cab))
            {
                object manager = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.ServiceManager"));
                object service = Invoke(manager, "AddScanPackageService", "PowerSCAP Offline", cab, 1);
                SetProp(searcher, "ServerSelection", 3);
                SetProp(searcher, "ServiceID", GetProp(service, "ServiceID"));
                r.Messages.Add("Searched offline catalog " + cab);
            }
            if (spec.Behavior("include_superseded_updates", "true") == "false") SetProp(searcher, "IncludePotentiallySupersededUpdates", false);

            foreach (var criteria in critC.Values)
            {
                object result = Invoke(searcher, "Search", criteria);
                object updates = GetProp(result, "Updates");
                int count = (int)GetProp(updates, "Count");
                var item = new OvalItem(ctx.NextItemId(), "wuaupdatesearcher_item");
                item.Add("search_criteria", criteria);
                for (int i = 0; i < count; i++)
                {
                    object update = updates.GetType().InvokeMember("Item", System.Reflection.BindingFlags.GetProperty, null, updates, new object[] { i });
                    object identity = GetProp(update, "Identity");
                    item.Add("update_id", (string)GetProp(identity, "UpdateID"));
                }
                if (count == 0) item.Entities.Add(OvalEntity.Missing("update_id"));
                r.Items.Add(item);
            }
            return r;
        }

        static object Invoke(object target, string method, params object[] args)
        {
            return target.GetType().InvokeMember(method, System.Reflection.BindingFlags.InvokeMethod, null, target, args);
        }

        static object GetProp(object target, string name)
        {
            return target.GetType().InvokeMember(name, System.Reflection.BindingFlags.GetProperty, null, target, null);
        }

        static void SetProp(object target, string name, object value)
        {
            target.GetType().InvokeMember(name, System.Reflection.BindingFlags.SetProperty, null, target, new[] { value });
        }
    }
}
