using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security;
using Microsoft.Win32;

namespace PowerScap.Engine.Oval
{
    /// <summary>windows-def registry_object → registry_item (OVAL 5.11.2 Windows schema).</summary>
    public class RegistryCollector : ICollector
    {
        public string ObjectType { get { return "registry_object"; } }

        static readonly Dictionary<string, RegistryHive> Hives = new Dictionary<string, RegistryHive>(StringComparer.OrdinalIgnoreCase)
        {
            { "HKEY_LOCAL_MACHINE", RegistryHive.LocalMachine },
            { "HKEY_CURRENT_USER", RegistryHive.CurrentUser },
            { "HKEY_CLASSES_ROOT", RegistryHive.ClassesRoot },
            { "HKEY_USERS", RegistryHive.Users },
            { "HKEY_CURRENT_CONFIG", RegistryHive.CurrentConfig }
        };

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var result = new CollectedObject(spec.ObjectId);
            RegistryView view = CollectorUtil.Is64BitView(spec) && Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32;
            string viewText = view == RegistryView.Registry64 ? "64_bit" : "32_bit";

            EntityCriterion hiveC, keyC, nameC;
            spec.Entities.TryGetValue("hive", out hiveC);
            spec.Entities.TryGetValue("key", out keyC);
            spec.Entities.TryGetValue("name", out nameC);

            bool anyError = false;
            foreach (var hiveName in Hives.Keys.Where(h => CollectorUtil.SatisfiesIgnoreCase(hiveC, h)).ToList())
            {
                using (RegistryKey root = RegistryKey.OpenBaseKey(Hives[hiveName], view))
                {
                    foreach (var keyPath in FindKeys(root, keyC, result, ref anyError))
                        CollectValues(root, hiveName, keyPath, nameC, viewText, ctx, result, ref anyError);
                }
            }
            ApplyRecursion(spec, result, ctx, view, viewText, ref anyError);

            if (anyError) result.Flag = CollectedFlag.Error;
            else if (result.Items.Count == 0) result.Flag = CollectedFlag.DoesNotExist;
            return result;
        }

        IEnumerable<string> FindKeys(RegistryKey root, EntityCriterion keyC, CollectedObject result, ref bool anyError)
        {
            var found = new List<string>();
            if (keyC == null || keyC.IsNil) { found.Add(null); return found; }

            IList<string> literals = CollectorUtil.LiteralValues(keyC);
            if (literals != null)
            {
                foreach (var k in literals)
                {
                    try
                    {
                        using (var key = root.OpenSubKey(k, false))
                            if (key != null) found.Add(KeyPath(root, key));
                    }
                    catch (Exception ex)
                    {
                        if (!(ex is SecurityException || ex is UnauthorizedAccessException)) throw;
                        anyError = true;
                        result.Messages.Add("Access is denied: " + root.Name + "\\" + k);
                    }
                }
                return found;
            }

            // Pattern/other operations: enumerate beneath the longest literal prefix of each pattern.
            var starts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var v in keyC.Values)
            {
                string prefix = keyC.Operation == "pattern match" ? CollectorUtil.LiteralPrefix(v) : string.Empty;
                int cut = prefix.LastIndexOf('\\');
                starts.Add(cut >= 0 ? prefix.Substring(0, cut) : string.Empty);
            }
            foreach (var start in starts)
            {
                var stack = new Stack<string>();
                stack.Push(start);
                while (stack.Count > 0)
                {
                    string path = stack.Pop();
                    RegistryKey key = null;
                    try
                    {
                        key = path.Length == 0 ? root : root.OpenSubKey(path, false);
                        if (key == null) continue;
                        if (path.Length > 0 && CollectorUtil.SatisfiesIgnoreCase(keyC, path)) found.Add(KeyPath(root, key));
                        foreach (var sub in key.GetSubKeyNames())
                            stack.Push(path.Length == 0 ? sub : path + "\\" + sub);
                    }
                    catch (Exception ex)
                    {
                        if (!(ex is SecurityException || ex is UnauthorizedAccessException)) throw;
                        // Unreadable branches during pattern enumeration are reported but do not fail the object.
                        result.Messages.Add("Access is denied: " + root.Name + "\\" + path);
                    }
                    finally
                    {
                        if (key != null && !ReferenceEquals(key, root)) key.Dispose();
                    }
                }
            }
            return found.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        static string KeyPath(RegistryKey root, RegistryKey key)
        {
            return key.Name.Length > root.Name.Length ? key.Name.Substring(root.Name.Length + 1) : string.Empty;
        }

        void CollectValues(RegistryKey root, string hiveName, string keyPath, EntityCriterion nameC,
            string viewText, OvalContext ctx, CollectedObject result, ref bool anyError)
        {
            RegistryKey key;
            try
            {
                key = keyPath == null ? root : root.OpenSubKey(keyPath, false);
            }
            catch (Exception ex)
            {
                if (!(ex is SecurityException || ex is UnauthorizedAccessException)) throw;
                anyError = true;
                result.Messages.Add("Access is denied: " + hiveName + "\\" + keyPath);
                return;
            }
            if (key == null) return;
            try
            {
                if (nameC == null || nameC.IsNil)
                {
                    result.Items.Add(NewItem(ctx, hiveName, keyPath, null, viewText));
                    return;
                }
                IList<string> literals = CollectorUtil.LiteralValues(nameC);
                IEnumerable<string> names = literals ?? key.GetValueNames().Where(n => CollectorUtil.SatisfiesIgnoreCase(nameC, n)).ToList();
                foreach (var name in names)
                {
                    object raw;
                    RegistryValueKind kind;
                    try
                    {
                        if (!key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
                        {
                            if (literals != null)
                            {
                                var missing = NewItem(ctx, hiveName, keyPath, null, viewText);
                                missing.Entities.Add(OvalEntity.Missing("name"));
                                missing.Status = ItemStatus.DoesNotExist;
                                result.Items.Add(missing);
                            }
                            continue;
                        }
                        raw = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                        kind = key.GetValueKind(name);
                    }
                    catch (Exception ex)
                    {
                        if (!(ex is SecurityException || ex is UnauthorizedAccessException || ex is System.IO.IOException)) throw;
                        anyError = true;
                        var err = NewItem(ctx, hiveName, keyPath, name, viewText);
                        err.Status = ItemStatus.Error;
                        err.Messages.Add("Access is denied: " + ex.Message);
                        result.Items.Add(err);
                        continue;
                    }
                    var item = NewItem(ctx, hiveName, keyPath, name, viewText);
                    AddValue(item, raw, kind);
                    result.Items.Add(item);
                }
            }
            finally
            {
                if (!ReferenceEquals(key, root)) key.Dispose();
            }
        }

        static OvalItem NewItem(OvalContext ctx, string hive, string keyPath, string name, string viewText)
        {
            var item = new OvalItem(ctx.NextItemId(), "registry_item");
            item.Add("hive", hive);
            if (keyPath != null) item.Add("key", keyPath);
            if (name != null) item.Add("name", name);
            item.Add("windows_view", viewText);
            return item;
        }

        static void AddValue(OvalItem item, object raw, RegistryValueKind kind)
        {
            switch (kind)
            {
                case RegistryValueKind.DWord:
                    item.Add("type", "reg_dword");
                    item.Add("value", unchecked((uint)(int)raw).ToString(CultureInfo.InvariantCulture), "int");
                    break;
                case RegistryValueKind.QWord:
                    item.Add("type", "reg_qword");
                    item.Add("value", unchecked((ulong)(long)raw).ToString(CultureInfo.InvariantCulture), "int");
                    break;
                case RegistryValueKind.MultiString:
                    item.Add("type", "reg_multi_sz");
                    foreach (var s in (string[])raw) item.Add("value", s);
                    break;
                case RegistryValueKind.ExpandString:
                    item.Add("type", "reg_expand_sz");
                    item.Add("value", (string)raw);
                    break;
                case RegistryValueKind.Binary:
                    item.Add("type", "reg_binary");
                    item.Add("value", BitConverter.ToString((byte[])raw ?? new byte[0]).Replace("-", ""), "binary");
                    break;
                case RegistryValueKind.String:
                    item.Add("type", "reg_sz");
                    item.Add("value", (string)raw);
                    break;
                default:
                    item.Add("type", "reg_none");
                    var bytes = raw as byte[];
                    if (bytes != null) item.Add("value", BitConverter.ToString(bytes).Replace("-", ""), "binary");
                    break;
            }
        }

        /// <summary>recurse_direction/max_depth behaviors: add sub- or super-keys of matched keys.</summary>
        void ApplyRecursion(ObjectSpec spec, CollectedObject result, OvalContext ctx, RegistryView view, string viewText, ref bool anyError)
        {
            string direction = spec.Behavior("recurse_direction", "none");
            if (direction == "none") return;
            int maxDepth;
            if (!int.TryParse(spec.Behavior("max_depth", "-1"), out maxDepth)) maxDepth = -1;
            EntityCriterion nameC;
            spec.Entities.TryGetValue("name", out nameC);

            var seeds = result.Items.Where(i => i.Get("key").Count > 0)
                .Select(i => new { Hive = i.Get("hive")[0].Value, Key = i.Get("key")[0].Value })
                .Distinct().ToList();
            foreach (var seed in seeds)
            {
                using (RegistryKey root = RegistryKey.OpenBaseKey(Hives[seed.Hive], view))
                {
                    var extra = new List<string>();
                    if (direction == "up")
                    {
                        string k = seed.Key;
                        int depth = 0;
                        while (k.Contains("\\") && (maxDepth < 0 || depth < maxDepth))
                        {
                            k = k.Substring(0, k.LastIndexOf('\\'));
                            extra.Add(k);
                            depth++;
                        }
                    }
                    else
                    {
                        var queue = new Queue<KeyValuePair<string, int>>();
                        queue.Enqueue(new KeyValuePair<string, int>(seed.Key, 0));
                        while (queue.Count > 0)
                        {
                            var cur = queue.Dequeue();
                            if (maxDepth >= 0 && cur.Value >= maxDepth) continue;
                            try
                            {
                                using (var key = root.OpenSubKey(cur.Key, false))
                                {
                                    if (key == null) continue;
                                    foreach (var sub in key.GetSubKeyNames())
                                    {
                                        string p = cur.Key + "\\" + sub;
                                        extra.Add(p);
                                        queue.Enqueue(new KeyValuePair<string, int>(p, cur.Value + 1));
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                if (!(ex is SecurityException || ex is UnauthorizedAccessException)) throw;
                                result.Messages.Add("Access is denied: " + seed.Hive + "\\" + cur.Key);
                            }
                        }
                    }
                    foreach (var k in extra)
                        CollectValues(root, seed.Hive, k, nameC, viewText, ctx, result, ref anyError);
                }
            }
        }
    }
}
