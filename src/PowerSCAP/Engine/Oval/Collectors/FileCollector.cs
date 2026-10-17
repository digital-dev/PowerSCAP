using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace PowerScap.Engine.Oval
{
    /// <summary>Base for collectors whose objects locate files (filepath or path+filename + behaviors).</summary>
    public abstract class FileBasedCollector : ICollector
    {
        public abstract string ObjectType { get; }

        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var result = new CollectedObject(spec.ObjectId);
            var hits = FileSearch.Find(spec, result.Messages);
            bool view32 = !CollectorUtil.Is64BitView(spec);
            foreach (var hit in hits)
            {
                try
                {
                    CollectFile(spec, hit, FileSearch.Redirect(hit.FullPath, view32), view32 ? "32_bit" : "64_bit", ctx, result);
                }
                catch (Exception ex)
                {
                    if (!(ex is UnauthorizedAccessException || ex is IOException || ex is System.Security.SecurityException)) throw;
                    var err = new OvalItem(ctx.NextItemId(), ItemType);
                    AddLocation(err, hit);
                    err.Status = ItemStatus.Error;
                    err.Messages.Add(ex.Message);
                    result.Items.Add(err);
                    result.Flag = CollectedFlag.Error;
                }
            }
            if (result.Items.Count == 0 && result.Flag == CollectedFlag.Complete) result.Flag = CollectedFlag.DoesNotExist;
            return result;
        }

        protected abstract string ItemType { get; }

        protected abstract void CollectFile(ObjectSpec spec, FileHit hit, string physicalPath, string viewText, OvalContext ctx, CollectedObject result);

        protected static void AddLocation(OvalItem item, FileHit hit)
        {
            if (hit.FileName != null) item.Add("filepath", hit.FullPath);
            item.Add("path", hit.Path);
            if (hit.FileName != null) item.Add("filename", hit.FileName);
        }
    }

    /// <summary>windows-def file_object → file_item.</summary>
    public class FileCollector : FileBasedCollector
    {
        public override string ObjectType { get { return "file_object"; } }
        protected override string ItemType { get { return "file_item"; } }

        protected override void CollectFile(ObjectSpec spec, FileHit hit, string physicalPath, string viewText, OvalContext ctx, CollectedObject result)
        {
            var item = new OvalItem(ctx.NextItemId(), ItemType);
            AddLocation(item, hit);
            if (hit.FileName == null)
            {
                var d = new DirectoryInfo(physicalPath);
                AddTimes(item, d);
                item.Add("type", "FILE_ATTRIBUTE_DIRECTORY");
            }
            else
            {
                var f = new FileInfo(physicalPath);
                AddOwner(item, () => f.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(NTAccount)));
                item.Add("size", f.Length.ToString(CultureInfo.InvariantCulture), "int");
                AddTimes(item, f);
                item.Add("type", "FILE_TYPE_DISK");
                AddVersionInfo(item, physicalPath);
            }
            item.Add("windows_view", viewText);
            result.Items.Add(item);
        }

        static void AddTimes(OvalItem item, FileSystemInfo info)
        {
            item.Add("a_time", info.LastAccessTimeUtc.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture), "int");
            item.Add("c_time", info.CreationTimeUtc.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture), "int");
            item.Add("m_time", info.LastWriteTimeUtc.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture), "int");
        }

        static void AddOwner(OvalItem item, Func<IdentityReference> owner)
        {
            try
            {
                var id = owner();
                item.Add("owner", id == null ? "" : id.Value);
            }
            catch (Exception)
            {
                var e = new OvalEntity("owner", null);
                e.Status = ItemStatus.Error;
                item.Entities.Add(e);
            }
        }

        static void AddVersionInfo(OvalItem item, string path)
        {
            FileVersionInfo v;
            try { v = FileVersionInfo.GetVersionInfo(path); }
            catch (Exception) { v = null; }
            bool hasVersion = v != null && (v.FileMajorPart | v.FileMinorPart | v.FileBuildPart | v.FilePrivatePart) != 0;
            if (hasVersion)
                item.Add("version", string.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}.{3}", v.FileMajorPart, v.FileMinorPart, v.FileBuildPart, v.FilePrivatePart), "version");
            else
                item.Entities.Add(OvalEntity.Missing("version"));
            AddString(item, "company", v == null ? null : v.CompanyName);
            AddString(item, "internal_name", v == null ? null : v.InternalName);
            AddString(item, "language", v == null ? null : v.Language);
            AddString(item, "original_filename", v == null ? null : v.OriginalFilename);
            AddString(item, "product_name", v == null ? null : v.ProductName);
            if (v != null && (v.ProductMajorPart | v.ProductMinorPart | v.ProductBuildPart | v.ProductPrivatePart) != 0)
                item.Add("product_version", string.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}.{3}", v.ProductMajorPart, v.ProductMinorPart, v.ProductBuildPart, v.ProductPrivatePart), "version");
            else
                item.Entities.Add(OvalEntity.Missing("product_version"));
        }

        static void AddString(OvalItem item, string name, string value)
        {
            if (string.IsNullOrEmpty(value)) item.Entities.Add(OvalEntity.Missing(name));
            else item.Add(name, value);
        }
    }
}
