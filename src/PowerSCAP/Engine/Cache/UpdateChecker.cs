using System;
using System.Collections.Generic;
using System.Linq;
using PowerScap.Engine.Ncp;

namespace PowerScap.Engine.Cache
{
    public enum UpdateState { Current, UpdateAvailable, NotInCatalog, CheckFailed }

    public class UpdateInfo
    {
        public CacheEntry Cached { get; set; }
        public NcpChecklist Checklist { get; set; }
        public NcpResource Latest { get; set; }
        public UpdateState State { get; set; }
        public string Reason { get; set; }
    }

    /// <summary>
    /// Compares cached content with NCP. Releases are compared by the picked resource's file name, not the
    /// checklist version: NCP's STIG version can run ahead of the enhanced zip it links. Never changes the cache.
    /// </summary>
    public class UpdateChecker
    {
        readonly NcpClient ncp;
        readonly IHttpTransport http;

        public UpdateChecker(NcpClient ncp, IHttpTransport http)
        {
            this.ncp = ncp;
            this.http = http;
        }

        public IList<UpdateInfo> Check(IList<CacheEntry> cached)
        {
            // A checklist can hold several benchmarks (IIS Server and Site): each is followed on its own.
            var newest = cached.Where(e => !e.Imported && e.ChecklistId.HasValue)
                .GroupBy(e => e.ChecklistId.Value + "|" + (NcpClient.Series(e.FileName) ?? e.BenchmarkId))
                .Select(g => g.OrderByDescending(e => e.AddedUtc).First())
                .ToList();
            var result = new List<UpdateInfo>();
            if (newest.Count == 0) return result;

            IList<NcpChecklist> catalog;
            try
            {
                catalog = ncp.Search("", new[] { NcpClient.Scap14, NcpClient.Scap13, NcpClient.Scap12 });
            }
            catch (NcpException ex)
            {
                foreach (var e in newest) result.Add(new UpdateInfo { Cached = e, State = UpdateState.CheckFailed, Reason = ex.Message });
                return result;
            }

            foreach (var e in newest)
            {
                var info = new UpdateInfo { Cached = e };
                info.Checklist = catalog.FirstOrDefault(c => c.Id == e.ChecklistId.Value);
                info.Latest = NcpClient.PickScapResource(info.Checklist, null, e.FileName);
                if (info.Checklist == null || info.Latest == null)
                {
                    info.State = UpdateState.NotInCatalog;
                    info.Reason = "checklist " + e.ChecklistId.Value + " is no longer published with SCAP content";
                }
                else if (!string.Equals(info.Latest.FileName, e.FileName, StringComparison.OrdinalIgnoreCase))
                {
                    info.State = UpdateState.UpdateAvailable;
                    info.Reason = "new release " + info.Latest.FileName;
                }
                else
                {
                    info.State = UpdateState.Current;
                    try
                    {
                        string etag = http.Head(info.Latest.Location).ETag;
                        if (!string.IsNullOrEmpty(etag) && !string.IsNullOrEmpty(e.ETag) && etag != e.ETag)
                        {
                            info.State = UpdateState.UpdateAvailable;
                            info.Reason = "republished";
                        }
                    }
                    catch (NcpException ex)
                    {
                        info.State = UpdateState.CheckFailed;
                        info.Reason = ex.Message;
                    }
                }
                result.Add(info);
            }
            return result;
        }
    }
}
