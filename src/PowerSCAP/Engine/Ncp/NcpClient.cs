using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace PowerScap.Engine.Ncp
{
    public class NcpChecklist
    {
        public NcpChecklist()
        {
            Targets = new List<string>();
            Resources = new List<NcpResource>();
        }

        public int Id { get; set; }
        public string Name { get; set; }
        public string Version { get; set; }
        public string Authority { get; set; }
        public DateTime LastModified { get; set; }
        public IList<string> Targets { get; private set; }
        public IList<NcpResource> Resources { get; private set; }

        public override string ToString() { return Name + " (" + Version + ")"; }
    }

    public class NcpResource
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Location { get; set; }
        public string TypeName { get; set; }

        /// <summary>Last segment of the download URL.</summary>
        public string FileName
        {
            get
            {
                if (string.IsNullOrEmpty(Location)) return null;
                string path = Location.Split('?')[0];
                return Uri.UnescapeDataString(path.Substring(path.LastIndexOf('/') + 1));
            }
        }
    }

    /// <summary>NIST National Checklist Program catalog (public JSON API).</summary>
    public class NcpClient
    {
        public const string BaseUrl = "https://ncp.nist.gov/public/service/rest/json/ncp/checklist/repository";
        public const int Scap12 = 14, Scap13 = 17, Scap14 = 29;

        /// <summary>SCAP resource types in preference order: NIWC enhanced 1.4, then DISA 1.3, then 1.2.</summary>
        static readonly string[] Preference = { "SCAP 1.4 Content", "SCAP 1.3 Content", "SCAP 1.2 Content" };
        static readonly Regex NonWindows = new Regex(@"linux|rhel|red hat|ubuntu|suse|macos|solaris|aix|hp-ux", RegexOptions.IgnoreCase);

        readonly IHttpTransport http;

        public NcpClient(IHttpTransport http)
        {
            this.http = http;
            PageSize = 200;
        }

        public int PageSize { get; set; }

        /// <summary>All checklists matching the keyword and content types, every page, deduplicated by id.</summary>
        public IList<NcpChecklist> Search(string keyword, int[] contentTypeIds)
        {
            var result = new List<NcpChecklist>();
            var seen = new HashSet<int>();
            int offset = 0;
            while (true)
            {
                string url = BaseUrl + "/search/results?offset=" + offset + "&rowCount=" + PageSize +
                    "&contentTypeIdList=" + string.Join(",", contentTypeIds ?? new int[0]) +
                    "&keyword=" + Uri.EscapeDataString(keyword ?? "") + "&sortOrder=4&sortDirection=2";
                var grid = Grid(url);
                var page = grid.ContainsKey("checklists") ? grid["checklists"] as IEnumerable : null;
                int count = 0;
                if (page != null)
                    foreach (var o in page)
                    {
                        count++;
                        var c = ParseChecklist(o as IDictionary<string, object>);
                        if (c != null && seen.Add(c.Id)) result.Add(c);
                    }
                int total = Int(grid, "totalResults");
                offset += count;
                if (count == 0 || offset >= total) break;
            }
            return result;
        }

        IDictionary<string, object> Grid(string url)
        {
            string body = http.GetString(url);
            object parsed;
            try { parsed = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.DeserializeObject(body); }
            catch (ArgumentException ex) { throw new NcpException(url, "NCP returned a response that is not JSON", ex); }
            var root = parsed as IDictionary<string, object>;
            var response = root != null && root.ContainsKey("response") ? root["response"] as IEnumerable : null;
            var first = response == null ? null : response.Cast<object>().FirstOrDefault() as IDictionary<string, object>;
            var grid = first != null && first.ContainsKey("grid") ? first["grid"] as IDictionary<string, object> : null;
            if (grid == null) throw new NcpException(url, "NCP returned JSON without a result grid");
            return grid;
        }

        static NcpChecklist ParseChecklist(IDictionary<string, object> o)
        {
            if (o == null || !o.ContainsKey("checklistId")) return null;
            var c = new NcpChecklist
            {
                Id = Int(o, "checklistId"),
                Name = Str(o, "name"),
                Version = Str(o, "version"),
                Authority = Str(o, "authority")
            };
            DateTime lm;
            if (DateTime.TryParse(Str(o, "lastModified"), CultureInfo.InvariantCulture, DateTimeStyles.None, out lm)) c.LastModified = lm;
            var targets = o.ContainsKey("targets") ? o["targets"] as IEnumerable : null;
            if (targets != null) foreach (var t in targets) if (t != null) c.Targets.Add(t.ToString());
            var resources = o.ContainsKey("resources") ? o["resources"] as IEnumerable : null;
            if (resources != null)
                foreach (var r in resources.OfType<IDictionary<string, object>>())
                    c.Resources.Add(new NcpResource { Id = Int(r, "checklistResourceId"), Title = Str(r, "title"), Location = Str(r, "location"), TypeName = Str(r, "resourceTypeName") });
            return c;
        }

        /// <summary>The SCAP resource to use for a Windows host, or null when the checklist has none.</summary>
        public static NcpResource PickScapResource(NcpChecklist c)
        {
            return PickScapResource(c, null);
        }

        /// <summary>As PickScapResource, trying the preferred resource type ("SCAP 1.3 Content") first.</summary>
        public static NcpResource PickScapResource(NcpChecklist c, string preferredType)
        {
            if (c == null) return null;
            var order = string.IsNullOrEmpty(preferredType) ? Preference : new[] { preferredType }.Concat(Preference);
            foreach (var type in order)
            {
                var pick = c.Resources.FirstOrDefault(r => string.Equals(r.TypeName, type, StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrEmpty(r.Location) && !NonWindows.IsMatch(r.Title ?? ""));
                if (pick != null) return pick;
            }
            return null;
        }

        static string Str(IDictionary<string, object> o, string key)
        {
            object v;
            return o.TryGetValue(key, out v) && v != null ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;
        }

        static int Int(IDictionary<string, object> o, string key)
        {
            object v;
            return o.TryGetValue(key, out v) && v != null ? Convert.ToInt32(v, CultureInfo.InvariantCulture) : 0;
        }
    }
}
