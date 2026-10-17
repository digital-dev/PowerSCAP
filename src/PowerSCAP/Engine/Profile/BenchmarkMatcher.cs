using System;
using System.Collections.Generic;
using System.Linq;
using PowerScap.Engine.Ncp;

namespace PowerScap.Engine.Profile
{
    public class BenchmarkMatch
    {
        public NcpChecklist Checklist { get; set; }
        public NcpResource Resource { get; set; }
        public DetectedProduct Product { get; set; }

        public override string ToString() { return Checklist.Name + " (for " + Product.Name + ")"; }
    }

    /// <summary>
    /// Pre-selects the NCP checklists for the detected products (target name equality). A convenience only:
    /// the content's own CPE applicability still decides at scan time.
    /// </summary>
    public static class BenchmarkMatcher
    {
        public static IList<BenchmarkMatch> Match(SystemProfile profile, IList<NcpChecklist> catalog)
        {
            var result = new List<BenchmarkMatch>();
            foreach (var c in catalog)
            {
                var product = profile.Products.FirstOrDefault(p => c.Targets.Any(t => string.Equals(t, p.NcpTarget, StringComparison.OrdinalIgnoreCase)));
                if (product == null) continue;
                var resource = NcpClient.PickScapResource(c);
                if (resource == null) continue;
                result.Add(new BenchmarkMatch { Checklist = c, Resource = resource, Product = product });
            }
            return result.OrderBy(m => m.Checklist.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }
    }
}
