using System.Collections.Generic;
using System.Linq;
using System.Xml;

namespace PowerScap.Engine.Xccdf
{
    public class ResolvedRule
    {
        public string RuleId { get; set; }
        public string Severity { get; set; }
        public double Weight { get; set; }
        public string Role { get; set; }
        public bool Selected { get; set; }
        /// <summary>Each level (benchmark, groups..., rule) contributes a list of platform ids; levels AND, ids within a level OR.</summary>
        public List<List<string>> PlatformLevels { get; private set; }
        public List<string> PlatformIds { get { return PlatformLevels.SelectMany(l => l).ToList(); } }
        public XmlElement RuleElement { get; set; }
        public List<string> GroupPath { get; private set; }
        /// <summary>Weights of the enclosing groups (outermost first), for the default scoring model.</summary>
        public List<double> GroupWeights { get; private set; }

        public ResolvedRule()
        {
            PlatformLevels = new List<List<string>>();
            GroupPath = new List<string>();
            GroupWeights = new List<double>();
        }
    }

    public class ResolvedProfile
    {
        public string ProfileId { get; set; }
        public List<ResolvedRule> Rules { get; private set; }
        public IDictionary<string, string> Values { get; private set; }
        /// <summary>Selected groups (id → weight); used by the default scoring model.</summary>
        public IDictionary<string, double> GroupWeights { get; private set; }

        public ResolvedProfile()
        {
            Rules = new List<ResolvedRule>();
            Values = new Dictionary<string, string>();
            GroupWeights = new Dictionary<string, double>();
        }
    }

    public static class XccdfNs
    {
        public const string Xccdf = "http://checklists.nist.gov/xccdf/1.2";
        public const string Cpe2 = "http://cpe.mitre.org/language/2.0";
        public const string CpeDict = "http://cpe.mitre.org/dictionary/2.0";
        public const string OvalSystem = "http://oval.mitre.org/XMLSchema/oval-definitions-5";
        public const string OcilSystem = "http://scap.nist.gov/schema/ocil/2";
    }
}
