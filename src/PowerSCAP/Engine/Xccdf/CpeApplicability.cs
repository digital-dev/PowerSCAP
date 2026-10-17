using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using PowerScap.Engine.Content;
using PowerScap.Engine.Oval;

namespace PowerScap.Engine.Xccdf
{
    /// <summary>
    /// Decides XCCDF platform applicability: CPE names via the CPE dictionary's OVAL checks,
    /// "#id" platforms via CPE applicability language logical tests. Results are cached.
    /// </summary>
    public class CpeApplicability
    {
        readonly ScapContent content;
        readonly CollectorRegistry collectors;
        readonly Dictionary<string, OvalEvaluator> evaluators = new Dictionary<string, OvalEvaluator>(StringComparer.Ordinal);
        readonly Dictionary<string, bool> cache = new Dictionary<string, bool>(StringComparer.Ordinal);
        readonly Dictionary<string, XmlElement> platforms = new Dictionary<string, XmlElement>(StringComparer.Ordinal);

        public CpeApplicability(ScapContent content, CollectorRegistry collectors)
        {
            this.content = content;
            this.collectors = collectors;
            foreach (XmlElement p in content.Benchmark.GetElementsByTagName("platform", XccdfNs.Cpe2))
                platforms[p.GetAttribute("id")] = p;
        }

        /// <summary>True when any id in the list is applicable (or the list is empty).</summary>
        public bool IsApplicable(IList<string> platformIds)
        {
            if (platformIds == null || platformIds.Count == 0) return true;
            return platformIds.Any(IsPlatformApplicable);
        }

        /// <summary>All levels must be applicable; within a level any id suffices.</summary>
        public bool IsApplicable(ResolvedRule rule)
        {
            return rule.PlatformLevels.All(level => IsApplicable(level));
        }

        bool IsPlatformApplicable(string id)
        {
            bool cached;
            if (cache.TryGetValue(id, out cached)) return cached;
            bool result;
            if (id.StartsWith("#"))
            {
                XmlElement platform;
                result = platforms.TryGetValue(id.Substring(1), out platform) && EvaluatePlatform(platform);
            }
            else
            {
                result = EvaluateCpeName(id) == OvalResult.True;
            }
            cache[id] = result;
            return result;
        }

        bool EvaluatePlatform(XmlElement platform)
        {
            XmlElement test = platform.ChildNodes.OfType<XmlElement>().FirstOrDefault(e => e.LocalName == "logical-test");
            return test != null && EvaluateLogicalTest(test) == OvalResult.True;
        }

        OvalResult EvaluateLogicalTest(XmlElement test)
        {
            var results = new List<OvalResult>();
            foreach (XmlElement e in test.ChildNodes.OfType<XmlElement>())
            {
                switch (e.LocalName)
                {
                    case "logical-test": results.Add(EvaluateLogicalTest(e)); break;
                    case "fact-ref": results.Add(EvaluateCpeName(e.GetAttribute("name"))); break;
                    case "check-fact-ref": results.Add(EvaluateCheck(e.GetAttribute("system"), e.GetAttribute("href"), e.GetAttribute("id-ref"))); break;
                }
            }
            var combined = OvalLogic.Combine(test.GetAttribute("operator") == "OR" ? "OR" : "AND", results);
            return test.GetAttribute("negate") == "true" ? OvalLogic.Negate(combined) : combined;
        }

        OvalResult EvaluateCpeName(string name)
        {
            if (content.CpeDictionary == null) return OvalResult.False;
            foreach (XmlElement item in content.CpeDictionary.GetElementsByTagName("cpe-item", XccdfNs.CpeDict))
            {
                if (!string.Equals(item.GetAttribute("name"), name, StringComparison.OrdinalIgnoreCase)) continue;
                foreach (XmlElement check in item.GetElementsByTagName("check", XccdfNs.CpeDict))
                    if (check.GetAttribute("system") == XccdfNs.OvalSystem)
                        return EvaluateCheck(XccdfNs.OvalSystem, check.GetAttribute("href"), check.InnerText.Trim());
            }
            return OvalResult.False;
        }

        OvalResult EvaluateCheck(string system, string href, string definitionId)
        {
            if (system != XccdfNs.OvalSystem) return OvalResult.Error;
            OvalEvaluator ev;
            if (!evaluators.TryGetValue(href, out ev))
            {
                XmlDocument doc;
                if (!content.CpeChecks.TryGetValue(href, out doc) && !content.CheckComponents.TryGetValue(href, out doc))
                    return OvalResult.Error;
                ev = new OvalEvaluator(doc, collectors, null);
                evaluators[href] = ev;
            }
            return ev.Evaluate(definitionId).Result;
        }
    }
}
