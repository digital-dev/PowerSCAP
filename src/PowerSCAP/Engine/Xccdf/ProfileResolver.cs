using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Xml;
using PowerScap.Engine.Content;

namespace PowerScap.Engine.Xccdf
{
    /// <summary>Applies an XCCDF 1.2 profile (extends, select, refine-rule, refine-value, set-value) to the benchmark.</summary>
    public static class ProfileResolver
    {
        class Refinement
        {
            public double? Weight;
            public string Severity, Role;
        }

        public static ResolvedProfile Resolve(ScapContent content, string profileId)
        {
            XmlElement benchmark = content.Benchmark.DocumentElement;
            string ns = benchmark.NamespaceURI;
            var profiles = Children(benchmark, "Profile", ns).ToDictionary(p => p.GetAttribute("id"), p => p);

            var chain = new List<XmlElement>();
            if (!string.IsNullOrEmpty(profileId))
            {
                XmlElement p;
                if (!profiles.TryGetValue(profileId, out p)) throw new ArgumentException("Profile not found: " + profileId);
                var seen = new HashSet<string>();
                while (p != null && seen.Add(p.GetAttribute("id")))
                {
                    chain.Insert(0, p);
                    string parent = p.GetAttribute("extends");
                    p = string.IsNullOrEmpty(parent) || !profiles.ContainsKey(parent) ? null : profiles[parent];
                }
            }

            var selections = new Dictionary<string, bool>();
            var refinements = new Dictionary<string, Refinement>();
            var valueSelectors = new Dictionary<string, string>();
            var setValues = new Dictionary<string, string>();
            foreach (var p in chain)
            {
                foreach (XmlElement e in p.ChildNodes.OfType<XmlElement>())
                {
                    string id = e.GetAttribute("idref");
                    switch (e.LocalName)
                    {
                        case "select":
                            selections[id] = e.GetAttribute("selected") == "true" || e.GetAttribute("selected") == "1";
                            break;
                        case "refine-rule":
                            Refinement r;
                            if (!refinements.TryGetValue(id, out r)) refinements[id] = r = new Refinement();
                            if (e.HasAttribute("weight")) r.Weight = double.Parse(e.GetAttribute("weight"), CultureInfo.InvariantCulture);
                            if (e.HasAttribute("severity")) r.Severity = e.GetAttribute("severity");
                            if (e.HasAttribute("role")) r.Role = e.GetAttribute("role");
                            break;
                        case "refine-value":
                            valueSelectors[id] = e.GetAttribute("selector");
                            setValues.Remove(id);
                            break;
                        case "set-value":
                            setValues[id] = e.InnerText;
                            break;
                    }
                }
            }

            var result = new ResolvedProfile { ProfileId = profileId };
            var benchmarkPlatforms = Platforms(benchmark, ns);
            Walk(benchmark, ns, true, new List<List<string>> { benchmarkPlatforms }, new List<string>(), new List<double>(),
                selections, refinements, valueSelectors, setValues, result);
            return result;
        }

        static void Walk(XmlElement container, string ns, bool ancestorsSelected, List<List<string>> platformLevels,
            List<string> groupPath, List<double> groupWeights,
            Dictionary<string, bool> selections, Dictionary<string, Refinement> refinements,
            Dictionary<string, string> valueSelectors, Dictionary<string, string> setValues, ResolvedProfile result)
        {
            foreach (XmlElement e in container.ChildNodes.OfType<XmlElement>())
            {
                if (e.NamespaceURI != ns) continue;
                string id = e.GetAttribute("id");
                switch (e.LocalName)
                {
                    case "Value":
                        result.Values[id] = ResolveValue(e, ns, valueSelectors, setValues);
                        break;
                    case "Group":
                    {
                        bool selected = Selected(e, id, selections) && ancestorsSelected;
                        double weight = Weight(e, id, refinements);
                        if (selected) result.GroupWeights[id] = weight;
                        var levels = new List<List<string>>(platformLevels) { Platforms(e, ns) };
                        Walk(e, ns, selected, levels, new List<string>(groupPath) { id }, new List<double>(groupWeights) { weight },
                            selections, refinements, valueSelectors, setValues, result);
                        break;
                    }
                    case "Rule":
                    {
                        Refinement r;
                        refinements.TryGetValue(id, out r);
                        var rule = new ResolvedRule
                        {
                            RuleId = id,
                            Selected = Selected(e, id, selections) && ancestorsSelected,
                            Weight = Weight(e, id, refinements),
                            Severity = r != null && r.Severity != null ? r.Severity : (e.HasAttribute("severity") ? e.GetAttribute("severity") : "unknown"),
                            Role = r != null && r.Role != null ? r.Role : (e.HasAttribute("role") ? e.GetAttribute("role") : "full"),
                            RuleElement = e
                        };
                        rule.PlatformLevels.AddRange(platformLevels);
                        rule.PlatformLevels.Add(Platforms(e, ns));
                        rule.PlatformLevels.RemoveAll(l => l.Count == 0);
                        rule.GroupPath.AddRange(groupPath);
                        rule.GroupWeights.AddRange(groupWeights);
                        result.Rules.Add(rule);
                        break;
                    }
                }
            }
        }

        static bool Selected(XmlElement item, string id, Dictionary<string, bool> selections)
        {
            bool s;
            if (selections.TryGetValue(id, out s)) return s;
            string attr = item.GetAttribute("selected");
            return attr != "false" && attr != "0";
        }

        static double Weight(XmlElement item, string id, Dictionary<string, Refinement> refinements)
        {
            Refinement r;
            if (refinements.TryGetValue(id, out r) && r.Weight.HasValue) return r.Weight.Value;
            return item.HasAttribute("weight") ? double.Parse(item.GetAttribute("weight"), CultureInfo.InvariantCulture) : 1.0;
        }

        static string ResolveValue(XmlElement valueElement, string ns, Dictionary<string, string> selectors, Dictionary<string, string> setValues)
        {
            string id = valueElement.GetAttribute("id");
            string set;
            if (setValues.TryGetValue(id, out set)) return set;
            var values = Children(valueElement, "value", ns).ToList();
            string selector;
            if (selectors.TryGetValue(id, out selector))
            {
                var hit = values.FirstOrDefault(v => v.GetAttribute("selector") == selector);
                if (hit != null) return hit.InnerText;
            }
            var dflt = values.FirstOrDefault(v => !v.HasAttribute("selector") || v.GetAttribute("selector") == "");
            return dflt != null ? dflt.InnerText : (values.Count > 0 ? values[0].InnerText : string.Empty);
        }

        static List<string> Platforms(XmlElement item, string ns)
        {
            return Children(item, "platform", ns).Select(p => p.GetAttribute("idref")).ToList();
        }

        static IEnumerable<XmlElement> Children(XmlElement parent, string localName, string ns)
        {
            return parent.ChildNodes.OfType<XmlElement>().Where(e => e.LocalName == localName && e.NamespaceURI == ns);
        }
    }
}
