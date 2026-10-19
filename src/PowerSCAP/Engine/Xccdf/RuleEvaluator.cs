using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using PowerScap.Engine.Content;
using PowerScap.Engine.Oval;

namespace PowerScap.Engine.Xccdf
{
    public enum XccdfResult { Pass, Fail, Error, Unknown, NotApplicable, NotChecked, NotSelected, Informational, Fixed }

    public class RuleResult
    {
        public ResolvedRule Rule { get; set; }
        public XccdfResult Result { get; set; }
        public List<DefinitionResult> OvalResults { get; private set; }
        public string CheckSystem { get; set; }
        public string CheckHref { get; set; }
        public string CheckName { get; set; }
        public string Message { get; set; }

        public RuleResult() { OvalResults = new List<DefinitionResult>(); }
    }

    public class ScanProgress
    {
        public int Done { get; set; }
        public int Total { get; set; }
        public string CurrentRuleId { get; set; }
    }

    /// <summary>Evaluates resolved XCCDF rules: selection, CPE applicability, OVAL/complex checks (XCCDF 1.2 §7.2, SP 800-126r3 result mapping).</summary>
    public static class RuleEvaluator
    {
        public static List<RuleResult> Evaluate(ScapContent content, ResolvedProfile profile, CollectorRegistry collectors, IProgress<ScanProgress> progress)
        {
            return Evaluate(content, profile, collectors, progress, System.Threading.CancellationToken.None);
        }

        /// <summary>Cancellation is checked between rules.</summary>
        public static List<RuleResult> Evaluate(ScapContent content, ResolvedProfile profile, CollectorRegistry collectors, IProgress<ScanProgress> progress,
            System.Threading.CancellationToken cancel)
        {
            return Evaluate(content, profile, collectors, progress, cancel, false);
        }

        /// <summary>
        /// With <paramref name="ignorePlatforms"/>, rules are evaluated even where the content's CPE platform checks rule the
        /// machine out. That is not a SCAP evaluation: its results are for the "evaluate anyway" report only, never for
        /// SCAP results, scores or checklists.
        /// </summary>
        public static List<RuleResult> Evaluate(ScapContent content, ResolvedProfile profile, CollectorRegistry collectors, IProgress<ScanProgress> progress,
            System.Threading.CancellationToken cancel, bool ignorePlatforms)
        {
            collectors = collectors ?? CollectorRegistry.CreateDefault();
            var cpe = new CpeApplicability(content, collectors);
            var externalValues = CollectExports(profile);
            var evaluators = new Dictionary<string, OvalEvaluator>(StringComparer.Ordinal);
            var results = new List<RuleResult>();
            int done = 0, total = profile.Rules.Count;

            foreach (var rule in profile.Rules)
            {
                cancel.ThrowIfCancellationRequested();
                if (progress != null) progress.Report(new ScanProgress { Done = done, Total = total, CurrentRuleId = rule.RuleId });
                results.AddRange(EvaluateRule(content, rule, ignorePlatforms ? null : cpe, collectors, externalValues, evaluators));
                done++;
            }
            if (progress != null) progress.Report(new ScanProgress { Done = done, Total = total, CurrentRuleId = null });
            return results;
        }

        /// <summary>check-export: XCCDF Value → OVAL external variable, using the profile's resolved values.</summary>
        static Dictionary<string, IList<string>> CollectExports(ResolvedProfile profile)
        {
            var map = new Dictionary<string, IList<string>>(StringComparer.Ordinal);
            foreach (var rule in profile.Rules)
                foreach (XmlElement export in rule.RuleElement.GetElementsByTagName("check-export", rule.RuleElement.NamespaceURI))
                {
                    string value;
                    if (profile.Values.TryGetValue(export.GetAttribute("value-id"), out value))
                        map[export.GetAttribute("export-name")] = new List<string> { value };
                }
            return map;
        }

        static IEnumerable<RuleResult> EvaluateRule(ScapContent content, ResolvedRule rule, CpeApplicability cpe, CollectorRegistry collectors,
            Dictionary<string, IList<string>> externalValues, Dictionary<string, OvalEvaluator> evaluators)
        {
            if (!rule.Selected) return new[] { Simple(rule, XccdfResult.NotSelected) };
            if (cpe != null && !cpe.IsApplicable(rule)) return new[] { Simple(rule, XccdfResult.NotApplicable) };
            if (rule.Role == "unchecked") return new[] { Simple(rule, XccdfResult.NotChecked) };

            string ns = rule.RuleElement.NamespaceURI;
            var checks = rule.RuleElement.ChildNodes.OfType<XmlElement>().Where(e => e.NamespaceURI == ns).ToList();
            XmlElement complex = checks.FirstOrDefault(e => e.LocalName == "complex-check");
            if (complex != null)
            {
                var r = Simple(rule, XccdfResult.NotChecked);
                r.Result = EvaluateComplex(content, complex, collectors, externalValues, evaluators, r);
                r.CheckSystem = "complex-check";
                return new[] { r };
            }

            var all = checks.Where(e => e.LocalName == "check").ToList();
            XmlElement oval = all.FirstOrDefault(c => c.GetAttribute("system") == XccdfNs.OvalSystem);
            if (oval == null)
            {
                var r = Simple(rule, XccdfResult.NotChecked);
                if (all.Count > 0) r.CheckSystem = all[0].GetAttribute("system");
                return new[] { r };
            }

            XmlElement contentRef = oval.ChildNodes.OfType<XmlElement>().FirstOrDefault(e => e.LocalName == "check-content-ref");
            if (contentRef != null && !contentRef.HasAttribute("name") && oval.GetAttribute("multi-check") == "true")
                return MultiCheck(content, rule, oval, contentRef, collectors, externalValues, evaluators);

            var single = Simple(rule, XccdfResult.NotChecked);
            single.Result = EvaluateCheck(content, oval, collectors, externalValues, evaluators, single);
            return new[] { single };
        }

        static RuleResult Simple(ResolvedRule rule, XccdfResult result)
        {
            return new RuleResult { Rule = rule, Result = result };
        }

        static XccdfResult EvaluateCheck(ScapContent content, XmlElement check, CollectorRegistry collectors,
            Dictionary<string, IList<string>> externalValues, Dictionary<string, OvalEvaluator> evaluators, RuleResult into)
        {
            into.CheckSystem = check.GetAttribute("system");
            if (into.CheckSystem != XccdfNs.OvalSystem) return XccdfResult.NotChecked;
            XmlElement contentRef = check.ChildNodes.OfType<XmlElement>().FirstOrDefault(e => e.LocalName == "check-content-ref");
            if (contentRef == null) { into.Message = "check has no check-content-ref"; return XccdfResult.Error; }
            into.CheckHref = contentRef.GetAttribute("href");
            into.CheckName = contentRef.GetAttribute("name");

            OvalEvaluator ev = Evaluator(content, into.CheckHref, collectors, externalValues, evaluators);
            if (ev == null) { into.Message = "Check content not found: " + into.CheckHref; return XccdfResult.Error; }
            DefinitionResult def = ev.Evaluate(into.CheckName);
            into.OvalResults.Add(def);
            XccdfResult r = Map(def.Result);
            return check.GetAttribute("negate") == "true" ? Negate(r) : r;
        }

        static IEnumerable<RuleResult> MultiCheck(ScapContent content, ResolvedRule rule, XmlElement check, XmlElement contentRef,
            CollectorRegistry collectors, Dictionary<string, IList<string>> externalValues, Dictionary<string, OvalEvaluator> evaluators)
        {
            string href = contentRef.GetAttribute("href");
            OvalEvaluator ev = Evaluator(content, href, collectors, externalValues, evaluators);
            if (ev == null) return new[] { new RuleResult { Rule = rule, Result = XccdfResult.Error, Message = "Check content not found: " + href } };
            var list = new List<RuleResult>();
            foreach (XmlElement def in ev.Context.Definitions.GetElementsByTagName("definition", OvalContext.DefNs))
            {
                var d = ev.Evaluate(def.GetAttribute("id"));
                var rr = new RuleResult { Rule = rule, CheckSystem = XccdfNs.OvalSystem, CheckHref = href, CheckName = d.DefinitionId };
                rr.OvalResults.Add(d);
                rr.Result = check.GetAttribute("negate") == "true" ? Negate(Map(d.Result)) : Map(d.Result);
                list.Add(rr);
            }
            return list;
        }

        static XccdfResult EvaluateComplex(ScapContent content, XmlElement complex, CollectorRegistry collectors,
            Dictionary<string, IList<string>> externalValues, Dictionary<string, OvalEvaluator> evaluators, RuleResult into)
        {
            var parts = new List<OvalResult>();
            foreach (XmlElement e in complex.ChildNodes.OfType<XmlElement>())
            {
                if (e.LocalName == "check") parts.Add(ToOval(EvaluateCheck(content, e, collectors, externalValues, evaluators, into)));
                else if (e.LocalName == "complex-check") parts.Add(ToOval(EvaluateComplex(content, e, collectors, externalValues, evaluators, into)));
            }
            XccdfResult r = Map(OvalLogic.Combine(complex.GetAttribute("operator") == "OR" ? "OR" : "AND", parts));
            return complex.GetAttribute("negate") == "true" ? Negate(r) : r;
        }

        static OvalEvaluator Evaluator(ScapContent content, string href, CollectorRegistry collectors,
            Dictionary<string, IList<string>> externalValues, Dictionary<string, OvalEvaluator> evaluators)
        {
            OvalEvaluator ev;
            if (evaluators.TryGetValue(href, out ev)) return ev;
            XmlDocument doc;
            if (!content.CheckComponents.TryGetValue(href, out doc) || doc.DocumentElement.LocalName != "oval_definitions") return null;
            ev = new OvalEvaluator(doc, collectors, externalValues);
            evaluators[href] = ev;
            return ev;
        }

        /// <summary>OVAL definition result → XCCDF rule result (SP 800-126r3 Table 6).</summary>
        public static XccdfResult Map(OvalResult r)
        {
            switch (r)
            {
                case OvalResult.True: return XccdfResult.Pass;
                case OvalResult.False: return XccdfResult.Fail;
                case OvalResult.Error: return XccdfResult.Error;
                case OvalResult.Unknown: return XccdfResult.Unknown;
                case OvalResult.NotApplicable: return XccdfResult.NotApplicable;
                default: return XccdfResult.NotChecked;
            }
        }

        static OvalResult ToOval(XccdfResult r)
        {
            switch (r)
            {
                case XccdfResult.Pass: case XccdfResult.Fixed: return OvalResult.True;
                case XccdfResult.Fail: return OvalResult.False;
                case XccdfResult.Error: return OvalResult.Error;
                case XccdfResult.Unknown: return OvalResult.Unknown;
                case XccdfResult.NotApplicable: return OvalResult.NotApplicable;
                default: return OvalResult.NotEvaluated;
            }
        }

        static XccdfResult Negate(XccdfResult r)
        {
            if (r == XccdfResult.Pass) return XccdfResult.Fail;
            if (r == XccdfResult.Fail) return XccdfResult.Pass;
            return r;
        }
    }
}
