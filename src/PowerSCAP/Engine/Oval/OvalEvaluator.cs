using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;

namespace PowerScap.Engine.Oval
{
    public class ItemResult
    {
        public OvalItem Item { get; set; }
        public OvalResult Result { get; set; }
    }

    public class TestResult
    {
        public string TestId { get; set; }
        public string TestType { get; set; }
        public string Comment { get; set; }
        public string Check { get; set; }
        public string CheckExistence { get; set; }
        public string StateOperator { get; set; }
        public OvalResult Result { get; set; }
        public CollectedObject Object { get; set; }
        public List<ItemResult> Items { get; private set; }
        public List<string> StateIds { get; private set; }
        public List<string> Messages { get; private set; }

        public TestResult()
        {
            Items = new List<ItemResult>();
            StateIds = new List<string>();
            Messages = new List<string>();
        }
    }

    public class DefinitionResult
    {
        public string DefinitionId { get; set; }
        public string Title { get; set; }
        public string Class { get; set; }
        public OvalResult Result { get; set; }
        public List<TestResult> Tests { get; private set; }
        public List<string> Messages { get; private set; }

        public DefinitionResult()
        {
            Tests = new List<TestResult>();
            Messages = new List<string>();
        }
    }

    /// <summary>Evaluates OVAL definitions and tests (OVAL 5.11.2 §5), memoizing tests and definitions.</summary>
    public class OvalEvaluator
    {
        readonly OvalContext ctx;
        readonly Dictionary<string, DefinitionResult> definitions = new Dictionary<string, DefinitionResult>(StringComparer.Ordinal);
        readonly Dictionary<string, TestResult> tests = new Dictionary<string, TestResult>(StringComparer.Ordinal);
        readonly HashSet<string> inProgress = new HashSet<string>(StringComparer.Ordinal);

        public OvalContext Context { get { return ctx; } }

        public OvalEvaluator(XmlDocument definitionsDocument, CollectorRegistry collectors, IDictionary<string, IList<string>> externalValues)
        {
            ctx = new OvalContext(definitionsDocument, collectors ?? new CollectorRegistry());
            ctx.Variables = new VariableResolver(ctx, externalValues);
        }

        public IEnumerable<TestResult> AllTestResults() { return tests.Values; }
        public IEnumerable<DefinitionResult> AllDefinitionResults() { return definitions.Values; }

        public DefinitionResult Evaluate(string definitionId)
        {
            DefinitionResult r;
            if (definitions.TryGetValue(definitionId, out r)) return r;

            r = new DefinitionResult();
            r.DefinitionId = definitionId;
            XmlElement def = ctx.Find(definitionId);
            if (def == null || def.LocalName != "definition")
            {
                r.Result = OvalResult.Error;
                r.Messages.Add("Definition not found: " + definitionId);
                definitions[definitionId] = r;
                return r;
            }
            if (!inProgress.Add(definitionId))
            {
                r.Result = OvalResult.Error;
                r.Messages.Add("Circular extend_definition: " + definitionId);
                return r;
            }
            try
            {
                r.Class = def.GetAttribute("class");
                XmlElement title = Find(def, "metadata", "title");
                if (title != null) r.Title = title.InnerText;
                XmlElement criteria = Child(def, "criteria");
                if (criteria == null)
                {
                    r.Result = OvalResult.NotEvaluated;
                }
                else
                {
                    bool notApplicable = false;
                    OvalResult result = EvaluateNode(criteria, r, ref notApplicable);
                    r.Result = notApplicable ? OvalResult.NotApplicable : result;
                }
            }
            finally { inProgress.Remove(definitionId); }
            definitions[definitionId] = r;
            return r;
        }

        OvalResult EvaluateNode(XmlElement node, DefinitionResult owner, ref bool notApplicable)
        {
            OvalResult result;
            switch (node.LocalName)
            {
                case "criteria":
                {
                    var children = new List<OvalResult>();
                    foreach (XmlNode n in node.ChildNodes)
                    {
                        var e = n as XmlElement;
                        if (e == null || e.NamespaceURI != OvalContext.DefNs) continue;
                        if (e.LocalName == "criteria" || e.LocalName == "criterion" || e.LocalName == "extend_definition")
                            children.Add(EvaluateNode(e, owner, ref notApplicable));
                    }
                    string op = node.HasAttribute("operator") ? node.GetAttribute("operator") : "AND";
                    result = OvalLogic.Combine(op, children);
                    break;
                }
                case "criterion":
                {
                    TestResult t = EvaluateTest(node.GetAttribute("test_ref"));
                    if (!owner.Tests.Contains(t)) owner.Tests.Add(t);
                    result = t.Result;
                    break;
                }
                case "extend_definition":
                {
                    DefinitionResult d = Evaluate(node.GetAttribute("definition_ref"));
                    foreach (var t in d.Tests) if (!owner.Tests.Contains(t)) owner.Tests.Add(t);
                    result = d.Result;
                    break;
                }
                default:
                    result = OvalResult.Error;
                    break;
            }
            if (node.GetAttribute("negate") == "true") result = OvalLogic.Negate(result);
            if (node.GetAttribute("applicability_check") == "true" && result == OvalResult.False) notApplicable = true;
            return result;
        }

        public TestResult EvaluateTest(string testId)
        {
            TestResult t;
            if (tests.TryGetValue(testId, out t)) return t;
            t = new TestResult();
            t.TestId = testId;
            tests[testId] = t;

            XmlElement test = ctx.Find(testId);
            if (test == null)
            {
                t.Result = OvalResult.Error;
                t.Messages.Add("Test not found: " + testId);
                return t;
            }
            t.TestType = test.LocalName;
            t.Comment = test.GetAttribute("comment");
            t.Check = test.HasAttribute("check") ? test.GetAttribute("check") : "all";
            t.CheckExistence = test.HasAttribute("check_existence") ? test.GetAttribute("check_existence") : "at_least_one_exists";
            t.StateOperator = test.HasAttribute("state_operator") ? test.GetAttribute("state_operator") : "AND";

            XmlElement objectRef = ChildAnyNs(test, "object");
            if (objectRef == null)
            {
                t.Result = OvalResult.Unknown; // e.g. unknown_test
                return t;
            }
            XmlElement obj = ctx.FindObject(objectRef.GetAttribute("object_ref"));
            if (obj == null)
            {
                t.Result = OvalResult.Error;
                t.Messages.Add("Object not found: " + objectRef.GetAttribute("object_ref"));
                return t;
            }
            t.Object = ObjectEvaluator.Evaluate(obj, ctx);
            var states = new List<XmlElement>();
            foreach (XmlNode n in test.ChildNodes)
            {
                var e = n as XmlElement;
                if (e == null || e.LocalName != "state") continue;
                string sid = e.GetAttribute("state_ref");
                t.StateIds.Add(sid);
                XmlElement s = ctx.FindState(sid);
                if (s == null) { t.Result = OvalResult.Error; t.Messages.Add("State not found: " + sid); return t; }
                states.Add(s);
            }
            t.Result = Decide(t, states);
            return t;
        }

        OvalResult Decide(TestResult t, List<XmlElement> states)
        {
            switch (t.Object.Flag)
            {
                case CollectedFlag.Error: return OvalResult.Error;
                case CollectedFlag.NotCollected: return OvalResult.Unknown;
                case CollectedFlag.NotApplicable: return OvalResult.NotApplicable;
            }

            int exists = 0, dne = 0, err = 0, nc = 0;
            foreach (var item in t.Object.Items)
            {
                switch (item.Status)
                {
                    case ItemStatus.Exists: exists++; break;
                    case ItemStatus.DoesNotExist: dne++; break;
                    case ItemStatus.Error: err++; break;
                    default: nc++; break;
                }
            }
            OvalResult existence = OvalLogic.Existence(t.CheckExistence, exists, dne, err, nc);
            OvalResult result;
            if (existence != OvalResult.True || states.Count == 0 || exists == 0)
            {
                result = existence;
                foreach (var item in t.Object.Items) t.Items.Add(new ItemResult { Item = item, Result = OvalResult.NotEvaluated });
            }
            else
            {
                var itemResults = new List<OvalResult>();
                foreach (var item in t.Object.Items)
                {
                    if (item.Status != ItemStatus.Exists)
                    {
                        t.Items.Add(new ItemResult { Item = item, Result = OvalResult.NotEvaluated });
                        continue;
                    }
                    var perState = states.Select(s => StateEvaluator.Evaluate(s, item, ctx)).ToList();
                    OvalResult ir = OvalLogic.Combine(t.StateOperator, perState);
                    t.Items.Add(new ItemResult { Item = item, Result = ir });
                    itemResults.Add(ir);
                }
                result = OvalLogic.Check(t.Check, itemResults);
            }

            // An incomplete collection cannot prove universal claims.
            if (t.Object.Flag == CollectedFlag.Incomplete && result == OvalResult.True &&
                (t.Check == "all" || t.Check == "none satisfy" || t.CheckExistence == "none_exist" || t.CheckExistence == "all_exist"))
                result = OvalResult.Unknown;
            return result;
        }

        static XmlElement Child(XmlElement parent, string localName)
        {
            foreach (XmlNode n in parent.ChildNodes)
            {
                var e = n as XmlElement;
                if (e != null && e.LocalName == localName && e.NamespaceURI == OvalContext.DefNs) return e;
            }
            return null;
        }

        static XmlElement ChildAnyNs(XmlElement parent, string localName)
        {
            foreach (XmlNode n in parent.ChildNodes)
            {
                var e = n as XmlElement;
                if (e != null && e.LocalName == localName) return e;
            }
            return null;
        }

        static XmlElement Find(XmlElement parent, string child, string grandchild)
        {
            XmlElement c = Child(parent, child);
            return c == null ? null : Child(c, grandchild);
        }
    }
}
