using System.Collections.Generic;
using System.Linq;

namespace PowerScap.Engine.Xccdf
{
    public class Score
    {
        public string System { get; set; }
        public double Value { get; set; }
        public double Maximum { get; set; }
    }

    /// <summary>The four standard XCCDF 1.2 scoring models (§7.3).</summary>
    public static class Scoring
    {
        public const string Default = "urn:xccdf:scoring:default";
        public const string Flat = "urn:xccdf:scoring:flat";
        public const string FlatUnweighted = "urn:xccdf:scoring:flat-unweighted";
        public const string Absolute = "urn:xccdf:scoring:absolute";

        /// <summary>Results that take part in scoring; pass/fixed score, the rest count against.</summary>
        static bool Counted(XccdfResult r)
        {
            return r == XccdfResult.Pass || r == XccdfResult.Fixed || r == XccdfResult.Fail || r == XccdfResult.Error || r == XccdfResult.Unknown;
        }

        static bool Passing(XccdfResult r) { return r == XccdfResult.Pass || r == XccdfResult.Fixed; }

        public static List<Score> Compute(ResolvedProfile profile, List<RuleResult> results)
        {
            // One result per rule for scoring (multi-check rules count once: all instances must pass).
            var perRule = results.Where(r => r.Rule.Selected && Counted(r.Result))
                .GroupBy(r => r.Rule.RuleId)
                .Select(g => new { Rule = g.First().Rule, Pass = g.All(x => Passing(x.Result)) })
                .ToList();

            double flatMax = perRule.Sum(r => r.Rule.Weight);
            double flat = perRule.Where(r => r.Pass).Sum(r => r.Rule.Weight);
            var scores = new List<Score>
            {
                new Score { System = Default, Value = DefaultModel(perRule.Select(r => new Leaf { Rule = r.Rule, Pass = r.Pass }).ToList()), Maximum = 100 },
                new Score { System = Flat, Value = flat, Maximum = flatMax },
                new Score { System = FlatUnweighted, Value = perRule.Count(r => r.Pass), Maximum = perRule.Count },
                new Score { System = Absolute, Value = flat == flatMax ? 1 : 0, Maximum = 1 }
            };
            return scores;
        }

        class Leaf
        {
            public ResolvedRule Rule;
            public bool Pass;
        }

        class Node
        {
            public double Weight = 1;
            public double Score;
            public bool Counted;
            public readonly Dictionary<string, Node> Children = new Dictionary<string, Node>();
            public readonly List<string> Order = new List<string>();
        }

        /// <summary>
        /// Default model: rule score 100 or 0; each group's score is the weight-normalised mean of its counted
        /// children; the benchmark is the root group.
        /// </summary>
        static double DefaultModel(List<Leaf> leaves)
        {
            var root = new Node();
            foreach (var leaf in leaves)
            {
                Node cur = root;
                for (int i = 0; i < leaf.Rule.GroupPath.Count; i++)
                {
                    string gid = leaf.Rule.GroupPath[i];
                    Node next;
                    if (!cur.Children.TryGetValue(gid, out next))
                    {
                        next = new Node { Weight = i < leaf.Rule.GroupWeights.Count ? leaf.Rule.GroupWeights[i] : 1 };
                        cur.Children[gid] = next;
                        cur.Order.Add(gid);
                    }
                    cur = next;
                }
                var ruleNode = new Node { Weight = leaf.Rule.Weight, Score = leaf.Pass ? 100 : 0, Counted = true };
                string key = "rule:" + leaf.Rule.RuleId;
                cur.Children[key] = ruleNode;
                cur.Order.Add(key);
            }
            Aggregate(root);
            return root.Counted ? root.Score : 0;
        }

        static void Aggregate(Node node)
        {
            if (node.Children.Count == 0) return;
            double weighted = 0, weights = 0;
            bool any = false;
            foreach (var key in node.Order)
            {
                Node child = node.Children[key];
                Aggregate(child);
                if (!child.Counted) continue;
                any = true;
                weighted += child.Score * child.Weight;
                weights += child.Weight;
            }
            node.Counted = any;
            node.Score = weights > 0 ? weighted / weights : 0;
        }
    }
}
