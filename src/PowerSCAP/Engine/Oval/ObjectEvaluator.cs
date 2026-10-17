using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;

namespace PowerScap.Engine.Oval
{
    /// <summary>Turns an OVAL object element into collected items: plain objects via collectors, sets via set algebra.</summary>
    public static class ObjectEvaluator
    {
        public static CollectedObject Evaluate(XmlElement objectElement, OvalContext ctx)
        {
            if (objectElement == null) throw new ArgumentNullException("objectElement");
            string id = objectElement.GetAttribute("id");
            CollectedObject cached;
            if (ctx.Cache.TryGetValue(id, out cached)) return cached;

            CollectedObject result;
            XmlElement set = Child(objectElement, "set", OvalContext.DefNs);
            if (set != null)
                result = EvaluateSet(id, set, ctx);
            else
                result = Collect(objectElement, ctx);

            ctx.Cache[id] = result;
            return result;
        }

        static CollectedObject Collect(XmlElement objectElement, OvalContext ctx)
        {
            string id = objectElement.GetAttribute("id");
            var spec = BuildSpec(objectElement, ctx);

            foreach (var c in spec.Entities.Values)
                if (c.VariableFlag.HasValue)
                    return CollectedObject.WithFlag(id, c.VariableFlag.Value, "Variable " + c.VarRef + " could not be resolved.");

            ICollector collector = ctx.Collectors.Find(spec.ObjectType);
            if (collector == null)
                return CollectedObject.WithFlag(id, CollectedFlag.NotCollected, "No collector for " + spec.ObjectType + ".");

            CollectedObject collected;
            try
            {
                collected = collector.Collect(spec, ctx) ?? CollectedObject.WithFlag(id, CollectedFlag.Error, "Collector returned nothing.");
            }
            catch (Exception ex)
            {
                collected = CollectedObject.WithFlag(id, CollectedFlag.Error, spec.ObjectType + ": " + ex.Message);
            }
            collected.ObjectId = id;

            var filters = Children(objectElement, "filter", OvalContext.DefNs);
            if (filters.Count > 0) ApplyFilters(collected, filters, ctx);
            return collected;
        }

        public static ObjectSpec BuildSpec(XmlElement objectElement, OvalContext ctx)
        {
            var spec = new ObjectSpec();
            spec.ObjectId = objectElement.GetAttribute("id");
            spec.ObjectType = objectElement.LocalName;
            spec.Element = objectElement;
            foreach (XmlNode n in objectElement.ChildNodes)
            {
                var e = n as XmlElement;
                if (e == null || e.NamespaceURI == OvalContext.DefNs || e.LocalName == "notes") continue;
                if (e.LocalName == "behaviors") { spec.Behaviors = e; continue; }
                spec.Entities[e.LocalName] = BuildCriterion(e, ctx);
            }
            return spec;
        }

        public static EntityCriterion BuildCriterion(XmlElement e, OvalContext ctx)
        {
            var c = new EntityCriterion();
            c.Name = e.LocalName;
            if (e.HasAttribute("operation")) c.Operation = e.GetAttribute("operation");
            if (e.HasAttribute("datatype")) c.Datatype = e.GetAttribute("datatype");
            if (e.HasAttribute("var_check")) c.VarCheck = e.GetAttribute("var_check");
            c.IsNil = e.GetAttribute("nil", "http://www.w3.org/2001/XMLSchema-instance") == "true";
            if (e.HasAttribute("var_ref"))
            {
                c.VarRef = e.GetAttribute("var_ref");
                ResolveVariable(c, ctx);
            }
            else if (!c.IsNil)
            {
                c.Values = new List<string> { e.InnerText };
            }
            return c;
        }

        /// <summary>Hook for variable resolution (OVAL variables are added in a later task).</summary>
        static void ResolveVariable(EntityCriterion c, OvalContext ctx)
        {
            c.Values = new List<string>();
        }

        static CollectedObject EvaluateSet(string id, XmlElement set, OvalContext ctx)
        {
            string op = set.HasAttribute("set_operator") ? set.GetAttribute("set_operator") : "UNION";
            var operands = new List<CollectedObject>();
            foreach (XmlNode n in set.ChildNodes)
            {
                var e = n as XmlElement;
                if (e == null || e.NamespaceURI != OvalContext.DefNs) continue;
                if (e.LocalName == "object_reference")
                {
                    XmlElement referenced = ctx.FindObject(e.InnerText.Trim());
                    if (referenced == null)
                    {
                        operands.Add(CollectedObject.WithFlag(e.InnerText, CollectedFlag.Error, "Object not found: " + e.InnerText));
                        continue;
                    }
                    operands.Add(Copy(Evaluate(referenced, ctx)));
                }
                else if (e.LocalName == "set")
                {
                    operands.Add(EvaluateSet(id, e, ctx));
                }
            }

            var filters = Children(set, "filter", OvalContext.DefNs);
            if (filters.Count > 0)
                foreach (var o in operands) ApplyFilters(o, filters, ctx);

            var result = new CollectedObject(id);
            foreach (var o in operands) result.Messages.AddRange(o.Messages);
            if (operands.Count == 0) { result.Flag = CollectedFlag.Error; return result; }

            var first = operands[0];
            List<OvalItem> items;
            switch (op)
            {
                case "INTERSECTION":
                    items = first.Items;
                    foreach (var o in operands.Skip(1))
                    {
                        var sigs = new HashSet<string>(o.Items.Select(i => i.Signature()));
                        items = items.Where(i => sigs.Contains(i.Signature())).ToList();
                    }
                    break;
                case "COMPLEMENT":
                    var remove = operands.Count > 1 ? new HashSet<string>(operands[1].Items.Select(i => i.Signature())) : new HashSet<string>();
                    items = first.Items.Where(i => !remove.Contains(i.Signature())).ToList();
                    break;
                default:
                    items = new List<OvalItem>();
                    var seen = new HashSet<string>();
                    foreach (var o in operands)
                        foreach (var i in o.Items)
                            if (seen.Add(i.Signature())) items.Add(i);
                    break;
            }
            result.Items.AddRange(items);
            result.Flag = CombineFlags(op, operands, items.Count);
            return result;
        }

        /// <summary>Set flag combination (OVAL 5.11.2 §4.3.3 set evaluation tables, condensed).</summary>
        static CollectedFlag CombineFlags(string op, List<CollectedObject> operands, int itemCount)
        {
            var flags = operands.Select(o => o.Flag).ToList();
            if (op == "COMPLEMENT")
            {
                var a = flags[0];
                var b = flags.Count > 1 ? flags[1] : CollectedFlag.DoesNotExist;
                if (a == CollectedFlag.Error || b == CollectedFlag.Error) return CollectedFlag.Error;
                if (a == CollectedFlag.NotCollected || b == CollectedFlag.NotCollected) return CollectedFlag.NotCollected;
                if (a == CollectedFlag.DoesNotExist) return CollectedFlag.DoesNotExist;
                if (b == CollectedFlag.Incomplete) return CollectedFlag.Error;
                if (a == CollectedFlag.Incomplete) return CollectedFlag.Incomplete;
                return itemCount > 0 ? CollectedFlag.Complete : CollectedFlag.DoesNotExist;
            }
            if (flags.Contains(CollectedFlag.Error)) return CollectedFlag.Error;
            if (op == "INTERSECTION" && flags.Contains(CollectedFlag.DoesNotExist)) return CollectedFlag.DoesNotExist;
            if (flags.Contains(CollectedFlag.NotCollected)) return CollectedFlag.NotCollected;
            if (flags.Contains(CollectedFlag.Incomplete)) return CollectedFlag.Incomplete;
            if (flags.All(f => f == CollectedFlag.NotApplicable)) return CollectedFlag.NotApplicable;
            return itemCount > 0 ? CollectedFlag.Complete : CollectedFlag.DoesNotExist;
        }

        static void ApplyFilters(CollectedObject collected, IList<XmlElement> filters, OvalContext ctx)
        {
            foreach (var f in filters)
            {
                string action = f.HasAttribute("action") ? f.GetAttribute("action") : "exclude";
                XmlElement state = ctx.FindState(f.InnerText.Trim());
                if (state == null)
                {
                    collected.Flag = CollectedFlag.Error;
                    collected.Messages.Add("Filter state not found: " + f.InnerText);
                    continue;
                }
                var keep = new List<OvalItem>();
                foreach (var item in collected.Items)
                {
                    var r = StateEvaluator.Evaluate(state, item, ctx);
                    bool matches = r == OvalResult.True;
                    if (r == OvalResult.Error) collected.Messages.Add("Filter evaluation error on item " + item.Id + ".");
                    if (action == "include" ? matches : !matches) keep.Add(item);
                }
                collected.Items.Clear();
                collected.Items.AddRange(keep);
            }
            if (collected.Items.Count == 0 && collected.Flag == CollectedFlag.Complete)
                collected.Flag = CollectedFlag.DoesNotExist;
        }

        static CollectedObject Copy(CollectedObject source)
        {
            var c = new CollectedObject(source.ObjectId);
            c.Flag = source.Flag;
            c.Items.AddRange(source.Items);
            c.Messages.AddRange(source.Messages);
            return c;
        }

        static XmlElement Child(XmlElement parent, string localName, string ns)
        {
            foreach (XmlNode n in parent.ChildNodes)
            {
                var e = n as XmlElement;
                if (e != null && e.LocalName == localName && e.NamespaceURI == ns) return e;
            }
            return null;
        }

        static IList<XmlElement> Children(XmlElement parent, string localName, string ns)
        {
            var list = new List<XmlElement>();
            foreach (XmlNode n in parent.ChildNodes)
            {
                var e = n as XmlElement;
                if (e != null && e.LocalName == localName && e.NamespaceURI == ns) list.Add(e);
            }
            return list;
        }
    }
}
