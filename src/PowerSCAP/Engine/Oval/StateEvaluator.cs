using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;

namespace PowerScap.Engine.Oval
{
    /// <summary>Compares one collected item against one OVAL state (OVAL 5.11.2 §5, state evaluation).</summary>
    public static class StateEvaluator
    {
        public static OvalResult Evaluate(XmlElement state, OvalItem item, OvalContext ctx)
        {
            if (item.Status == ItemStatus.Error) return OvalResult.Error;
            if (item.Status == ItemStatus.NotCollected) return OvalResult.Unknown;
            if (item.Status == ItemStatus.DoesNotExist) return OvalResult.False;

            var entityResults = new List<OvalResult>();
            foreach (XmlNode n in state.ChildNodes)
            {
                var se = n as XmlElement;
                if (se == null || se.LocalName == "notes" || se.NamespaceURI == OvalContext.DefNs) continue;
                entityResults.Add(EvaluateEntity(se, item.Get(se.LocalName), ctx));
            }
            string op = state.HasAttribute("operator") ? state.GetAttribute("operator") : "AND";
            return OvalLogic.Combine(op, entityResults);
        }

        static OvalResult EvaluateEntity(XmlElement stateEntity, IList<OvalEntity> itemEntities, OvalContext ctx)
        {
            // Entity-level check_existence (default at_least_one_exists) decides first whether values are compared.
            string checkExistence = stateEntity.HasAttribute("check_existence") ? stateEntity.GetAttribute("check_existence") : "at_least_one_exists";
            int exists = itemEntities.Count(e => e.Status == ItemStatus.Exists);
            int dne = itemEntities.Count(e => e.Status == ItemStatus.DoesNotExist);
            int err = itemEntities.Count(e => e.Status == ItemStatus.Error);
            int nc = itemEntities.Count(e => e.Status == ItemStatus.NotCollected);
            OvalResult existence = OvalLogic.Existence(checkExistence, exists, dne, err, nc);
            if (existence != OvalResult.True || exists == 0) return existence;

            var criterion = ObjectEvaluator.BuildCriterion(stateEntity, ctx);
            if (criterion.VariableFlag.HasValue) return OvalResult.Error;
            string entityCheck = stateEntity.HasAttribute("entity_check") ? stateEntity.GetAttribute("entity_check") : "all";

            var results = new List<OvalResult>();
            foreach (var ie in itemEntities)
            {
                if (ie.Status == ItemStatus.Error) { results.Add(OvalResult.Error); continue; }
                if (ie.Status == ItemStatus.NotCollected) { results.Add(OvalResult.Unknown); continue; }
                if (ie.Status == ItemStatus.DoesNotExist) continue; // existence already judged above
                if (criterion.Datatype == "record")
                    results.Add(EvaluateRecord(stateEntity, ie, ctx));
                else
                    results.Add(criterion.Matches(ie.Value));
            }
            return OvalLogic.Check(entityCheck, results);
        }

        static OvalResult EvaluateRecord(XmlElement stateEntity, OvalEntity record, OvalContext ctx)
        {
            var fieldResults = new List<OvalResult>();
            foreach (XmlNode n in stateEntity.ChildNodes)
            {
                var sf = n as XmlElement;
                if (sf == null || sf.LocalName != "field") continue;
                string name = sf.GetAttribute("name");
                var itemFields = record.Fields.Where(f => f.Name == name).ToList();
                if (itemFields.Count == 0) { fieldResults.Add(OvalResult.Error); continue; }
                var criterion = ObjectEvaluator.BuildCriterion(sf, ctx);
                string entityCheck = sf.HasAttribute("entity_check") ? sf.GetAttribute("entity_check") : "all";
                var r = itemFields.Select(f => f.Status == ItemStatus.Exists ? criterion.Matches(f.Value) : OvalResult.False).ToList();
                fieldResults.Add(OvalLogic.Check(entityCheck, r));
            }
            return OvalLogic.Combine("AND", fieldResults);
        }
    }
}
