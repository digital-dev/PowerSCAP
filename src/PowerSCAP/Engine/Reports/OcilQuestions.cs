using System;
using System.Collections.Generic;
using System.Xml;
using PowerScap.Engine.Content;

namespace PowerScap.Engine.Reports
{
    /// <summary>
    /// The question a rule's OCIL check asks a person (OCIL 2.0: questionnaire -> test action -> question). The
    /// NIWC enhanced content carries one per manual rule, with the choices Finding / Not a Finding / Not Applicable /
    /// Not Reviewed.
    /// </summary>
    public class OcilQuestions
    {
        const string OcilNs = "http://scap.nist.gov/schema/ocil/2.0";
        readonly Dictionary<string, XmlElement> byId = new Dictionary<string, XmlElement>(StringComparer.Ordinal);

        public OcilQuestions(ScapContent content)
        {
            if (content == null || content.Ocil == null) return;
            foreach (XmlNode n in content.Ocil.GetElementsByTagName("*"))
            {
                var e = n as XmlElement;
                if (e != null && e.NamespaceURI == OcilNs && e.HasAttribute("id") && !byId.ContainsKey(e.GetAttribute("id")))
                    byId[e.GetAttribute("id")] = e;
            }
        }

        /// <summary>The question text for the rule's OCIL check, or null when it has none.</summary>
        public string For(XmlElement rule)
        {
            if (rule == null || byId.Count == 0) return null;
            foreach (XmlNode n in rule.ChildNodes)
            {
                var check = n as XmlElement;
                if (check == null || check.LocalName != "check" || check.GetAttribute("system").IndexOf("ocil", StringComparison.OrdinalIgnoreCase) < 0) continue;
                foreach (XmlNode c in check.ChildNodes)
                {
                    var reference = c as XmlElement;
                    if (reference == null || reference.LocalName != "check-content-ref") continue;
                    string text = QuestionFor(reference.GetAttribute("name"));
                    if (text != null) return text;
                }
            }
            return null;
        }

        string QuestionFor(string questionnaireId)
        {
            XmlElement questionnaire;
            if (string.IsNullOrEmpty(questionnaireId) || !byId.TryGetValue(questionnaireId, out questionnaire)) return null;
            foreach (XmlNode n in questionnaire.GetElementsByTagName("test_action_ref", OcilNs))
            {
                XmlElement action;
                if (!byId.TryGetValue(n.InnerText.Trim(), out action)) continue;
                XmlElement question;
                if (!byId.TryGetValue(action.GetAttribute("question_ref"), out question)) continue;
                foreach (XmlNode q in question.ChildNodes)
                    if (q.LocalName == "question_text") return q.InnerText.Trim();
            }
            return null;
        }
    }
}
