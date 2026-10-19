using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace PowerScap.Engine.Oval
{
    public enum ItemStatus { Exists, DoesNotExist, Error, NotCollected }

    public enum CollectedFlag { Complete, Incomplete, DoesNotExist, Error, NotCollected, NotApplicable }

    public class OvalEntity
    {
        public string Name { get; set; }
        public string Datatype { get; set; }
        public string Value { get; set; }
        public ItemStatus Status { get; set; }
        /// <summary>Record fields (datatype "record"), otherwise empty.</summary>
        public List<OvalEntity> Fields { get; private set; }

        public OvalEntity(string name, string value) : this(name, value, "string") { }

        public OvalEntity(string name, string value, string datatype)
        {
            Name = name;
            Value = value;
            Datatype = datatype ?? "string";
            Status = ItemStatus.Exists;
            Fields = new List<OvalEntity>();
        }

        public static OvalEntity Missing(string name)
        {
            return Missing(name, "string");
        }

        /// <summary>A missing entity of a type whose schema requires its datatype even when absent (version).</summary>
        public static OvalEntity Missing(string name, string datatype)
        {
            var e = new OvalEntity(name, null, datatype);
            e.Status = ItemStatus.DoesNotExist;
            return e;
        }
    }

    public class OvalItem
    {
        public int Id { get; set; }
        public string ItemType { get; set; }
        public ItemStatus Status { get; set; }
        public List<OvalEntity> Entities { get; private set; }
        public List<string> Messages { get; private set; }

        public OvalItem(int id, string itemType)
        {
            Id = id;
            ItemType = itemType;
            Status = ItemStatus.Exists;
            Entities = new List<OvalEntity>();
            Messages = new List<string>();
        }

        public IList<OvalEntity> Get(string name)
        {
            return Entities.Where(e => e.Name == name).ToList();
        }

        public OvalItem Add(string name, string value, string datatype)
        {
            Entities.Add(new OvalEntity(name, value, datatype));
            return this;
        }

        public OvalItem Add(string name, string value)
        {
            return Add(name, value, "string");
        }

        /// <summary>Identity used to de-duplicate items in set operations.</summary>
        public string Signature()
        {
            var sb = new StringBuilder(ItemType).Append('|').Append(Status);
            foreach (var e in Entities)
                sb.Append('|').Append(e.Name).Append('=').Append(e.Status).Append(':').Append(e.Value);
            return sb.ToString();
        }
    }

    public class EntityCriterion
    {
        public string Name { get; set; }
        public string Operation { get; set; }
        public string Datatype { get; set; }
        public IList<string> Values { get; set; }
        public string VarCheck { get; set; }
        public string VarRef { get; set; }
        public bool IsNil { get; set; }
        /// <summary>Set when a var_ref could not be resolved; the object must then be flagged accordingly.</summary>
        public CollectedFlag? VariableFlag { get; set; }

        public EntityCriterion()
        {
            Operation = "equals";
            Datatype = "string";
            VarCheck = "all";
            Values = new List<string>();
        }

        /// <summary>Does a collected value satisfy this criterion (applying var_check across multiple values)?</summary>
        public OvalResult Matches(string actual)
        {
            if (Values.Count == 0) return VarRef != null ? OvalResult.False : OvalResult.Error;
            var results = Values.Select(v => OvalOps.Compare(Datatype, Operation, actual, v)).ToList();
            return OvalLogic.Check(VarCheck, results);
        }

        public bool IsEqualityOnly
        {
            get { return Operation == "equals" && VarRef == null; }
        }
    }

    public class ObjectSpec
    {
        public string ObjectId { get; set; }
        public string ObjectType { get; set; }
        public IDictionary<string, EntityCriterion> Entities { get; private set; }
        public XmlElement Behaviors { get; set; }
        public XmlElement Element { get; set; }

        public ObjectSpec()
        {
            Entities = new Dictionary<string, EntityCriterion>(StringComparer.Ordinal);
        }

        public string Behavior(string name, string defaultValue)
        {
            if (Behaviors == null || !Behaviors.HasAttribute(name)) return defaultValue;
            return Behaviors.GetAttribute(name);
        }
    }

    public class CollectedObject
    {
        public string ObjectId { get; set; }
        public CollectedFlag Flag { get; set; }
        public List<OvalItem> Items { get; private set; }
        public List<string> Messages { get; private set; }

        public CollectedObject(string objectId)
        {
            ObjectId = objectId;
            Flag = CollectedFlag.Complete;
            Items = new List<OvalItem>();
            Messages = new List<string>();
        }

        public static CollectedObject WithFlag(string objectId, CollectedFlag flag, string message)
        {
            var c = new CollectedObject(objectId);
            c.Flag = flag;
            if (message != null) c.Messages.Add(message);
            return c;
        }
    }

    public class OvalContext
    {
        public const string DefNs = "http://oval.mitre.org/XMLSchema/oval-definitions-5";
        public XmlDocument Definitions { get; private set; }
        public CollectorRegistry Collectors { get; private set; }
        public IDictionary<string, CollectedObject> Cache { get; private set; }
        /// <summary>Variable resolution; when null, var_ref entities resolve to no values.</summary>
        public VariableResolver Variables { get; set; }
        readonly Dictionary<string, XmlElement> index = new Dictionary<string, XmlElement>(StringComparer.Ordinal);
        int nextItemId;

        public OvalContext(XmlDocument definitions, CollectorRegistry collectors)
        {
            Definitions = definitions;
            Collectors = collectors;
            Cache = new Dictionary<string, CollectedObject>(StringComparer.Ordinal);
            foreach (string section in new[] { "definitions", "tests", "objects", "states", "variables" })
            {
                foreach (XmlNode container in definitions.DocumentElement.ChildNodes)
                {
                    if (container.NodeType != XmlNodeType.Element || container.LocalName != section || container.NamespaceURI != DefNs) continue;
                    foreach (XmlNode n in container.ChildNodes)
                    {
                        var e = n as XmlElement;
                        if (e != null && e.HasAttribute("id")) index[e.GetAttribute("id")] = e;
                    }
                }
            }
        }

        public int NextItemId() { return ++nextItemId; }

        public XmlElement Find(string id)
        {
            XmlElement e;
            return index.TryGetValue(id, out e) ? e : null;
        }

        public XmlElement FindObject(string id) { return Find(id); }
        public XmlElement FindState(string id) { return Find(id); }
    }
}
