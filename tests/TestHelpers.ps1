# Shared test helpers. Dot-source after importing the module.

$script:EngineAssembly = [PowerScap.Engine.EngineInfo].Assembly.Location

if (-not ('PowerScapTests.FakeCollector' -as [type])) {
    Add-Type -ReferencedAssemblies $script:EngineAssembly, 'System.Xml' -TypeDefinition @'
using System;
using System.Collections.Generic;
using PowerScap.Engine.Oval;
namespace PowerScapTests
{
    /// Returns one fake_item per comma-separated value of the object's "items" entity.
    public class FakeCollector : ICollector
    {
        public string ObjectType { get { return "fake_object"; } }
        public CollectedObject Collect(ObjectSpec spec, OvalContext ctx)
        {
            var result = new CollectedObject(spec.ObjectId);
            EntityCriterion items;
            if (!spec.Entities.TryGetValue("items", out items)) return result;
            string csv = items.Values.Count > 0 ? items.Values[0] : "";
            if (csv == "throw") throw new InvalidOperationException("collector exploded");
            if (csv.Length == 0) { result.Flag = CollectedFlag.DoesNotExist; return result; }
            foreach (var v in csv.Split(','))
            {
                var item = new OvalItem(ctx.NextItemId(), "fake_item");
                item.Entities.Add(new OvalEntity("name", v));
                result.Items.Add(item);
            }
            result.Flag = result.Items.Count > 0 ? CollectedFlag.Complete : CollectedFlag.DoesNotExist;
            return result;
        }
    }
}
'@
}

function New-OvalDocument([string]$Objects, [string]$States = '', [string]$Variables = '', [string]$Tests = '', [string]$Definitions = '') {
    $xml = @"
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
    xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
    xmlns:win="http://oval.mitre.org/XMLSchema/oval-definitions-5#windows"
    xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <generator><oval:schema_version>5.11.2</oval:schema_version><oval:timestamp>2026-10-16T00:00:00</oval:timestamp></generator>
  <definitions>$Definitions</definitions><tests>$Tests</tests><objects>$Objects</objects><states>$States</states><variables>$Variables</variables>
</oval_definitions>
"@
    $doc = New-Object System.Xml.XmlDocument
    $doc.LoadXml($xml)
    $doc
}

# Context with the real (default) collectors and variable resolution.
function New-DefaultContext([string]$Objects, [string]$States = '', [string]$Variables = '') {
    $doc = New-OvalDocument -Objects $Objects -States $States -Variables $Variables
    $ctx = New-Object PowerScap.Engine.Oval.OvalContext($doc, [PowerScap.Engine.Oval.CollectorRegistry]::CreateDefault())
    $ctx.Variables = New-Object PowerScap.Engine.Oval.VariableResolver($ctx, $null)
    $ctx
}

function New-TestContext([string]$Path) {
    $doc = [PowerScap.Engine.Content.ScapContentLoader]::LoadXml($Path)
    $reg = New-Object PowerScap.Engine.Oval.CollectorRegistry
    $reg.Register((New-Object PowerScapTests.FakeCollector))
    New-Object PowerScap.Engine.Oval.OvalContext($doc, $reg)
}
