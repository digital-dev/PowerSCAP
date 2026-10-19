# Shared test helpers. Dot-source after importing the module.

$script:EngineAssembly = [PowerScap.Engine.EngineInfo].Assembly.Location
# Test types compile against the engine and the assemblies it was built with (PowerShell 7 needs its .NET references).
$script:TestReferences = @($script:EngineAssembly) + @(& (Get-Module PowerSCAP) { $script:EngineReferences })

if (-not ('PowerScapTests.FakeCollector' -as [type])) {
    Add-Type -ReferencedAssemblies $script:TestReferences -TypeDefinition @'
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
                foreach (var part in v.Split('|')) item.Entities.Add(new OvalEntity("name", part)); // "a|b": two name entities
                result.Items.Add(item);
            }
            result.Flag = result.Items.Count > 0 ? CollectedFlag.Complete : CollectedFlag.DoesNotExist;
            return result;
        }
    }
}
'@
}

if (-not ('PowerScapTests.FakeTransport' -as [type])) {
    Add-Type -ReferencedAssemblies $script:TestReferences -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using PowerScap.Engine.Ncp;
namespace PowerScapTests
{
    /// Serves canned responses by URL substring; records every URL requested.
    public class FakeTransport : IHttpTransport
    {
        readonly List<KeyValuePair<string, string>> text = new List<KeyValuePair<string, string>>();
        readonly List<KeyValuePair<string, string>> files = new List<KeyValuePair<string, string>>();
        readonly List<KeyValuePair<string, string>> failures = new List<KeyValuePair<string, string>>();
        public List<string> Requests = new List<string>();
        public string ETag = "\"etag-1\"";
        public bool PartialThenFail;

        public void Map(string urlPart, string body) { text.Add(new KeyValuePair<string, string>(urlPart, body)); }
        public void MapFile(string urlPart, string path) { files.Add(new KeyValuePair<string, string>(urlPart, path)); }
        public void Fail(string urlPart, string message) { failures.Add(new KeyValuePair<string, string>(urlPart, message)); }

        void Check(string url)
        {
            Requests.Add(url);
            foreach (var f in failures) if (url.Contains(f.Key)) throw new NcpException(url, f.Value);
        }

        static string Find(List<KeyValuePair<string, string>> map, string url)
        {
            foreach (var kv in map) if (url.Contains(kv.Key)) return kv.Value;
            return null;
        }

        public string GetString(string url)
        {
            Check(url);
            string body = Find(text, url);
            if (body == null) throw new NcpException(url, "404 Not Found");
            return body;
        }

        public HttpHead Head(string url)
        {
            Check(url);
            return new HttpHead { Status = 200, ETag = ETag };
        }

        public void Download(string url, string destinationPath)
        {
            Check(url);
            string file = Find(files, url);
            if (file != null)
            {
                if (PartialThenFail)
                {
                    byte[] all = File.ReadAllBytes(file);
                    using (var fs = File.Create(destinationPath)) fs.Write(all, 0, all.Length / 2);
                    throw new NcpException(url, "connection reset");
                }
                File.Copy(file, destinationPath, true);
                return;
            }
            string body = Find(text, url);
            if (body == null) throw new NcpException(url, "404 Not Found");
            File.WriteAllText(destinationPath, body);
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
    $ctx = New-Object PowerScap.Engine.Oval.OvalContext($doc, $reg)
    $ctx.Variables = New-Object PowerScap.Engine.Oval.VariableResolver($ctx, $null)
    $ctx
}
