$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force

$edgeZip = Get-ChildItem (Join-Path $PSScriptRoot 'content') -Filter '*MS_Edge*.zip' -ErrorAction SilentlyContinue | Select-Object -First 1

Describe 'OVAL results and ARF' -Tag Content {
    $content = [PowerScap.Engine.Content.ScapContentLoader]::Load($edgeZip.FullName)
    $profileId = ($content.Benchmark.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'Profile' } | Select-Object -First 1).GetAttribute('id')
    $profile = [PowerScap.Engine.Xccdf.ProfileResolver]::Resolve($content, $profileId)
    $results = [PowerScap.Engine.Xccdf.RuleEvaluator]::Evaluate($content, $profile, [PowerScap.Engine.Oval.CollectorRegistry]::CreateDefault(), $null)
    $scores = [PowerScap.Engine.Xccdf.Scoring]::Compute($profile, $results)
    $target = [PowerScap.Engine.Xccdf.TargetInfo]::Collect()
    $report = [PowerScap.Engine.Reports.BenchmarkReport]::Build($content, $profile, $results, $scores, $target, (Get-Date), (Get-Date))
    $oval = [PowerScap.Engine.Reports.OvalResultsWriter]::Build($results, $content, $target, (Get-Date))
    $doc = @($oval.Values)[0]
    $ns = New-Object Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('r', 'http://oval.mitre.org/XMLSchema/oval-results-5')
    $ns.AddNamespace('sc', 'http://oval.mitre.org/XMLSchema/oval-system-characteristics-5')

    It 'has one definition result per evaluated definition' {
        $evaluated = @($results | Where-Object { $_.CheckHref } | ForEach-Object { $h = $_.CheckHref; $_.OvalResults | ForEach-Object { "$h|$($_.DefinitionId)" } } | Sort-Object -Unique)
        $written = 0
        foreach ($d in $oval.Values) { $written += $d.SelectNodes('//r:results/r:system/r:definitions/r:definition', $ns).Count }
        $written | Should Be $evaluated.Count
    }

    It 'records every tested item in the system characteristics' {
        $itemIds = @{}
        foreach ($i in $doc.SelectNodes('//sc:system_data/*', $ns)) { $itemIds[$i.GetAttribute('id')] = $true }
        $tested = $doc.SelectNodes('//r:tested_item', $ns)
        $tested.Count -gt 0 | Should Be $true
        @($tested | Where-Object { -not $itemIds.ContainsKey($_.GetAttribute('item_id')) }).Count | Should Be 0
    }

    It 'names each interface with its adapter and MAC address' {
        $ifaces = $doc.SelectNodes('//sc:system_info/sc:interfaces/sc:interface', $ns)
        $ifaces.Count | Should Be $target.Addresses.Count
        foreach ($i in $ifaces) {
            $i.SelectSingleNode('sc:interface_name', $ns).InnerText | Should Not BeNullOrEmpty
            $i.SelectSingleNode('sc:mac_address', $ns).InnerText | Should Match '^([0-9A-F]{2}-){5}[0-9A-F]{2}$'
        }
    }

    It 'writes registry items in the windows system-characteristics namespace' {
        $reg = $doc.GetElementsByTagName('registry_item', 'http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#windows')
        $reg.Count -gt 0 | Should Be $true
    }

    It 'wraps request, asset and reports in ARF' {
        $out = Join-Path $env:TEMP ('powerscap-arf-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory $out | Out-Null
        try {
            $xccdf = Join-Path $out 'x.xml'
            [PowerScap.Engine.Xccdf.ResultsWriter]::WriteXccdf($content, $profile, $results, $scores, $target, $xccdf)
            $report.ContentFile = $edgeZip.FullName
            $arf = [PowerScap.Engine.Reports.ArfWriter]::Build($report, $xccdf, $oval)
            $a = New-Object Xml.XmlNamespaceManager($arf.NameTable)
            $a.AddNamespace('arf', 'http://scap.nist.gov/schema/asset-reporting-format/1.1')
            $a.AddNamespace('core', 'http://scap.nist.gov/schema/reporting-core/1.1')
            $arf.SelectNodes('//arf:report-request/arf:content/*', $a)[0].LocalName | Should Be 'data-stream-collection'
            $arf.SelectNodes('//arf:asset', $a).Count | Should Be 1
            $reports = $arf.SelectNodes('//arf:reports/arf:report/arf:content/*', $a)
            ($reports | ForEach-Object { $_.LocalName }) -join ',' | Should Be ('TestResult,' + ((1..$oval.Count | ForEach-Object { 'oval_results' }) -join ','))
            $arf.SelectNodes('//core:relationship', $a).Count | Should Be $reports.Count
        }
        finally { Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
