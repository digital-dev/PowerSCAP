<#
.SYNOPSIS
    Compares XCCDF rule results between a reference scanner (e.g. SCC) and PowerSCAP, rule by rule.
.DESCRIPTION
    Outputs one object per rule id found in either file: RuleId, Reference, Actual, Match.
    Writes a summary line and exits with 1 when any rule differs.
.EXAMPLE
    .\tools\Compare-XccdfResults.ps1 -Reference scc.xml -Actual out\HOST_..._XCCDF-Results.xml | Where-Object { -not $_.Match }
#>
param(
    [Parameter(Mandatory)][string]$Reference,
    [Parameter(Mandatory)][string]$Actual
)

function Read-RuleResults([string]$Path) {
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = 'Prohibit'
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create((Resolve-Path -LiteralPath $Path).ProviderPath, $settings)
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.Load($reader)
    } finally { $reader.Dispose() }

    $map = [ordered]@{}
    # Use the last TestResult when a file holds several.
    $testResults = @($doc.GetElementsByTagName('TestResult', 'http://checklists.nist.gov/xccdf/1.2'))
    if ($testResults.Count -eq 0) { throw "No XCCDF 1.2 TestResult in $Path" }
    foreach ($rr in $testResults[-1].ChildNodes) {
        if ($rr.LocalName -ne 'rule-result') { continue }
        $result = @($rr.ChildNodes | Where-Object { $_.LocalName -eq 'result' } | Select-Object -First 1)
        $map[$rr.GetAttribute('idref')] = if ($result) { $result[0].InnerText.Trim() } else { '(none)' }
    }
    $map
}

$ref = Read-RuleResults $Reference
$act = Read-RuleResults $Actual

$ids = New-Object System.Collections.Generic.List[string]
foreach ($k in $ref.Keys) { $ids.Add($k) }
foreach ($k in $act.Keys) { if (-not $ref.Contains($k)) { $ids.Add($k) } }

$mismatches = 0
foreach ($id in $ids) {
    $r = if ($ref.Contains($id)) { $ref[$id] } else { '(missing)' }
    $a = if ($act.Contains($id)) { $act[$id] } else { '(missing)' }
    $match = $r -eq $a
    if (-not $match) { $mismatches++ }
    [pscustomobject]@{ RuleId = $id; Reference = $r; Actual = $a; Match = $match }
}

Write-Host ('{0} rules, {1} mismatches' -f $ids.Count, $mismatches)
if ($mismatches -gt 0) { exit 1 }
exit 0
