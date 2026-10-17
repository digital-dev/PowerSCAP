<#
.SYNOPSIS
    Lists the OVAL object types used by SCAP content and whether PowerSCAP has a collector for each.
.EXAMPLE
    .\tools\Get-OvalInventory.ps1 -Path tests\content
#>
param([Parameter(Mandatory)][string]$Path)

Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\PowerSCAP') -Force
$registry = [PowerScap.Engine.Oval.CollectorRegistry]::CreateDefault()
$defNs = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'

$files = if (Test-Path -LiteralPath $Path -PathType Container) {
    Get-ChildItem -LiteralPath $Path -Include *.zip, *.xml -Recurse
} else { Get-Item -LiteralPath $Path }

$counts = @{}
foreach ($f in $files) {
    $content = [PowerScap.Engine.Content.ScapContentLoader]::Load($f.FullName)
    $docs = @($content.CheckComponents.Values) + @($content.CpeChecks.Values)
    foreach ($doc in $docs) {
        if ($doc.DocumentElement.LocalName -ne 'oval_definitions') { continue }
        foreach ($section in $doc.DocumentElement.ChildNodes) {
            if ($section.LocalName -ne 'objects' -or $section.NamespaceURI -ne $defNs) { continue }
            foreach ($o in $section.ChildNodes) {
                if ($o.NodeType -ne 'Element') { continue }
                $counts[$o.LocalName] = 1 + [int]$counts[$o.LocalName]
            }
        }
    }
}

$counts.GetEnumerator() | Sort-Object Name | ForEach-Object {
    [pscustomobject]@{
        ObjectType  = $_.Name
        ObjectCount = $_.Value
        Supported   = $null -ne $registry.Find($_.Name)
    }
}
