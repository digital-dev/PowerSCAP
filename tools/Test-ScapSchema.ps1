<#
.SYNOPSIS
    Validates PowerSCAP's XCCDF results, OVAL results and ARF files against the official XML schemas.
.DESCRIPTION
    Loads the schemas a document needs from -SchemaRoot (by default the copies in tests\fixtures\schemas) and
    reports every validation error with its line. OVAL results are checked against OVAL 5.12.3, or 5.11.2 when they
    declare it and -SchemaRoot has those schemas (SCC's Resources\Schemas folder does). Content embedded without a known
    schema is checked laxly, as the schemas allow.
.PARAMETER Path
    Files to validate (*_XCCDF-Results.xml, *_OVAL-Results.xml, *_ARF.xml).
.PARAMETER SchemaRoot
    Folder holding the schemas, laid out like SCC's Resources\Schemas folder.
.EXAMPLE
    .\tools\Test-ScapSchema.ps1 -Path (Get-ChildItem "$HOME\Documents\PowerSCAP Results\*_ARF.xml")
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][Alias('FullName')][string[]]$Path,
    [string]$SchemaRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tests\fixtures\schemas')
)

begin {
    $ErrorActionPreference = 'Stop'
    $common = 'xccdf_1.2.xsd', 'asset-reporting-format_1.1.0.xsd', 'reporting-core_1.1.0.xsd', 'asset-identification_1.1.0.xsd'
    $oval = 'oval-common-schema.xsd', 'oval-definitions-schema.xsd', 'oval-system-characteristics-schema.xsd', 'oval-results-schema.xsd',
        'windows-definitions-schema.xsd', 'windows-system-characteristics-schema.xsd',
        'independent-definitions-schema.xsd', 'independent-system-characteristics-schema.xsd'
    $sets = @{}

    # One schema set per OVAL version: the two versions share namespaces, so they cannot sit in one set.
    function Get-SchemaSet([string]$OvalVersion) {
        if ($sets.ContainsKey($OvalVersion)) { return $sets[$OvalVersion] }
        $set = New-Object Xml.Schema.XmlSchemaSet
        $set.XmlResolver = New-Object Xml.XmlUrlResolver
        $files = @($common | ForEach-Object { Join-Path $SchemaRoot $_ }) + @($oval | ForEach-Object { Join-Path $SchemaRoot "oval_$OvalVersion\$_" })
        foreach ($f in $files) {
            if (-not (Test-Path -LiteralPath $f)) { throw "Schema not found: $f" }
            # By URL, so a schema that another one imports is loaded once. [NullString] passes a real null
            # (take the target namespace from the schema); PowerShell turns $null into "".
            [void]$set.Add([NullString]::Value, (New-Object Uri $f).AbsoluteUri)
        }
        $set.Compile()
        $sets[$OvalVersion] = $set
        $set
    }
}

process {
    foreach ($p in $Path) {
        $file = (Resolve-Path -LiteralPath $p).ProviderPath
        $text = [IO.File]::ReadAllText($file)
        # PowerSCAP writes OVAL 5.12.3; a file that declares 5.11 is checked against 5.11.2 when those schemas are present.
        # The results generator's version, not that of definitions or a data stream embedded in the same file.
        $m = [regex]::Match($text, '<(?:\w+:)?oval_results\b[\s\S]*?<(?:\w+:)?schema_version[^>]*>\s*([\d.]+)')
        $version = if ($m.Success -and $m.Groups[1].Value.StartsWith('5.11')) { '5.11.2' } else { '5.12.3' }
        $errors = New-Object 'System.Collections.Generic.List[string]'
        $settings = New-Object Xml.XmlReaderSettings
        $settings.ValidationType = [Xml.ValidationType]::Schema
        $settings.Schemas = Get-SchemaSet $version
        $settings.ValidationFlags = $settings.ValidationFlags -bor [Xml.Schema.XmlSchemaValidationFlags]::ReportValidationWarnings
        $handler = [Xml.Schema.ValidationEventHandler] {
            param($s, $e)
            # Lax content with no schema (for example XHTML in descriptions) produces "could not find schema
            # information" warnings; those are not errors.
            if ($e.Severity -eq [Xml.Schema.XmlSeverityType]::Error) {
                $errors.Add(('line {0}: {1}' -f $e.Exception.LineNumber, $e.Message))
            }
        }
        $settings.add_ValidationEventHandler($handler)
        $reader = [Xml.XmlReader]::Create($file, $settings)
        try { while ($reader.Read()) { } } finally { $reader.Close() }
        [pscustomobject]@{
            Path        = $file
            OvalVersion = $version
            Valid       = $errors.Count -eq 0
            Errors      = $errors.ToArray()
        }
    }
}
