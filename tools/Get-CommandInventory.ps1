<#
.SYNOPSIS
    Lists the shell commands and cmdlets SCAP content asks for and whether PowerSCAP implements each natively.
.DESCRIPTION
    PowerSCAP never runs PowerShell or cmd during a scan; shellcommand_object and cmdlet_object content is
    answered by native C# implementations. Anything listed here as unsupported would be "not collected".
    Reads content only: commands are matched, never executed. Variables in commands are resolved, which can
    read the registry or files the way any OVAL variable would.
.EXAMPLE
    .\tools\Get-CommandInventory.ps1 -Path tests\content | Where-Object { -not $_.Supported }
#>
param([Parameter(Mandatory)][string]$Path)

Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\PowerSCAP') -Force

$files = if (Test-Path -LiteralPath $Path -PathType Container) {
    Get-ChildItem -LiteralPath $Path -Include *.zip, *.xml -Recurse
} else { Get-Item -LiteralPath $Path }

foreach ($f in $files) {
    $content = [PowerScap.Engine.Content.ScapContentLoader]::Load($f.FullName)
    foreach ($doc in @($content.CheckComponents.Values) + @($content.CpeChecks.Values)) {
        if ($doc.DocumentElement.LocalName -ne 'oval_definitions') { continue }
        $ctx = New-Object PowerScap.Engine.Oval.OvalContext($doc, [PowerScap.Engine.Oval.CollectorRegistry]::CreateDefault())
        $ctx.Variables = New-Object PowerScap.Engine.Oval.VariableResolver($ctx, $null)
        $objects = $doc.SelectNodes("//*[local-name()='objects']/*[local-name()='shellcommand_object' or local-name()='cmdlet_object']")
        foreach ($o in $objects) {
            $spec = [PowerScap.Engine.Oval.ObjectEvaluator]::BuildSpec($o, $ctx)
            if ($o.LocalName -eq 'shellcommand_object') {
                $shell = if ($spec.Entities.ContainsKey('shell')) { $spec.Entities['shell'].Values[0] } else { 'cmd' }
                foreach ($command in $spec.Entities['command'].Values) {
                    [pscustomobject]@{
                        Content   = $f.Name
                        ObjectId  = $o.GetAttribute('id')
                        Kind      = "shell:$shell"
                        Command   = $command
                        Supported = [PowerScap.Engine.Oval.NativeShell]::IsSupported($shell, $command)
                    }
                }
            }
            else {
                $parameters = [PowerScap.Engine.Oval.CmdletCollector]::RecordFields($spec, 'parameters')
                $select = [PowerScap.Engine.Oval.CmdletCollector]::RecordFields($spec, 'select')
                $properties = $null; $unique = $false
                $selectOk = [PowerScap.Engine.Oval.CmdletCollector]::ParseSelect($select, [ref]$properties, [ref]$unique)
                $verb = $spec.Entities['verb'].Values[0]; $noun = $spec.Entities['noun'].Values[0]
                [pscustomobject]@{
                    Content   = $f.Name
                    ObjectId  = $o.GetAttribute('id')
                    Kind      = 'cmdlet'
                    Command   = "$verb-$noun " + (($parameters.GetEnumerator() | ForEach-Object { "-$($_.Key) $($_.Value)" }) -join ' ')
                    Supported = $selectOk -and [PowerScap.Engine.Oval.NativeCmdlets]::IsSupported($verb, $noun, $parameters, $properties)
                }
            }
        }
    }
}
