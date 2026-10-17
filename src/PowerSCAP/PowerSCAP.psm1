Set-StrictMode -Version 2.0

$script:EngineSourceRoot = Join-Path $PSScriptRoot 'Engine'
$script:EngineReferences = @(
    'System.Xml', 'System.Xml.Linq', 'System.Management',
    'System.DirectoryServices.AccountManagement', 'System.Security', 'System.Core'
)

function Get-PowerScapBinDirectory {
    if ($env:POWERSCAP_BINDIR) { return $env:POWERSCAP_BINDIR }
    Join-Path $env:LOCALAPPDATA 'PowerSCAP\bin'
}

function Import-PowerScapEngine {
    <#
    .SYNOPSIS
        Compiles the C# engine (cached by source hash) and loads it into the session.
    #>
    [CmdletBinding()]
    param([switch]$Force)

    if (-not $Force -and ('PowerScap.Engine.EngineInfo' -as [type])) { return }

    $sources = @(Get-ChildItem -LiteralPath $script:EngineSourceRoot -Filter *.cs -Recurse | Sort-Object FullName)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $ms = New-Object System.IO.MemoryStream
        foreach ($s in $sources) {
            $name = [Text.Encoding]::UTF8.GetBytes($s.FullName.Substring($script:EngineSourceRoot.Length))
            $ms.Write($name, 0, $name.Length)
            $bytes = [IO.File]::ReadAllBytes($s.FullName)
            $ms.Write($bytes, 0, $bytes.Length)
        }
        $hash = -join ($sha.ComputeHash($ms.ToArray())[0..5] | ForEach-Object { $_.ToString('x2') })
    } finally { $sha.Dispose() }

    $bin = Get-PowerScapBinDirectory
    if (-not (Test-Path -LiteralPath $bin)) { New-Item -ItemType Directory -Path $bin -Force | Out-Null }
    $dll = Join-Path $bin "PowerScap.Engine.$hash.dll"

    if (-not (Test-Path -LiteralPath $dll)) {
        # Stale builds are removed when possible; a DLL loaded by another session stays until it is free.
        Get-ChildItem -LiteralPath $bin -Filter 'PowerScap.Engine.*.dll' |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Add-Type -Path $sources.FullName -ReferencedAssemblies $script:EngineReferences `
            -OutputAssembly $dll -OutputType Library -ErrorAction Stop
    }
    Add-Type -Path $dll -ErrorAction Stop
}

Import-PowerScapEngine

Export-ModuleMember -Function Import-PowerScapEngine
