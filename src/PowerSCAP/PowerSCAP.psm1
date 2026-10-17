Set-StrictMode -Version 2.0

$script:EngineSourceRoot = Join-Path $PSScriptRoot 'Engine'
$script:EngineReferences = @(
    'System.Xml', 'System.Xml.Linq', 'System.Management',
    'System.DirectoryServices.AccountManagement', 'System.Security', 'System.Core',
    'System.IO.Compression', 'System.IO.Compression.FileSystem', 'System.Numerics',
    'System.ServiceProcess', 'System.Web.Extensions'
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

    # .NET cannot unload an assembly: a window that already loaded an older engine keeps using it.
    $loaded = 'PowerScap.Engine.EngineInfo' -as [type]
    if ($loaded) {
        if ([IO.Path]::GetFileName($loaded.Assembly.Location) -ne "PowerScap.Engine.$hash.dll") {
            Write-Warning 'PowerSCAP was updated after this PowerShell window loaded it. This window will keep running the old engine; open a new PowerShell window to use the new version.'
        }
        return
    }

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

$public = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter *.ps1 -ErrorAction SilentlyContinue)
foreach ($p in $public) { . $p.FullName }

# PowerSCAP.psd1 FunctionsToExport decides what is public; helpers stay internal.
Export-ModuleMember -Function *-PowerScap*

# Compact default views (all properties remain available with Format-List *).
Update-TypeData -TypeName PowerScap.Engine.Cache.CacheEntry -MemberType ScriptProperty -MemberName Benchmark -Value { if ($this.ChecklistName) { $this.ChecklistName } else { $this.BenchmarkTitle } } -Force
Update-TypeData -TypeName PowerScap.Engine.Cache.CacheEntry -MemberType ScriptProperty -MemberName Signed -Value {
    if (-not $this.Signature) { 'Unknown' }
    elseif ("$($this.Signature.State)" -eq 'Valid' -and -not $this.Signature.ChainTrusted) { 'Valid (issuer not trusted here)' }
    else { "$($this.Signature.State)" }
} -Force
Update-TypeData -TypeName PowerScap.Engine.Cache.CacheEntry -DefaultDisplayPropertySet Benchmark, BenchmarkVersion, Signed, AddedUtc -Force
Update-TypeData -TypeName PowerScap.Engine.Cache.UpdateInfo -DefaultDisplayPropertySet Cached, State, Reason -Force
