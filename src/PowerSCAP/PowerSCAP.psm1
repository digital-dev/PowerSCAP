Set-StrictMode -Version 2.0

$script:EngineSourceRoot = Join-Path $PSScriptRoot 'Engine'
# Set when this session runs an engine older than the sources (tools check it: & (Get-Module PowerSCAP) { $EngineStale }).
$script:EngineStale = $false
# PowerShell 7 runs on .NET, Windows PowerShell 5.1 on .NET Framework: the same sources compile against different
# assemblies, and each edition keeps its own builds.
$script:IsCore = $PSVersionTable.PSEdition -eq 'Core'
$script:EngineReferences = if ($script:IsCore) {
    # .NET's reference assemblies (PowerShell ships them in $PSHOME\ref; Add-Type drops its defaults when given
    # references), plus the Windows packages PowerShell carries beside them.
    $ref = @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter *.dll)
    $refNames = @($ref | ForEach-Object { $_.BaseName })
    $windows = @('System.Management', 'System.DirectoryServices', 'System.DirectoryServices.AccountManagement',
        'System.ServiceProcess.ServiceController', 'System.Security.Cryptography.Xml', 'System.Security.AccessControl',
        'System.Security.Principal.Windows', 'System.IO.FileSystem.AccessControl', 'System.Diagnostics.EventLog',
        'Microsoft.Win32.Registry') | Where-Object { $refNames -notcontains $_ } |
        ForEach-Object { Join-Path $PSHOME "$_.dll" } | Where-Object { Test-Path -LiteralPath $_ }
    @($ref | ForEach-Object { $_.FullName }) + @($windows)
} else {
    @(
        'System.Xml', 'System.Xml.Linq', 'System.Management',
        'System.DirectoryServices.AccountManagement', 'System.Security', 'System.Core',
        'System.IO.Compression', 'System.IO.Compression.FileSystem', 'System.Numerics',
        'System.ServiceProcess', 'System.Web.Extensions'
    )
}

function Get-PowerScapBinDirectory {
    $bin = if ($env:POWERSCAP_BINDIR) { $env:POWERSCAP_BINDIR } else { Join-Path $env:LOCALAPPDATA 'PowerSCAP\bin' }
    if ($script:IsCore) { Join-Path $bin 'pwsh' } else { $bin }
}

# The engine's C# sources; under PowerShell 7 also the JSON serializer .NET lacks (Compat\).
function Get-PowerScapEngineSource {
    $s = @(Get-ChildItem -LiteralPath $script:EngineSourceRoot -Filter *.cs -Recurse)
    if ($script:IsCore) { $s += @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Compat') -Filter *.cs) }
    @($s | Sort-Object FullName)
}

function Import-PowerScapEngine {
    <#
    .SYNOPSIS
        Compiles the C# engine (cached by source hash) and loads it into the session.
    #>
    [CmdletBinding()]
    param([switch]$Force)

    $sources = Get-PowerScapEngineSource
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $ms = New-Object System.IO.MemoryStream
        foreach ($s in $sources) {
            $name = [Text.Encoding]::UTF8.GetBytes($s.FullName.Substring($PSScriptRoot.Length))
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
            $script:EngineStale = $true
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
        try {
            # .NET marks WebRequest and friends obsolete (they still work); its compiler would stop on those warnings.
            $warnings = @{}
            if ($script:IsCore) { $warnings.IgnoreWarnings = $true; $warnings.WarningAction = 'SilentlyContinue' }
            Add-Type -Path $sources.FullName -ReferencedAssemblies $script:EngineReferences `
                -OutputAssembly $dll -OutputType Library -ErrorAction Stop @warnings
        }
        catch {
            # A failed compile can leave a partial file that the next import would try to load.
            Remove-Item -LiteralPath $dll -Force -ErrorAction SilentlyContinue
            throw
        }
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
