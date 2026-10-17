# Content management: NCP catalog, local cache, updates and system profile.

# Network transport; tests replace it with a fake.
$script:PowerScapHttp = $null

function Get-PowerScapHttp {
    if (-not $script:PowerScapHttp) { $script:PowerScapHttp = New-Object PowerScap.Engine.Ncp.HttpTransport }
    $script:PowerScapHttp
}

function Get-PowerScapCache([string]$CacheRoot) {
    if (-not $CacheRoot) { $CacheRoot = [PowerScap.Engine.Cache.ContentCache]::DefaultRoot() }
    New-Object PowerScap.Engine.Cache.ContentCache($CacheRoot, (Get-PowerScapHttp))
}

function Get-PowerScapSystemProfile {
    <#
    .SYNOPSIS
        Describes this machine and the STIG-relevant products installed on it.
    #>
    [CmdletBinding()]
    param()
    [PowerScap.Engine.Profile.SystemProfile]::Collect()
}

function Find-PowerScapBenchmark {
    <#
    .SYNOPSIS
        Searches the NIST National Checklist Program for checklists with SCAP content.
    .PARAMETER MatchSystem
        Returns only the checklists for products detected on this machine, each with the SCAP resource to use.
    .EXAMPLE
        Find-PowerScapBenchmark -MatchSystem | Save-PowerScapBenchmark
    #>
    [CmdletBinding()]
    param(
        [string]$Keyword = '',
        [switch]$MatchSystem
    )
    $ErrorActionPreference = 'Stop'
    $ncp = New-Object PowerScap.Engine.Ncp.NcpClient((Get-PowerScapHttp))
    $types = [int[]]@([PowerScap.Engine.Ncp.NcpClient]::Scap14, [PowerScap.Engine.Ncp.NcpClient]::Scap13, [PowerScap.Engine.Ncp.NcpClient]::Scap12)
    $catalog = $ncp.Search($Keyword, $types)
    if ($MatchSystem) {
        [PowerScap.Engine.Profile.BenchmarkMatcher]::Match([PowerScap.Engine.Profile.SystemProfile]::Collect(), $catalog)
    }
    else {
        $catalog | Where-Object { [PowerScap.Engine.Ncp.NcpClient]::PickScapResource($_) }
    }
}

function Save-PowerScapBenchmark {
    <#
    .SYNOPSIS
        Downloads a checklist's SCAP content into the local cache (keeping any older versions).
    .PARAMETER InputObject
        A checklist from Find-PowerScapBenchmark, or a match from Find-PowerScapBenchmark -MatchSystem.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object]$InputObject,
        [string]$CacheRoot
    )
    begin {
        $ErrorActionPreference = 'Stop'
        $cache = Get-PowerScapCache $CacheRoot
    }
    process {
        if ($InputObject -is [PowerScap.Engine.Profile.BenchmarkMatch]) {
            $checklist = $InputObject.Checklist; $resource = $InputObject.Resource
        }
        elseif ($InputObject -is [PowerScap.Engine.Ncp.NcpChecklist]) {
            $checklist = $InputObject; $resource = [PowerScap.Engine.Ncp.NcpClient]::PickScapResource($InputObject)
        }
        else { throw "Save-PowerScapBenchmark takes a checklist or match from Find-PowerScapBenchmark, not $($InputObject.GetType().Name)." }
        # One unavailable benchmark must not stop the rest of the pipeline: report it and continue.
        if (-not $resource) {
            $PSCmdlet.WriteError((New-Object Management.Automation.ErrorRecord(
                (New-Object InvalidOperationException("$($checklist.Name) has no SCAP content for Windows.")), 'NoScapContent', 'ObjectNotFound', $checklist)))
            return
        }
        Write-Verbose "Downloading $($resource.Location)"
        try { $cache.Download($checklist, $resource) }
        catch {
            $inner = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
            $PSCmdlet.WriteError((New-Object Management.Automation.ErrorRecord(
                (New-Object InvalidOperationException("Could not download $($checklist.Name): $($inner.Message)", $inner)), 'DownloadFailed', 'ConnectionError', $checklist)))
        }
    }
}

function Import-PowerScapBenchmark {
    <#
    .SYNOPSIS
        Adds a local SCAP zip or data stream file to the cache (offline content, or content not on NCP).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)][Alias('FullName')][string]$Path,
        [string]$CacheRoot
    )
    begin { $ErrorActionPreference = 'Stop'; $cache = Get-PowerScapCache $CacheRoot }
    process { $cache.Import((Resolve-Path -LiteralPath $Path).ProviderPath) }
}

function Get-PowerScapBenchmark {
    <#
    .SYNOPSIS
        Lists cached SCAP content. Works offline.
    .PARAMETER Latest
        Only the newest cached version of each checklist (imported content: of each benchmark id).
    #>
    [CmdletBinding()]
    param(
        [switch]$Latest,
        [string]$CacheRoot
    )
    $entries = (Get-PowerScapCache $CacheRoot).List()
    if ($Latest) {
        $entries | Group-Object { if ($_.ChecklistId) { "c$($_.ChecklistId)" } else { "b$($_.BenchmarkId)" } } |
            ForEach-Object { $_.Group | Sort-Object AddedUtc -Descending | Select-Object -First 1 }
    }
    else { $entries }
}

function Test-PowerScapBenchmarkUpdate {
    <#
    .SYNOPSIS
        Checks NCP for newer releases of cached content. Never changes the cache.
    #>
    [CmdletBinding()]
    param([string]$CacheRoot)
    $cache = Get-PowerScapCache $CacheRoot
    $checker = New-Object PowerScap.Engine.Cache.UpdateChecker((New-Object PowerScap.Engine.Ncp.NcpClient((Get-PowerScapHttp))), (Get-PowerScapHttp))
    $checker.Check($cache.List())
}
