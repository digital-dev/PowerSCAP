<#
.SYNOPSIS
    Opens the PowerSCAP window off screen, visits each page and saves a PNG of it (layout review and docs).
.PARAMETER Theme
    Dark, Light or System.
.PARAMETER SelectRule
    On the Results page, select the first open finding so the detail panel shows.
.EXAMPLE
    powershell -STA -File tools\Save-GuiScreenshots.ps1 -OutputPath out\gui -Theme Light
#>
param(
    [string]$OutputPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\gui'),
    [ValidateSet('Dark', 'Light', 'System')][string]$Theme = 'Dark',
    [string[]]$Pages = @('System', 'Content', 'Scan', 'Results', 'Settings'),
    [switch]$SelectRule,
    # Scans the cached benchmarks whose titles match (unelevated is allowed) before taking the pictures.
    [string]$ScanPattern,
    # Scan history folder to show and write; a scratch folder keeps test scans out of the real history.
    [string]$HistoryRoot
)
$ErrorActionPreference = 'Stop'
if ($HistoryRoot) { $env:POWERSCAP_HISTORYDIR = $HistoryRoot }
$m = Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\PowerSCAP') -Force -PassThru
& $m { Import-PowerScapGui }
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$settings = New-Object PowerScap.Gui.GuiSettings
$settings.Theme = $Theme
$settings.CheckUpdatesOnLaunch = $false
$settings.AllowUnelevated = [bool]$ScanPattern
$settings.OutputPath = Join-Path $OutputPath 'results'
$settingsPath = Join-Path $env:TEMP 'powerscap-screenshot-settings.json'
$gui = Join-Path (Split-Path $PSScriptRoot -Parent) 'src\PowerSCAP\Gui'
$window = [PowerScap.Gui.GuiHost]::CreateWindow($gui, $settings, $settingsPath, (New-Object PowerScap.Engine.Ncp.HttpTransport), $null)
$window.WindowStartupLocation = 'Manual'
$window.Left = -32000; $window.Top = 0; $window.ShowActivated = $false; $window.ShowInTaskbar = $false
$window.Show()
$vm = $window.DataContext
[PowerScap.Gui.GuiHost]::Pump([TimeSpan]::FromSeconds(8))

if ($ScanPattern) {
    foreach ($i in $vm.Content.Items) { $i.IsSelected = $i.Title -match $ScanPattern }
    $vm.Content.ScanSelectedCommand.Execute($null)
    $shot = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($vm.Scan.IsRunning -and $sw.Elapsed.TotalMinutes -lt 10) {
        [PowerScap.Gui.GuiHost]::Pump([TimeSpan]::FromSeconds(2))
        if ($shot -eq 0 -and $sw.Elapsed.TotalSeconds -gt 4) { [PowerScap.Gui.GuiHost]::Snapshot($window, (Join-Path $OutputPath "Scan-running-$Theme.png")); $shot = 1 }
    }
    [PowerScap.Gui.GuiHost]::Pump([TimeSpan]::FromSeconds(2))
    Write-Host "Scan: $($vm.Scan.BatchMessage)"
}

foreach ($p in $Pages) {
    $vm.Page = $p
    [PowerScap.Gui.GuiHost]::Pump([TimeSpan]::FromSeconds($(if ($p -eq 'Results') { 4 } else { 1 })))
    if ($p -eq 'Results' -and $SelectRule) {
        $row = $vm.Results.Rows | Where-Object Status -eq 'Open' | Select-Object -First 1
        if ($row) { $vm.Results.SelectedRow = $row; [PowerScap.Gui.GuiHost]::Pump([TimeSpan]::FromSeconds(1)) }
    }
    $file = Join-Path $OutputPath ("{0}-{1}.png" -f $p, $Theme)
    [PowerScap.Gui.GuiHost]::Snapshot($window, $file)
    Write-Host $file
}
if ($vm.Status) { Write-Host "Status: $($vm.Status)" }
$window.Close()
