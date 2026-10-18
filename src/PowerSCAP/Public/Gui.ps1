# Desktop GUI: compiles the view-models (cached by source hash, like the engine) and shows the WPF window.

$script:GuiRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'Gui'
$script:WpfAssemblies = @('PresentationFramework', 'PresentationCore', 'WindowsBase', 'System.Xaml', 'System.Windows.Forms')

function Import-PowerScapGui {
    $sources = @(Get-ChildItem -LiteralPath $script:GuiRoot -Filter *.cs | Sort-Object FullName)
    $engine = ('PowerScap.Engine.EngineInfo' -as [type]).Assembly.Location
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $ms = New-Object System.IO.MemoryStream
        foreach ($s in $sources) { $b = [IO.File]::ReadAllBytes($s.FullName); $ms.Write($b, 0, $b.Length) }
        $b = [Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFileName($engine)); $ms.Write($b, 0, $b.Length)
        $hash = -join ($sha.ComputeHash($ms.ToArray())[0..5] | ForEach-Object { $_.ToString('x2') })
    } finally { $sha.Dispose() }

    $loaded = 'PowerScap.Gui.GuiHost' -as [type]
    if ($loaded) {
        if ([IO.Path]::GetFileName($loaded.Assembly.Location) -ne "PowerScap.Gui.$hash.dll") {
            Write-Warning 'The PowerSCAP GUI was updated after this PowerShell window loaded it. Open a new PowerShell window to use the new version.'
        }
        return
    }

    Add-Type -AssemblyName $script:WpfAssemblies
    $bin = Get-PowerScapBinDirectory
    $dll = Join-Path $bin "PowerScap.Gui.$hash.dll"
    if (-not (Test-Path -LiteralPath $dll)) {
        Get-ChildItem -LiteralPath $bin -Filter 'PowerScap.Gui.*.dll' | Remove-Item -Force -ErrorAction SilentlyContinue
        $refs = foreach ($name in $script:WpfAssemblies) {
            ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { -not $_.IsDynamic -and $_.GetName().Name -eq $name } | Select-Object -First 1).Location
        }
        $refs += @('System.Xml', 'System.Core', 'System.Web.Extensions', 'System.Xaml', $engine)
        Add-Type -Path $sources.FullName -ReferencedAssemblies $refs -OutputAssembly $dll -OutputType Library -ErrorAction Stop
    }
    Add-Type -Path $dll -ErrorAction Stop
}

function Start-PowerScapGui {
    <#
    .SYNOPSIS
        Opens the PowerSCAP desktop app. Returns when the window closes.
    .DESCRIPTION
        Needs a single-threaded apartment (Windows PowerShell 5.1 consoles are STA by default).
        Scans need administrator rights; started unelevated, the app offers to restart elevated.
    #>
    [CmdletBinding()]
    param()
    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'The PowerSCAP GUI needs an STA thread. Start PowerShell with -STA (the default for Windows PowerShell 5.1).'
    }
    Import-PowerScapGui
    $launcher = Join-Path (Split-Path $PSScriptRoot -Parent) 'Start-PowerSCAP.ps1'
    [PowerScap.Gui.GuiHost]::Run($script:GuiRoot, $launcher)
}

function New-PowerScapShortcut {
    <#
    .SYNOPSIS
        Creates a PowerSCAP shortcut that opens the app as administrator with no console window.
    .PARAMETER Path
        The .lnk file to write. Default: PowerSCAP.lnk on the desktop.
    .EXAMPLE
        New-PowerScapShortcut
    .EXAMPLE
        New-PowerScapShortcut -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\PowerSCAP.lnk"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Path = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'PowerSCAP.lnk'))

    $launcher = Join-Path (Split-Path $PSScriptRoot -Parent) 'Start-PowerSCAP.ps1'
    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    if (-not $PSCmdlet.ShouldProcess($Path, 'Create PowerSCAP shortcut')) { return }
    $shell = New-Object -ComObject WScript.Shell
    try {
        $lnk = $shell.CreateShortcut($Path)
        $lnk.TargetPath = $powershell
        $lnk.Arguments = "-NoProfile -STA -WindowStyle Hidden -File `"$launcher`""
        $lnk.WorkingDirectory = Split-Path $launcher -Parent
        $lnk.Description = 'PowerSCAP SCAP compliance scanner'
        $lnk.IconLocation = "$powershell,0"
        $lnk.WindowStyle = 7
        $lnk.Save()
    }
    finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }

    # "Run as administrator": SLDF_RUNAS_USER (0x2000) in the LinkFlags field at offset 0x14 of the .lnk header.
    $bytes = [IO.File]::ReadAllBytes($Path)
    $bytes[0x15] = $bytes[0x15] -bor 0x20
    [IO.File]::WriteAllBytes($Path, $bytes)
    Get-Item -LiteralPath $Path
}
