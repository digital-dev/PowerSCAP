$repo = Split-Path $PSScriptRoot -Parent
$module = Import-Module (Join-Path $repo 'src\PowerSCAP') -Force -PassThru
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
& $module { Import-PowerScapGui }

$mini = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'
$guiDir = Join-Path $repo 'src\PowerSCAP\Gui'
$isSta = [Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'

if (-not ('PowerScapTests.BindingErrors' -as [type])) {
    Add-Type -ReferencedAssemblies WindowsBase -TypeDefinition @'
using System.Collections.Generic;
using System.Diagnostics;
namespace PowerScapTests
{
    /// Collects WPF data binding errors (System.Windows.Data Error: ...).
    public class BindingErrors : TraceListener
    {
        public List<string> Errors = new List<string>();
        public override void Write(string message) { }
        public override void WriteLine(string message) { Errors.Add(message); }
    }
}
'@
}

Describe 'GUI settings' {
    $path = Join-Path $env:TEMP ('powerscap-settings-' + [guid]::NewGuid().ToString('N') + '.json')

    It 'defaults to the dark theme, HTML and checklist outputs, and update checks' {
        $s = [PowerScap.Gui.GuiSettings]::Load($path)
        $s.Theme | Should Be 'Dark'
        $s.Formats.ToString() | Should Be 'Html, Cklb'
        $s.CheckUpdatesOnLaunch | Should Be $true
        $s.AllowUnelevated | Should Be $false
        $s.EffectiveCacheRoot | Should Be ([PowerScap.Engine.Cache.ContentCache]::DefaultRoot())
    }

    It 'saves and loads every choice' {
        $s = New-Object PowerScap.Gui.GuiSettings
        $s.Theme = 'Light'; $s.Oval = $true; $s.Flavor = 'SCAP 1.3 Content'; $s.OutputPath = 'D:\Results'
        $s.ProfileChoices['xccdf_b'] = 'xccdf_p2'
        $s.Save($path)
        $back = [PowerScap.Gui.GuiSettings]::Load($path)
        $back.Theme | Should Be 'Light'
        $back.Formats.ToString() | Should Be 'Html, Cklb, Oval'
        $back.Flavor | Should Be 'SCAP 1.3 Content'
        $back.EffectiveOutputPath | Should Be 'D:\Results'
        $back.ProfileChoices['xccdf_b'] | Should Be 'xccdf_p2'
    }

    It 'falls back to defaults when the file is damaged' {
        Set-Content $path -Value '{ broken' -Encoding ASCII
        ([PowerScap.Gui.GuiSettings]::Load($path)).Theme | Should Be 'Dark'
    }

    It 'resolves Follow Windows to the Windows app theme' {
        $expected = if ([PowerScap.Gui.ThemeManager]::WindowsUsesLightTheme()) { 'Light' } else { 'Dark' }
        [PowerScap.Gui.ThemeManager]::Resolve('System') | Should Be $expected
        [PowerScap.Gui.ThemeManager]::Resolve('Light') | Should Be 'Light'
        [PowerScap.Gui.ThemeManager]::Resolve('nonsense') | Should Be 'Dark'
    }

    Remove-Item $path -ErrorAction SilentlyContinue
}

Describe 'Benchmark detection for cached content' {
    $profile = New-Object PowerScap.Engine.Profile.SystemProfile
    foreach ($p in @(@('Windows 11', 'Microsoft Windows 11'), @('.NET Framework 4', 'Microsoft .NET Framework 4.0'), @('Windows Defender Firewall', 'Windows Firewall'))) {
        $profile.Products.Add((New-Object PowerScap.Engine.Profile.DetectedProduct -Property @{ Name = $p[0]; NcpTarget = $p[1] }))
    }

    It 'uses the NCP targets recorded at download' {
        [PowerScap.Gui.ContentViewModel]::IsForThisMachine($profile, [string[]]@('Microsoft Windows 11'), 'anything') | Should Be $true
        [PowerScap.Gui.ContentViewModel]::IsForThisMachine($profile, [string[]]@('Microsoft Windows Server 2008', 'Windows Firewall'), 'anything') | Should Be $false
    }

    It 'falls back to product names in the title for older or imported content' {
        [PowerScap.Gui.ContentViewModel]::IsForThisMachine($profile, $null, 'Microsoft .NET Framework 4') | Should Be $true
        [PowerScap.Gui.ContentViewModel]::IsForThisMachine($profile, $null, 'Microsoft Windows Defender Firewall with Advanced Security STIG') | Should Be $true
        [PowerScap.Gui.ContentViewModel]::IsForThisMachine($profile, $null, 'Google Chrome Browser STIG') | Should Be $false
    }
}

Describe 'GUI window' -Tag Gui {
    $root = Join-Path $env:TEMP ('powerscap-gui-' + [guid]::NewGuid().ToString('N'))
    $env:POWERSCAP_HISTORYDIR = Join-Path $root 'history'
    $cacheRoot = Join-Path $root 'cache'
    (New-Object PowerScap.Engine.Cache.ContentCache($cacheRoot, (New-Object PowerScapTests.FakeTransport))).Import($mini) | Out-Null
    $settings = New-Object PowerScap.Gui.GuiSettings
    $settings.CacheRoot = $cacheRoot
    $settings.OutputPath = Join-Path $root 'out'
    $settings.CheckUpdatesOnLaunch = $false
    $settings.AllowUnelevated = $true
    $settings.ProfileChoices['xccdf_test_benchmark_mini'] = 'xccdf_test_profile_p1'

    $errors = New-Object PowerScapTests.BindingErrors
    [Diagnostics.PresentationTraceSources]::Refresh()
    [void][Diagnostics.PresentationTraceSources]::DataBindingSource.Listeners.Add($errors)
    [Diagnostics.PresentationTraceSources]::DataBindingSource.Switch.Level = 'Error'

    $window = [PowerScap.Gui.GuiHost]::CreateWindow($guiDir, $settings, (Join-Path $root 'settings.json'), (New-Object PowerScapTests.FakeTransport), $null)
    $window.WindowStartupLocation = 'Manual'; $window.Left = -32000; $window.ShowActivated = $false; $window.ShowInTaskbar = $false
    $window.Show()
    $vm = $window.DataContext
    function Wait-Ui([double]$Seconds = 1) { [PowerScap.Gui.GuiHost]::Pump([TimeSpan]::FromSeconds($Seconds)) }
    Wait-Ui 3

    It 'lists the cached benchmark with its profiles' -Skip:(-not $isSta) {
        $vm.Content.Items.Count | Should Be 1
        $item = $vm.Content.Items[0]
        $item.ProfilesLoading | Should Be $false
        @($item.Profiles | ForEach-Object Id) -join ',' | Should Be 'xccdf_test_profile_p3,xccdf_test_profile_p1,xccdf_test_profile_p2'
    }

    It 'scans the selected benchmark in the background and reports progress' -Skip:(-not $isSta) {
        $item = $vm.Content.Items[0]
        $item.Profile = $item.Profiles | Where-Object Id -eq 'xccdf_test_profile_p1'
        $item.IsSelected = $true
        $vm.Content.ScanSelectedCommand.Execute($null)
        $vm.Page | Should Be 'Scan'
        $n = 0
        while ($vm.Scan.IsRunning -and $n++ -lt 60) { Wait-Ui 0.5 }
        $job = $vm.Scan.Jobs[0]
        $job.State | Should Be 'Completed'
        $job.Percent | Should Be 100
        $job.Report.Files.ContainsKey('Checklist') | Should Be $true
        @(Get-ChildItem (Join-Path $root 'out') -Filter '*_XCCDF-Results.xml').Count | Should Be 1
    }

    It 'shows the scan as a score tile and its findings' -Skip:(-not $isSta) {
        $vm.Page = 'Results'
        Wait-Ui 2
        $vm.Results.Tiles.Count | Should Be 1
        $vm.Results.Rows.Count | Should Be 2
        $vm.Results.StatusFilter = 'Open'
        @($vm.Results.RowsView).Count | Should Be 1
        $vm.Results.StatusFilter = 'All'
        $vm.Results.SearchText = 'zzz-no-such-rule'
        @($vm.Results.RowsView).Count | Should Be 0
        $vm.Results.SearchText = ''
    }

    It 'marks rules that changed since the previous scan' -Skip:(-not $isSta) {
        Start-Sleep -Milliseconds 1100
        $item = $vm.Content.Items[0]
        $item.Profile = $item.Profiles | Where-Object Id -eq 'xccdf_test_profile_p2'
        $item.IsSelected = $true
        $vm.Content.ScanSelectedCommand.Execute($null)
        $n = 0
        while ($vm.Scan.IsRunning -and $n++ -lt 60) { Wait-Ui 0.5 }
        $vm.Page = 'Results'
        Wait-Ui 2
        $vm.Results.SelectedTile.Runs.Count | Should Be 2
        $vm.Results.HasPrevious | Should Be $true
        $vm.Results.ChangedOnly = $true
        @($vm.Results.RowsView | ForEach-Object { $_.Changed }) -contains $false | Should Be $false
    }

    It 'remembers the profile chosen for a benchmark' -Skip:(-not $isSta) {
        $settings.ProfileChoices['xccdf_test_benchmark_mini'] | Should Be 'xccdf_test_profile_p2'
    }

    It 'switches theme live' -Skip:(-not $isSta) {
        $vm.Options.Theme = 'Light'
        [Windows.Application]::Current.Resources.MergedDictionaries[0]['ThemeName'] | Should Be 'Light'
        $vm.Options.Theme = 'Dark'
        [Windows.Application]::Current.Resources.MergedDictionaries[0]['ThemeName'] | Should Be 'Dark'
    }

    It 'takes a click anywhere on a catalog Download button' -Skip:(-not $isSta) {
        $c = New-Object PowerScap.Engine.Ncp.NcpChecklist
        $c.Id = 953; $c.Name = 'Microsoft Office 365 ProPlus STIG'; $c.Version = 'Ver 3, Rel 8'
        $r = New-Object PowerScap.Engine.Ncp.NcpResource
        $r.Title = 'x'; $r.Location = 'https://example.test/x.zip'; $r.TypeName = 'SCAP 1.4 Content'
        $vm.Content.Catalog.Add((New-Object PowerScap.Gui.CatalogItem -Property @{ Checklist = $c; Resource = $r }))
        $vm.Page = 'Content'
        Wait-Ui 1
        function Find-Visual($node, [scriptblock]$Where) {
            if (& $Where $node) { return $node }
            for ($i = 0; $i -lt [Windows.Media.VisualTreeHelper]::GetChildrenCount($node); $i++) {
                $hit = Find-Visual ([Windows.Media.VisualTreeHelper]::GetChild($node, $i)) $Where
                if ($hit) { return $hit }
            }
        }
        $button = Find-Visual $window { param($v) $v -is [Windows.Controls.Button] -and "$($v.Content)" -eq 'Download' }
        $button | Should Not BeNullOrEmpty
        $button.ActualHeight | Should Not BeLessThan 28
        # InputHitTest is what a mouse click uses (it skips hidden pages; VisualTreeHelper.HitTest does not).
        foreach ($fy in 0.1, 0.25, 0.5, 0.75, 0.9) {
            $point = $button.TranslatePoint((New-Object Windows.Point(($button.ActualWidth / 2), ($button.ActualHeight * $fy))), $window)
            $owner = $window.InputHitTest($point)
            while ($owner -and $owner -ne $button) { $owner = [Windows.Media.VisualTreeHelper]::GetParent($owner) }
            $owner | Should Be $button
        }
        $vm.Content.Catalog.Clear()
    }

    It 'opens the scan''s checklist in the app''s checklist view' -Skip:(-not $isSta) {
        $vm.Page = 'Results'
        Wait-Ui 1
        $vm.Results.OpenFileCommand.Execute('Checklist')
        $vm.Page | Should Be 'Checklist'
        $n = 0
        while ($vm.Checklist.IsLoading -and $n++ -lt 20) { Wait-Ui 0.25 }
        $vm.Checklist.Stigs.Count | Should Be 1
        $vm.Checklist.HasManyStigs | Should Be $false
        $vm.Checklist.Rows.Count | Should Be $vm.Results.Rows.Count
        $vm.Checklist.StatusFilter = 'Open'
        @($vm.Checklist.RowsView).Count | Should Be @($vm.Results.Rows | Where-Object Status -eq 'Open').Count
        $vm.Checklist.StatusFilter = 'All'
        # The benchmark was scanned twice: only the newest checklist is listed, and it is the one shown.
        Wait-Ui 2
        $vm.Checklist.Available.Count | Should Be 1
        $newest = $vm.Checklist.File.Path
        $vm.Checklist.SelectedListing.Path | Should Be $newest

        # Viewing the older scan's checklist from Results shows it and keeps it in the list.
        $vm.Page = 'Results'
        $vm.Results.SelectedRun = $vm.Results.SelectedTile.Runs[1]
        $n = 0
        while ($vm.Results.IsLoading -and $n++ -lt 20) { Wait-Ui 0.25 }
        $vm.Results.OpenFileCommand.Execute('Checklist')
        $n = 0
        while (($vm.Checklist.IsLoading -or $vm.Checklist.File.Path -eq $newest) -and $n++ -lt 20) { Wait-Ui 0.25 }
        $vm.Checklist.File.Path | Should Not Be $newest
        $vm.Checklist.Available.Count | Should Be 2
        $vm.Checklist.SelectedListing.Path | Should Be $vm.Checklist.File.Path
    }

    It 'renders every page without binding errors' -Skip:(-not $isSta) {
        foreach ($p in 'System', 'Content', 'Scan', 'Results', 'Checklist', 'Settings') {
            $vm.Page = $p
            if ($p -eq 'Results') { $vm.Results.SelectedRow = $vm.Results.Rows[0] }
            if ($p -eq 'Checklist') { $vm.Checklist.SelectedRow = $vm.Checklist.Rows[0] }
            Wait-Ui 0.5
        }
        ($errors.Errors -join "`n") | Should BeNullOrEmpty
    }

    $window.Close()
    [Diagnostics.PresentationTraceSources]::DataBindingSource.Listeners.Remove($errors)
    Remove-Item Env:\POWERSCAP_HISTORYDIR
    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Opening output files' {
    It 'knows which file types have a program to open them (.cklb without STIG Viewer is shown in Explorer)' {
        [PowerScap.Gui.Shell]::HasAssociation('.html') | Should Be $true
        [PowerScap.Gui.Shell]::HasAssociation('.powerscap-no-such-type') | Should Be $false
    }
}

Describe 'PowerSCAP shortcut' {
    It 'opens the app hidden and as administrator' {
        $lnk = Join-Path $env:TEMP ('PowerSCAP-' + [guid]::NewGuid().ToString('N') + '.lnk')
        New-PowerScapShortcut -Path $lnk | Out-Null
        $bytes = [IO.File]::ReadAllBytes($lnk)
        ([BitConverter]::ToUInt32($bytes, 0x14) -band 0x2000) | Should Be 0x2000
        $shell = New-Object -ComObject WScript.Shell
        $s = $shell.CreateShortcut($lnk)
        $s.Arguments | Should Match '-WindowStyle Hidden -File ".*Start-PowerSCAP\.ps1"'
        $s.TargetPath | Should Match 'WindowsPowerShell\\v1\.0\\powershell\.exe$'
        Remove-Item $lnk
    }
}
