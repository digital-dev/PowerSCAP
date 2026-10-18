# Opens the PowerSCAP desktop app. Shortcuts from New-PowerScapShortcut run this hidden and elevated,
# so a startup failure is shown in a message box rather than a console nobody sees.
try {
    Import-Module (Join-Path $PSScriptRoot 'PowerSCAP.psd1') -Force -ErrorAction Stop
    Start-PowerScapGui
}
catch {
    Add-Type -AssemblyName PresentationFramework
    [void][Windows.MessageBox]::Show("PowerSCAP could not start:`n`n$($_.Exception.Message)", 'PowerSCAP', 'OK', 'Error')
}
