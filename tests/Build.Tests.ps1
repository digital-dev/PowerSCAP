$repo = Split-Path $PSScriptRoot -Parent
$module = Join-Path $repo 'src\PowerSCAP'

Describe 'Engine build' {
    It 'compiles and exposes the engine version' {
        Import-Module $module -Force
        [PowerScap.Engine.EngineInfo]::Version | Should Be '0.1.0'
    }

    It 'reuses the cached DLL when sources are unchanged' {
        $bin = Join-Path $env:TEMP ('PowerScapBinTest_' + [guid]::NewGuid().ToString('N'))
        $cmd = "`$env:POWERSCAP_BINDIR='$bin'; Import-Module '$module' -Force; [PowerScap.Engine.EngineInfo]::Version"
        $first  = powershell.exe -NoProfile -NonInteractive -Command $cmd
        $second = powershell.exe -NoProfile -NonInteractive -Command $cmd
        $first  | Should Be '0.1.0'
        $second | Should Be '0.1.0'
        @(Get-ChildItem $bin -Filter 'PowerScap.Engine.*.dll').Count | Should Be 1
        Remove-Item $bin -Recurse -Force -ErrorAction SilentlyContinue
    }
}
