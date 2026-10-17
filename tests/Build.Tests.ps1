$repo = Split-Path $PSScriptRoot -Parent
$module = Join-Path $repo 'src\PowerSCAP'

Describe 'Engine build' {
    It 'compiles and exposes the engine version' {
        Import-Module $module -Force
        [PowerScap.Engine.EngineInfo]::Version | Should Be '0.1.0'
    }

    It 'warns when the sources changed after this window loaded the engine' {
        Import-Module $module -Force
        $copy = Join-Path $env:TEMP ('PowerScapSrcTest_' + [guid]::NewGuid().ToString('N'))
        Copy-Item (Join-Path $module 'Engine') $copy -Recurse
        Add-Content (Join-Path $copy 'Version.cs') '// changed'
        try {
            $warnings = & (Get-Module PowerSCAP) { param($root) $old = $script:EngineSourceRoot; $script:EngineSourceRoot = $root; try { Import-PowerScapEngine 3>&1 } finally { $script:EngineSourceRoot = $old } } $copy
            "$warnings" | Should Match 'open a new PowerShell window'
            $same = & (Get-Module PowerSCAP) { Import-PowerScapEngine 3>&1 }
            @($same).Count | Should Be 0
        }
        finally { Remove-Item $copy -Recurse -Force -ErrorAction SilentlyContinue }
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
