$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force

Describe 'OvalOps.Compare' {
    $cases = @(
        @('version', 'greater than', '10.0.26100.1', '10.0.9.0', 'True'),
        @('version', 'equals', '1.2', '1.2.0.0', 'True'),
        @('version', 'less than', '6.1.7601', '10.0', 'True'),
        @('int', 'equals', '0x10', '16', 'True'),
        @('int', 'less than or equal', 'abc', '1', 'Error'),
        @('int', 'greater than or equal', '15', '15', 'True'),
        @('string', 'case insensitive equals', 'ABC', 'abc', 'True'),
        @('string', 'equals', 'ABC', 'abc', 'False'),
        @('string', 'not equal', 'a', 'b', 'True'),
        @('string', 'pattern match', 'HKLM\Software', '^HKLM\\', 'True'),
        @('string', 'pattern match', 'abc', '^B', 'False'),
        @('boolean', 'equals', '1', 'true', 'True'),
        @('boolean', 'equals', 'false', '0', 'True'),
        @('int', 'bitwise and', '7', '5', 'True'),
        @('int', 'bitwise and', '4', '5', 'False'),
        @('int', 'bitwise or', '5', '7', 'True'),
        @('binary', 'equals', '0A0b', '0a0B', 'True'),
        @('string', 'greater than', 'b', 'a', 'Error'),
        @('ipv4_address', 'greater than', '10.0.0.2', '10.0.0.1', 'True'),
        @('ipv4_address', 'subset of', '10.1.2.0/24', '10.0.0.0/8', 'True'),
        @('float', 'less than', '1.5', '2', 'True')
    )
    foreach ($c in $cases) {
        It "$($c[0]) '$($c[2])' $($c[1]) '$($c[3])' -> $($c[4])" {
            [PowerScap.Engine.Oval.OvalOps]::Compare($c[0], $c[1], $c[2], $c[3]).ToString() | Should Be $c[4]
        }
    }
}

Describe 'OvalOps.PatternMatch' {
    It 'translates POSIX character classes' {
        [PowerScap.Engine.Oval.OvalOps]::PatternMatch('abc123', '^[[:alpha:]]+[[:digit:]]+$') | Should Be $true
    }
    It 'is case-sensitive unless the pattern asks otherwise' {
        [PowerScap.Engine.Oval.OvalOps]::PatternMatch('ABC', '^abc$') | Should Be $false
        [PowerScap.Engine.Oval.OvalOps]::PatternMatch('ABC', '(?i)^abc$') | Should Be $true
    }

    It 'drops a leading .* from each top-level alternative for yes/no matching' {
        [PowerScap.Engine.Oval.OvalOps]::SearchForm('.*\.exe\.config$|v4\.0\.30319\\Config\\machine.config') | Should Be '\.exe\.config$|v4\.0\.30319\\Config\\machine.config'
        [PowerScap.Engine.Oval.OvalOps]::SearchForm('.*?foo') | Should Be 'foo'
        [PowerScap.Engine.Oval.OvalOps]::SearchForm('(.*foo|bar)') | Should Be '(.*foo|bar)'
        [PowerScap.Engine.Oval.OvalOps]::SearchForm('[.*]x|\.*y') | Should Be '[.*]x|\.*y'
        [PowerScap.Engine.Oval.OvalOps]::SearchForm('.*') | Should Be ''
    }

    It 'gives the same answers with and without the leading .*' {
        $cases = @(
            @('C:\Program Files\App\app.exe.config', '.*\.exe\.config$'),
            @('C:\Windows\x.exe.config.bak', '.*\.exe\.config$'),
            @('C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config', '.*\.exe\.config$|v4\.0\.30319\\Config\\machine.config'),
            @("line1`nline2 tail", '.*tail$'),
            @('', '.*')
        )
        foreach ($c in $cases) {
            [PowerScap.Engine.Oval.OvalOps]::PatternMatch($c[0], $c[1]) | Should Be ([regex]::IsMatch($c[0], $c[1]))
        }
    }

    It 'matches a leading-.* pattern against many long paths quickly' {
        $path = 'C:\' + ('abcdefghij\' * 25) + 'file.dll'
        $sw = [Diagnostics.Stopwatch]::StartNew()
        for ($i = 0; $i -lt 20000; $i++) { [PowerScap.Engine.Oval.OvalOps]::PatternMatch($path, '.*\.exe\.config$|v4\.0\.30319\\Config\\machine.config') | Out-Null }
        $sw.Elapsed.TotalSeconds | Should BeLessThan 3
    }
}
