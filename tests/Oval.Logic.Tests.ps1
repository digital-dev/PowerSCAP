$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force

function New-ResultList([string]$s) {
    $map = @{ T = 'True'; F = 'False'; E = 'Error'; U = 'Unknown'; NE = 'NotEvaluated'; NA = 'NotApplicable' }
    $list = New-Object 'System.Collections.Generic.List[PowerScap.Engine.Oval.OvalResult]'
    foreach ($t in ($s -split ',' | Where-Object { $_ })) { $list.Add([PowerScap.Engine.Oval.OvalResult]$map[$t]) }
    , $list
}
$names = @{ T = 'True'; F = 'False'; E = 'Error'; U = 'Unknown'; NE = 'NotEvaluated'; NA = 'NotApplicable' }

Describe 'OvalLogic.Combine (operator truth tables)' {
    $cases = @(
        @('AND', 'T,T', 'T'), @('AND', 'T,F,E', 'F'), @('AND', 'T,E,U', 'E'), @('AND', 'T,U', 'U'),
        @('AND', 'NA,NA', 'NA'), @('AND', 'T,NA', 'T'), @('AND', 'T,NE', 'NE'),
        @('OR', 'F,T,E', 'T'), @('OR', 'F,E', 'E'), @('OR', 'F,F', 'F'), @('OR', 'F,NA', 'F'),
        @('ONE', 'T,F', 'T'), @('ONE', 'T,T', 'F'), @('ONE', 'T,U', 'U'), @('ONE', 'F,F', 'F'),
        @('XOR', 'T,T,T', 'T'), @('XOR', 'T,T', 'F'), @('XOR', 'T,E', 'E')
    )
    foreach ($c in $cases) {
        It "$($c[0]) [$($c[1])] -> $($c[2])" {
            [PowerScap.Engine.Oval.OvalLogic]::Combine($c[0], (New-ResultList $c[1])).ToString() | Should Be $names[$c[2]]
        }
    }
}

Describe 'OvalLogic.Negate' {
    It 'flips only true and false' {
        [PowerScap.Engine.Oval.OvalLogic]::Negate('True').ToString() | Should Be 'False'
        [PowerScap.Engine.Oval.OvalLogic]::Negate('Error').ToString() | Should Be 'Error'
        [PowerScap.Engine.Oval.OvalLogic]::Negate('NotApplicable').ToString() | Should Be 'NotApplicable'
    }
}

Describe 'OvalLogic.Existence' {
    $cases = @(
        @('all_exist', 0, 0, 0, 0, 'F'), @('all_exist', 2, 0, 0, 0, 'T'), @('all_exist', 2, 1, 0, 0, 'F'),
        @('all_exist', 1, 0, 1, 0, 'E'), @('all_exist', 1, 0, 0, 1, 'U'),
        @('none_exist', 0, 0, 0, 0, 'T'), @('none_exist', 1, 0, 0, 0, 'F'), @('none_exist', 0, 2, 0, 0, 'T'),
        @('at_least_one_exists', 1, 3, 0, 0, 'T'), @('at_least_one_exists', 0, 0, 0, 1, 'U'),
        @('at_least_one_exists', 0, 0, 0, 0, 'F'), @('at_least_one_exists', 0, 1, 1, 0, 'E'),
        @('only_one_exists', 2, 0, 0, 0, 'F'), @('only_one_exists', 1, 5, 0, 0, 'T'),
        @('any_exist', 0, 0, 0, 0, 'T'), @('any_exist', 0, 0, 1, 0, 'E'), @('any_exist', 1, 0, 1, 0, 'T')
    )
    foreach ($c in $cases) {
        It "$($c[0]) (ex=$($c[1]) dne=$($c[2]) err=$($c[3]) nc=$($c[4])) -> $($c[5])" {
            [PowerScap.Engine.Oval.OvalLogic]::Existence($c[0], $c[1], $c[2], $c[3], $c[4]).ToString() | Should Be $names[$c[5]]
        }
    }
}

Describe 'OvalLogic.Check' {
    $cases = @(
        @('all', 'T,T', 'T'), @('all', '', 'T'), @('all', 'T,F', 'F'), @('all', 'T,E', 'E'),
        @('none satisfy', 'F,F', 'T'), @('none satisfy', 'F,T', 'F'),
        @('only one', 'T,F', 'T'), @('only one', 'T,T', 'F'),
        @('at least one', 'F,E', 'E'), @('at least one', 'F,T', 'T'), @('at least one', 'F,F', 'F')
    )
    foreach ($c in $cases) {
        It "$($c[0]) [$($c[1])] -> $($c[2])" {
            [PowerScap.Engine.Oval.OvalLogic]::Check($c[0], (New-ResultList $c[1])).ToString() | Should Be $names[$c[2]]
        }
    }
}
