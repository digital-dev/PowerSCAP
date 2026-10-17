$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
$fixture = Join-Path $PSScriptRoot 'fixtures\oval\sets.xml'

function Get-Names($collected) { @($collected.Items | ForEach-Object { $_.Get('name')[0].Value }) -join ',' }

Describe 'ObjectEvaluator' {
    $ctx = New-TestContext $fixture

    It 'collects a plain object through its collector' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:a'), $ctx)
        Get-Names $o | Should Be 'a,b'
        $o.Flag.ToString() | Should Be 'Complete'
    }

    It 'unions two objects without duplicate items' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:union'), $ctx)
        Get-Names $o | Should Be 'a,b,c'
    }

    It 'complements object B from A' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:complement'), $ctx)
        Get-Names $o | Should Be 'a,c'
    }

    It 'intersects two objects' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:intersect'), $ctx)
        Get-Names $o | Should Be 'b'
    }

    It 'exclude filter drops items matching the state' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:filtered'), $ctx)
        Get-Names $o | Should Be 'b'
    }

    It 'unknown object type is NotCollected' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:unknown'), $ctx)
        $o.Flag.ToString() | Should Be 'NotCollected'
    }

    It 'a throwing collector yields Error with a message instead of throwing' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:boom'), $ctx)
        $o.Flag.ToString() | Should Be 'Error'
        ($o.Messages -join ' ') | Should Match 'collector exploded'
    }

    It 'memoizes objects by id' {
        $x = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:a'), $ctx)
        $y = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:a'), $ctx)
        [object]::ReferenceEquals($x, $y) | Should Be $true
    }
}
