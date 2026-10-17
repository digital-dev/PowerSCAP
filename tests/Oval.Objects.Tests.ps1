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

    It 'filter on a multi-valued entity matches when any value does (STIG intent; SCC)' {
        # user_object filter "group = Administrators" on a user in Administrators and docker-users (SV-253476).
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:admins'), $ctx)
        Get-Names $o | Should Be 'x'
    }

    It 'filter honours an explicit entity_check="all"' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:admins_all'), $ctx)
        $o.Items.Count | Should Be 0
    }

    It 'filter with a multi-value variable matches when any value does (.NET SV-225232 exclude paths)' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:not_os'), $ctx)
        Get-Names $o | Should Be 'b'
    }

    It 'test states keep the OVAL default entity_check="all"' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:groups'), $ctx)
        [PowerScap.Engine.Oval.StateEvaluator]::Evaluate($ctx.FindState('oval:t:ste:is_admin'), $o.Items[0], $ctx).ToString() | Should Be 'False'
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
