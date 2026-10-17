$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
$fixture = Join-Path $PSScriptRoot 'fixtures\oval\variables.xml'

Describe 'VariableResolver' {
    $ctx = New-TestContext $fixture
    $ext = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.IList[string]]'
    $ext['oval:t:var:ext'] = [System.Collections.Generic.List[string]]@('40')
    $ctx.Variables = New-Object PowerScap.Engine.Oval.VariableResolver($ctx, $ext)

    function V($id) { $ctx.Variables.Resolve($id) }

    It 'concat produces the cartesian product'      { (V 'oval:t:var:concat').Values -join '|' | Should Be 'ab|ac' }
    It 'regex_capture returns the first group'      { (V 'oval:t:var:capture').Values -join '|' | Should Be '10.0' }
    It 'split splits on the delimiter'              { (V 'oval:t:var:split').Values -join '|' | Should Be 'a|b' }
    It 'substring is 1-based'                       { (V 'oval:t:var:substring').Values -join '|' | Should Be 'bcd' }
    It 'count counts values'                        { (V 'oval:t:var:count').Values -join '|' | Should Be '2' }
    It 'glob_to_regex converts a glob'              { (V 'oval:t:var:glob').Values -join '|' | Should Be '^[^\\]*\.exe$' }
    It 'object_component reads item fields'         { (V 'oval:t:var:objcomp').Values -join '|' | Should Be 'a|b|c' }
    It 'arithmetic adds with external values'       { (V 'oval:t:var:arith').Values -join '|' | Should Be '42' }
    It 'unique removes duplicates'                  { (V 'oval:t:var:unique').Values -join '|' | Should Be 'b|c' }
    It 'escape_regex escapes metacharacters'        { (V 'oval:t:var:escape').Values -join '|' | Should Be 'a\.b\*c' }
    It 'begin prepends the character when missing'  { (V 'oval:t:var:begin').Values -join '|' | Should Be '\Windows' }

    It 'a missing external variable is an Error' {
        (V 'oval:t:var:missing_ext').Flag.ToString() | Should Be 'Error'
    }

    It 'objects use variable values for their entities' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:byvar'), $ctx)
        @($o.Items | ForEach-Object { $_.Get('name')[0].Value }) -join ',' | Should Be 'x,y'
    }

    It 'an object whose variable errors is flagged Error' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:byext'), $ctx)
        $o.Flag.ToString() | Should Be 'Error'
    }
}
