$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$mySid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$objects = @"
<win:wmi_object id="oval:t:obj:wmi" version="1"><win:namespace>root\cimv2</win:namespace><win:wql>SELECT name FROM win32_logicaldisk WHERE drivetype=3</win:wql></win:wmi_object>
<win:cmdlet_object id="oval:t:obj:cmdlet" version="1"><win:module_name>Microsoft.PowerShell.Management</win:module_name><win:module_id xsi:nil="true"/><win:module_version datatype="version" xsi:nil="true"/><win:verb>Get</win:verb><win:noun>Item</win:noun><win:parameters datatype="record"><field name="path">C:\Windows</field></win:parameters><win:select datatype="record"><field name="property">Name,Attributes</field></win:select></win:cmdlet_object>
<ind:shellcommand_object id="oval:t:obj:shell" version="1"><ind:shell>cmd</ind:shell><ind:command>echo Alpha - 1: &amp; echo Beta - 2: &amp; echo Alpha - 3:</ind:command><ind:pattern>Alpha - (\d+):</ind:pattern></ind:shellcommand_object>
<win:ntuser_object id="oval:t:obj:ntuser" version="1"><win:key>Software\PowerSCAPTest</win:key><win:name>NtValue</win:name></win:ntuser_object>
<win:userright_object id="oval:t:obj:right" version="1"><win:userright>SE_DEBUG_NAME</win:userright></win:userright_object>
"@

Describe 'Extra collectors' {
    New-Item 'HKCU:\Software\PowerSCAPTest' -Force | Out-Null
    New-ItemProperty 'HKCU:\Software\PowerSCAPTest' -Name NtValue -PropertyType DWord -Value 7 -Force | Out-Null
    $ctx = New-DefaultContext -Objects $objects
    function C($id) { [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject($id), $ctx) }

    It 'wmi_object returns one result value per WMI object' {
        $values = @((C 'oval:t:obj:wmi').Items[0].Get('result') | ForEach-Object { $_.Value })
        $values -contains $env:SystemDrive | Should Be $true
    }

    It 'cmdlet_object runs the cmdlet and records selected properties' {
        $o = C 'oval:t:obj:cmdlet'
        $o.Items.Count | Should Be 1
        $value = $o.Items[0].Get('value')[0]
        $value.Datatype | Should Be 'record'
        ($value.Fields | Where-Object { $_.Name -eq 'name' }).Value | Should Be 'Windows'
    }

    It 'shellcommand_object returns one item per matching output line with subexpressions' {
        $o = C 'oval:t:obj:shell'
        ($o.Items | ForEach-Object { $_.Get('subexpression')[0].Value }) -join ',' | Should Be '1,3'
        $o.Items[0].Get('exit_status')[0].Value | Should Be '0'
    }

    It 'ntuser_object reads the value from the current user hive' {
        $item = (C 'oval:t:obj:ntuser').Items | Where-Object { $_.Get('sid')[0].Value -eq $mySid }
        $item | Should Not BeNullOrEmpty
        $item.Get('value')[0].Value | Should Be '7'
        $item.Get('logged_on')[0].Value | Should Be '1'
    }

    Remove-Item 'HKCU:\Software\PowerSCAPTest' -Recurse -Force
}

Describe 'userright_object' -Tag Admin {
    $ctx = New-DefaultContext -Objects $objects
    It 'SE_DEBUG_NAME is held by Administrators (bare trustee name)' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:right'), $ctx)
        @($o.Items | ForEach-Object { $_.Get('trustee_name')[0].Value }) -contains 'Administrators' | Should Be $true
    }
}

Describe 'userright_object without elevation' {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $ctx = New-DefaultContext -Objects $objects
    It 'is an Error, not an exception' -Skip:$isAdmin {
        ([PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:right'), $ctx)).Flag.ToString() | Should Be 'Error'
    }
}
