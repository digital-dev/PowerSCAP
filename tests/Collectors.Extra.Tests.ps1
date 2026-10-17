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
<ind:shellcommand_object id="oval:t:obj:lines" version="1"><ind:shell>cmd</ind:shell><ind:command>echo A: &amp; echo. &amp; echo B:</ind:command><ind:pattern>.*</ind:pattern></ind:shellcommand_object>
<win:wmi57_object id="oval:t:obj:wmi57_none" version="1"><win:namespace>root\cimv2</win:namespace><win:wql>SELECT Name FROM Win32_Service WHERE Name='NoSuchServicePowerSCAP'</win:wql></win:wmi57_object>
<win:wmi_object id="oval:t:obj:wmi_none" version="1"><win:namespace>root\cimv2</win:namespace><win:wql>SELECT Name FROM Win32_Service WHERE Name='NoSuchServicePowerSCAP'</win:wql></win:wmi_object>
<win:passwordpolicy_object id="oval:t:obj:pw" version="1"/>
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

    It 'shellcommand_object returns one item per command with one stdout_line per matching line' {
        $o = C 'oval:t:obj:shell'
        $o.Items.Count | Should Be 1
        @($o.Items[0].Get('stdout_line')).Count | Should Be 2
        ($o.Items[0].Get('subexpression') | ForEach-Object { $_.Value }) -join ',' | Should Be '1,3'
        $o.Items[0].Get('exit_status')[0].Value | Should Be '0'
    }

    It 'shellcommand with no matching output still yields the item, without stdout_line' {
        $ctx2 = New-DefaultContext -Objects '<ind:shellcommand_object id="oval:t:obj:quiet" version="1"><ind:shell>cmd</ind:shell><ind:command>echo nothing</ind:command><ind:pattern>^zzz</ind:pattern></ind:shellcommand_object>'
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx2.FindObject('oval:t:obj:quiet'), $ctx2)
        $o.Items.Count | Should Be 1
        @($o.Items[0].Get('stdout_line')).Count | Should Be 0
    }

    It 'ntuser_object reads the value from the current user hive' {
        $item = (C 'oval:t:obj:ntuser').Items | Where-Object { $_.Get('sid')[0].Value -eq $mySid }
        $item | Should Not BeNullOrEmpty
        $item.Get('value')[0].Value | Should Be '7'
        $item.Get('logged_on')[0].Value | Should Be '1'
    }

    It 'shellcommand keeps blank lines but not the trailing newline' {
        @((C 'oval:t:obj:lines').Items[0].Get('stdout_line')).Count | Should Be 3
    }

    It 'powershell shell commands run in-process (no child powershell.exe)' {
        $ctx2 = New-DefaultContext -Objects '<ind:shellcommand_object id="oval:t:obj:pid" version="1"><ind:shell>powershell</ind:shell><ind:command>"pid=$PID"</ind:command><ind:pattern>^pid=(\d+)$</ind:pattern></ind:shellcommand_object>'
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx2.FindObject('oval:t:obj:pid'), $ctx2)
        $o.Items[0].Get('subexpression')[0].Value | Should Be "$PID"
    }

    It 'powershell shell commands report native exit codes and errors' {
        $objs = '<ind:shellcommand_object id="oval:t:obj:exit" version="1"><ind:shell>powershell</ind:shell><ind:command>cmd /c exit 3</ind:command><ind:pattern>.*</ind:pattern></ind:shellcommand_object>' +
                '<ind:shellcommand_object id="oval:t:obj:err" version="1"><ind:shell>powershell</ind:shell><ind:command>Write-Error "boom"</ind:command><ind:pattern>.*</ind:pattern></ind:shellcommand_object>'
        $ctx2 = New-DefaultContext -Objects $objs
        ([PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx2.FindObject('oval:t:obj:exit'), $ctx2)).Items[0].Get('exit_status')[0].Value | Should Be '3'
        $e = ([PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx2.FindObject('oval:t:obj:err'), $ctx2)).Items[0]
        $e.Get('exit_status')[0].Value | Should Be '1'
        ($e.Get('stderr_line') | ForEach-Object { $_.Value }) -join ' ' | Should Match 'boom'
    }

    It 'wmi57 with no rows is DoesNotExist' {
        $o = C 'oval:t:obj:wmi57_none'
        $o.Items.Count | Should Be 0
        $o.Flag.ToString() | Should Be 'DoesNotExist'
    }

    It 'wmi with no rows is DoesNotExist' {
        (C 'oval:t:obj:wmi_none').Flag.ToString() | Should Be 'DoesNotExist'
    }

    It 'passwordpolicy reports anonymous_name_lookup (Error without elevation)' {
        $e = (C 'oval:t:obj:pw').Items[0].Get('anonymous_name_lookup')
        $e.Count | Should Be 1
    }

    Remove-Item 'HKCU:\Software\PowerSCAPTest' -Recurse -Force
}

Describe 'passwordpolicy anonymous_name_lookup' -Tag Admin {
    $ctx = New-DefaultContext -Objects $objects
    It 'reads the LSA anonymous name lookup policy as a boolean' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:pw'), $ctx)
        $o.Items[0].Get('anonymous_name_lookup')[0].Value | Should Match '^(0|1)$'
    }
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
