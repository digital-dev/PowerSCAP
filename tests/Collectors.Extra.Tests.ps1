$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$mySid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$objects = @"
<win:wmi_object id="oval:t:obj:wmi" version="1"><win:namespace>root\cimv2</win:namespace><win:wql>SELECT name FROM win32_logicaldisk WHERE drivetype=3</win:wql></win:wmi_object>
<win:cmdlet_object id="oval:t:obj:cmdlet" version="1"><win:module_name>CimCmdlets</win:module_name><win:module_id xsi:nil="true"/><win:module_version datatype="version" xsi:nil="true"/><win:verb>Get</win:verb><win:noun>CimInstance</win:noun><win:parameters datatype="record"><field name="classname">Win32_OperatingSystem</field></win:parameters><win:select datatype="record"><field name="property">Caption,Primary</field></win:select></win:cmdlet_object>
<win:cmdlet_object id="oval:t:obj:cmdlet_unknown" version="1"><win:module_name>Microsoft.PowerShell.Management</win:module_name><win:module_id xsi:nil="true"/><win:module_version datatype="version" xsi:nil="true"/><win:verb>Get</win:verb><win:noun>Item</win:noun><win:parameters datatype="record"><field name="path">C:\Windows</field></win:parameters><win:select datatype="record"><field name="property">Name</field></win:select></win:cmdlet_object>
<win:ntuser_object id="oval:t:obj:ntuser" version="1"><win:key>Software\PowerSCAPTest</win:key><win:name>NtValue</win:name></win:ntuser_object>
<win:userright_object id="oval:t:obj:right" version="1"><win:userright>SE_DEBUG_NAME</win:userright></win:userright_object>
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

    It 'cmdlet_object runs the cmdlet natively and records selected properties with module identity' {
        $o = C 'oval:t:obj:cmdlet'
        $o.Items.Count | Should Be 1
        $item = $o.Items[0]
        $item.Get('module_name')[0].Value | Should Be 'CimCmdlets'
        $item.Get('module_id')[0].Value | Should Be '{fb6cc51d-c096-4b38-b78d-0fed6277096a}'
        $value = $item.Get('value')[0]
        $value.Datatype | Should Be 'record'
        ($value.Fields | ForEach-Object { $_.Name }) -join ',' | Should Be 'caption,primary'
        ($value.Fields | Where-Object { $_.Name -eq 'caption' }).Value | Should Be (Get-CimInstance Win32_OperatingSystem).Caption
        ($value.Fields | Where-Object { $_.Name -eq 'primary' }).Value | Should Be 'True'
    }

    It 'cmdlet_object whose cmdlet fails is an Error, not an absent value' {
        $ctx2 = New-DefaultContext -Objects '<win:cmdlet_object id="oval:t:obj:cmdlet_err" version="1"><win:module_name>CimCmdlets</win:module_name><win:module_id xsi:nil="true"/><win:module_version datatype="version" xsi:nil="true"/><win:verb>Get</win:verb><win:noun>CimInstance</win:noun><win:parameters datatype="record"><field name="classname">Win32_Nothing</field><field name="namespace">root\NoSuchNamespacePowerSCAP</field></win:parameters><win:select datatype="record"><field name="property">x</field></win:select></win:cmdlet_object>'
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx2.FindObject('oval:t:obj:cmdlet_err'), $ctx2)
        $o.Flag.ToString() | Should Be 'Error'
        $o.Items[0].Status.ToString() | Should Be 'Error'
    }

    It 'cmdlet_object without a native implementation is not collected (PowerShell is never run)' {
        $o = C 'oval:t:obj:cmdlet_unknown'
        $o.Flag.ToString() | Should Be 'NotCollected'
        $o.Items.Count | Should Be 0
    }

    It 'ntuser_object reads the value from the current user hive' {
        $item = (C 'oval:t:obj:ntuser').Items | Where-Object { $_.Get('sid')[0].Value -eq $mySid }
        $item | Should Not BeNullOrEmpty
        $item.Get('value')[0].Value | Should Be '7'
        $item.Get('logged_on')[0].Value | Should Be '1'
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
