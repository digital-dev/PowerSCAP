$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$testKey = 'HKCU:\Software\PowerSCAPTest'

Describe 'RegistryCollector' {
    Remove-Item $testKey -Recurse -Force -ErrorAction SilentlyContinue
    New-Item $testKey -Force | Out-Null
    New-ItemProperty $testKey -Name Dw -PropertyType DWord -Value 1 | Out-Null
    New-ItemProperty $testKey -Name Neg -PropertyType DWord -Value -1 | Out-Null
    New-ItemProperty $testKey -Name Multi -PropertyType MultiString -Value @('one', 'two') | Out-Null
    New-ItemProperty $testKey -Name Exp -PropertyType ExpandString -Value '%SystemRoot%\x' | Out-Null
    New-Item "$testKey\Sub1" -Force | Out-Null
    New-Item "$testKey\Sub2" -Force | Out-Null

    $objects = @'
<win:registry_object id="oval:t:obj:dw" version="1"><win:hive>HKEY_CURRENT_USER</win:hive><win:key>Software\PowerSCAPTest</win:key><win:name>Dw</win:name></win:registry_object>
<win:registry_object id="oval:t:obj:neg" version="1"><win:hive>HKEY_CURRENT_USER</win:hive><win:key>Software\PowerSCAPTest</win:key><win:name>Neg</win:name></win:registry_object>
<win:registry_object id="oval:t:obj:multi" version="1"><win:hive>HKEY_CURRENT_USER</win:hive><win:key>Software\PowerSCAPTest</win:key><win:name>Multi</win:name></win:registry_object>
<win:registry_object id="oval:t:obj:exp" version="1"><win:hive>HKEY_CURRENT_USER</win:hive><win:key>Software\PowerSCAPTest</win:key><win:name>Exp</win:name></win:registry_object>
<win:registry_object id="oval:t:obj:missingvalue" version="1"><win:hive>HKEY_CURRENT_USER</win:hive><win:key>Software\PowerSCAPTest</win:key><win:name>Nope</win:name></win:registry_object>
<win:registry_object id="oval:t:obj:missingkey" version="1"><win:hive>HKEY_CURRENT_USER</win:hive><win:key>Software\PowerSCAPTest\Nope</win:key><win:name>Dw</win:name></win:registry_object>
<win:registry_object id="oval:t:obj:pattern_none" version="1"><win:hive>HKEY_CURRENT_USER</win:hive><win:key operation="pattern match">^Software\\PowerSCAPTest\\Zzz.*$</win:key><win:name xsi:nil="true"/></win:registry_object>
<win:registry_object id="oval:t:obj:pattern_subs" version="1"><win:hive>HKEY_CURRENT_USER</win:hive><win:key operation="pattern match">^Software\\PowerSCAPTest\\Sub\d$</win:key><win:name xsi:nil="true"/></win:registry_object>
<win:registry_object id="oval:t:obj:namepattern" version="1"><win:hive>HKEY_CURRENT_USER</win:hive><win:key>Software\PowerSCAPTest</win:key><win:name operation="pattern match">^(Dw|Neg)$</win:name></win:registry_object>
<ind:family_object id="oval:t:obj:family" version="1"/>
<ind:environmentvariable58_object id="oval:t:obj:env" version="1"><ind:pid xsi:nil="true" datatype="int"/><ind:name>SystemRoot</ind:name></ind:environmentvariable58_object>
<ind:variable_object id="oval:t:obj:var" version="1"><ind:var_ref>oval:t:var:two</ind:var_ref></ind:variable_object>
'@
    $variables = '<constant_variable id="oval:t:var:two" version="1" datatype="string" comment="c"><value>x</value><value>y</value></constant_variable>'
    $ctx = New-DefaultContext -Objects $objects -Variables $variables
    function C($id) { [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject($id), $ctx) }

    It 'reads a DWORD as reg_dword with an int value' {
        $o = C 'oval:t:obj:dw'
        $o.Items.Count | Should Be 1
        $o.Items[0].Get('type')[0].Value | Should Be 'reg_dword'
        $o.Items[0].Get('value')[0].Value | Should Be '1'
        $o.Items[0].Get('value')[0].Datatype | Should Be 'int'
    }

    It 'reports DWORDs as unsigned' {
        (C 'oval:t:obj:neg').Items[0].Get('value')[0].Value | Should Be '4294967295'
    }

    It 'returns one value entity per REG_MULTI_SZ string' {
        ((C 'oval:t:obj:multi').Items[0].Get('value') | ForEach-Object { $_.Value }) -join ',' | Should Be 'one,two'
    }

    It 'does not expand REG_EXPAND_SZ' {
        (C 'oval:t:obj:exp').Items[0].Get('value')[0].Value | Should Be '%SystemRoot%\x'
    }

    It 'missing value under an existing key is a DoesNotExist item' {
        $o = C 'oval:t:obj:missingvalue'
        $o.Items.Count | Should Be 1
        $o.Items[0].Status.ToString() | Should Be 'DoesNotExist'
    }

    It 'missing key gives no items and flag DoesNotExist' {
        $o = C 'oval:t:obj:missingkey'
        $o.Items.Count | Should Be 0
        $o.Flag.ToString() | Should Be 'DoesNotExist'
    }

    It 'pattern-matched key with no matches gives DoesNotExist and 0 items' {
        $o = C 'oval:t:obj:pattern_none'
        $o.Items.Count | Should Be 0
        $o.Flag.ToString() | Should Be 'DoesNotExist'
    }

    It 'pattern-matched keys enumerate subkeys' {
        (C 'oval:t:obj:pattern_subs').Items.Count | Should Be 2
    }

    It 'pattern-matched names enumerate values' {
        (C 'oval:t:obj:namepattern').Items.Count | Should Be 2
    }

    It 'family is windows' {
        (C 'oval:t:obj:family').Items[0].Get('family')[0].Value | Should Be 'windows'
    }

    It 'reads process environment variables' {
        (C 'oval:t:obj:env').Items[0].Get('value')[0].Value | Should Be $env:SystemRoot
    }

    It 'variable_object yields one value entity per variable value' {
        ((C 'oval:t:obj:var').Items[0].Get('value') | ForEach-Object { $_.Value }) -join ',' | Should Be 'x,y'
    }

    Remove-Item $testKey -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'RegistryCollector access denied' {
    $locked = "$testKey\Locked"
    New-Item $locked -Force | Out-Null
    New-ItemProperty $locked -Name V -Value 'x' | Out-Null
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl $locked
    # Deny value reads only, so the test can still read and restore the ACL afterwards.
    $deny = New-Object System.Security.AccessControl.RegistryAccessRule($me, 'QueryValues', 'Deny')
    $acl.AddAccessRule($deny)
    Set-Acl $locked $acl

    $ctx = New-DefaultContext -Objects '<win:registry_object id="oval:t:obj:locked" version="1"><win:hive>HKEY_CURRENT_USER</win:hive><win:key>Software\PowerSCAPTest\Locked</win:key><win:name>V</win:name></win:registry_object>'

    It 'unreadable key gives an Error flag with the access-denied message' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:locked'), $ctx)
        $o.Flag.ToString() | Should Be 'Error'
        (($o.Messages + ($o.Items | ForEach-Object { $_.Messages })) -join ' ') | Should Match 'denied'
    }

    # Get-Acl would need value-read access; open with permission rights only to undo the deny.
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\PowerSCAPTest\Locked',
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]'ChangePermissions,ReadPermissions')
    $acl = $k.GetAccessControl()
    $acl.RemoveAccessRule($deny) | Out-Null
    $k.SetAccessControl($acl)
    $k.Close()
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree('Software\PowerSCAPTest', $false)
}

Describe 'RegistryCollector 32-bit view' -Tag Admin {
    $wow = 'HKLM:\SOFTWARE\WOW6432Node\PowerSCAPTest'
    New-Item $wow -Force | Out-Null
    New-ItemProperty $wow -Name Only32 -Value 'thirty-two' -Force | Out-Null
    $objects = @'
<win:registry_object id="oval:t:obj:v32" version="1"><win:behaviors windows_view="32_bit"/><win:hive>HKEY_LOCAL_MACHINE</win:hive><win:key>SOFTWARE\PowerSCAPTest</win:key><win:name>Only32</win:name></win:registry_object>
<win:registry_object id="oval:t:obj:v64" version="1"><win:hive>HKEY_LOCAL_MACHINE</win:hive><win:key>SOFTWARE\PowerSCAPTest</win:key><win:name>Only32</win:name></win:registry_object>
'@
    $ctx = New-DefaultContext -Objects $objects

    It 'windows_view=32_bit reads the WOW6432Node value' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:v32'), $ctx)
        $o.Items[0].Get('value')[0].Value | Should Be 'thirty-two'
    }
    It 'the default 64-bit view does not see it' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:v64'), $ctx)
        $o.Flag.ToString() | Should Be 'DoesNotExist'
    }
    Remove-Item $wow -Recurse -Force -ErrorAction SilentlyContinue
}
