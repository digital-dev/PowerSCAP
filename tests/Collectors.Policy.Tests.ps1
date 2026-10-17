$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myName = $me.Name.Split('\')[1]
$objects = @"
<win:passwordpolicy_object id="oval:t:obj:pw" version="1"/>
<win:lockoutpolicy_object id="oval:t:obj:lock" version="1"/>
<win:sid_sid_object id="oval:t:obj:admins_sid" version="1"><win:trustee_sid>S-1-5-32-544</win:trustee_sid></win:sid_sid_object>
<win:sid_object id="oval:t:obj:admins_name" version="1"><win:trustee_name>BUILTIN\Administrators</win:trustee_name></win:sid_object>
<win:user_object id="oval:t:obj:me" version="1"><win:user>$myName</win:user></win:user_object>
<win:user_sid55_object id="oval:t:obj:me_sid" version="1"><win:user_sid>$($me.User.Value)</win:user_sid></win:user_sid55_object>
<win:group_sid_object id="oval:t:obj:admins_members" version="1"><win:group_sid>S-1-5-32-544</win:group_sid></win:group_sid_object>
<win:group_object id="oval:t:obj:admins_group" version="1"><win:group>Administrators</win:group></win:group_object>
<win:service_object id="oval:t:obj:wuauserv" version="1"><win:service_name>wuauserv</win:service_name></win:service_object>
<win:service_object id="oval:t:obj:noservice" version="1"><win:service_name>NoSuchServicePowerSCAP</win:service_name></win:service_object>
<win:auditeventpolicysubcategories_object id="oval:t:obj:audit" version="1"/>
<win:accesstoken_object id="oval:t:obj:token" version="1"><win:security_principle>BUILTIN\Administrators</win:security_principle></win:accesstoken_object>
"@

function Get-NetAccountsValue([string]$label) {
    $line = net accounts | Where-Object { $_ -like "$label*" } | Select-Object -First 1
    ($line -split ':\s*', 2)[1].Trim()
}

Describe 'Policy and account collectors' {
    $ctx = New-DefaultContext -Objects $objects
    function C($id) { [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject($id), $ctx) }

    It 'passwordpolicy min_passwd_len matches net accounts' {
        (C 'oval:t:obj:pw').Items[0].Get('min_passwd_len')[0].Value | Should Be (Get-NetAccountsValue 'Minimum password length')
    }

    It 'passwordpolicy reports password_complexity as a boolean' {
        (C 'oval:t:obj:pw').Items[0].Get('password_complexity')[0].Value | Should Match '^(0|1)$'
    }

    It 'lockoutpolicy lockout_threshold matches net accounts' {
        $expected = Get-NetAccountsValue 'Lockout threshold'
        if ($expected -eq 'Never') { $expected = '0' }
        (C 'oval:t:obj:lock').Items[0].Get('lockout_threshold')[0].Value | Should Be $expected
    }

    It 'sid_sid resolves S-1-5-32-544 to BUILTIN\Administrators' {
        $i = (C 'oval:t:obj:admins_sid').Items[0]
        $i.Get('trustee_name')[0].Value | Should Be 'BUILTIN\Administrators'
        $i.Get('trustee_domain')[0].Value | Should Be 'BUILTIN'
    }

    It 'sid resolves BUILTIN\Administrators to its SID' {
        (C 'oval:t:obj:admins_name').Items[0].Get('trustee_sid')[0].Value | Should Be 'S-1-5-32-544'
    }

    It 'user_object reports the current user as enabled' {
        (C 'oval:t:obj:me').Items[0].Get('enabled')[0].Value | Should Be '1'
    }

    It 'user_sid55 lists group SIDs' {
        @((C 'oval:t:obj:me_sid').Items[0].Get('group_sid')).Count | Should BeGreaterThan 0
    }

    It 'group_sid lists Administrators members as SIDs' {
        $sids = @((C 'oval:t:obj:admins_members').Items[0].Get('user_sid') | ForEach-Object { $_.Value })
        $sids.Count | Should BeGreaterThan 0
        $sids | Should Match '^S-1-'
    }

    It 'group_object lists members by name' {
        @((C 'oval:t:obj:admins_group').Items[0].Get('user')).Count | Should BeGreaterThan 0
    }

    It 'service wuauserv has a start_type' {
        (C 'oval:t:obj:wuauserv').Items[0].Get('start_type')[0].Value | Should Match '^SERVICE_'
    }

    It 'a missing service gives DoesNotExist' {
        (C 'oval:t:obj:noservice').Flag.ToString() | Should Be 'DoesNotExist'
    }
}

Describe 'Policy collectors needing elevation' -Tag Admin {
    $ctx = New-DefaultContext -Objects $objects
    function C($id) { [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject($id), $ctx) }

    It 'auditeventpolicysubcategories credential_validation matches auditpol' {
        $line = auditpol /get /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /r | ConvertFrom-Csv | Select-Object -First 1
        $map = @{ 'No Auditing' = 'AUDIT_NONE'; 'Success' = 'AUDIT_SUCCESS'; 'Failure' = 'AUDIT_FAILURE'; 'Success and Failure' = 'AUDIT_SUCCESS_FAILURE' }
        (C 'oval:t:obj:audit').Items[0].Get('credential_validation')[0].Value | Should Be $map[$line.'Inclusion Setting']
    }

    It 'accesstoken for Administrators holds SeDebugPrivilege' {
        (C 'oval:t:obj:token').Items[0].Get('sedebugprivilege')[0].Value | Should Be '1'
    }
}

Describe 'Policy collectors without elevation' {
    $isAdmin = ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $ctx = New-DefaultContext -Objects $objects

    It 'audit policy without privilege is an Error, not an exception' -Skip:$isAdmin {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:audit'), $ctx)
        $o.Flag.ToString() | Should Be 'Error'
    }
}
