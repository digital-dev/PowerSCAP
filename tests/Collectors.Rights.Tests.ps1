$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$objects = @'
<win:fileeffectiverights53_object id="oval:t:obj:fer" version="1"><win:path>C:\Windows</win:path><win:filename xsi:nil="true"/><win:trustee_sid>S-1-5-32-544</win:trustee_sid></win:fileeffectiverights53_object>
<win:fileeffectiverights53_object id="oval:t:obj:fer_all" version="1"><win:path>C:\Windows</win:path><win:filename xsi:nil="true"/><win:trustee_sid operation="pattern match">.*</win:trustee_sid></win:fileeffectiverights53_object>
<win:regkeyeffectiverights53_object id="oval:t:obj:rer" version="1"><win:hive>HKEY_LOCAL_MACHINE</win:hive><win:key>SOFTWARE\Microsoft\Windows NT\CurrentVersion</win:key><win:trustee_sid>S-1-5-32-545</win:trustee_sid></win:regkeyeffectiverights53_object>
<win:sharedresource_object id="oval:t:obj:ipc" version="1"><win:netname>IPC$</win:netname></win:sharedresource_object>
<win:wuaupdatesearcher_object id="oval:t:obj:wua" version="1"><win:search_criteria>IsInstalled=1</win:search_criteria></win:wuaupdatesearcher_object>
'@

Describe 'Effective rights and share collectors' {
    $ctx = New-DefaultContext -Objects $objects
    function C($id) { [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject($id), $ctx) }

    It 'Administrators can read data in C:\Windows' {
        $o = C 'oval:t:obj:fer'
        $o.Items.Count | Should Be 1
        $o.Items[0].Get('file_read_data')[0].Value | Should Be '1'
        $o.Items[0].Get('trustee_sid')[0].Value | Should Be 'S-1-5-32-544'
    }

    It 'a trustee pattern enumerates the trustees in the DACL' {
        $sids = @((C 'oval:t:obj:fer_all').Items | ForEach-Object { $_.Get('trustee_sid')[0].Value })
        $sids -contains 'S-1-5-32-544' | Should Be $true
        $sids -contains 'S-1-5-32-545' | Should Be $true
    }

    It 'Users can query values of HKLM\...\CurrentVersion but not set them' {
        $i = (C 'oval:t:obj:rer').Items[0]
        $i.Get('key_query_value')[0].Value | Should Be '1'
        $i.Get('key_set_value')[0].Value | Should Be '0'
    }

    $serverRunning = (Get-Service LanmanServer).Status -eq 'Running'

    It 'shares include IPC$ when the Server service runs' -Skip:(-not $serverRunning) {
        (C 'oval:t:obj:ipc').Items[0].Get('netname')[0].Value | Should Be 'IPC$'
    }

    It 'no shares exist when the Server service is stopped' -Skip:$serverRunning {
        (C 'oval:t:obj:ipc').Flag.ToString() | Should Be 'DoesNotExist'
    }
}

Describe 'Windows Update search' -Tag Slow, Online {
    $ctx = New-DefaultContext -Objects $objects

    It 'WUA search for installed updates returns update ids' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:wua'), $ctx)
        @($o.Items[0].Get('update_id')).Count | Should BeGreaterThan 0
    }
}
