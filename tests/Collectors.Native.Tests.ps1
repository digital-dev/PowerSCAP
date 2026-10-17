$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# A shellcommand context whose collector uses a scripted runner instead of NativeShell.
function New-ShellContext([string]$Objects, [scriptblock]$Runner) {
    $doc = New-OvalDocument -Objects $Objects
    $reg = New-Object PowerScap.Engine.Oval.CollectorRegistry
    $reg.Register((New-Object PowerScap.Engine.Oval.ShellCommandCollector([PowerScap.Engine.Oval.CommandRunner]$Runner)))
    $ctx = New-Object PowerScap.Engine.Oval.OvalContext($doc, $reg)
    $ctx.Variables = New-Object PowerScap.Engine.Oval.VariableResolver($ctx, $null)
    $ctx
}

function New-Output([string[]]$Stdout = @(), [string[]]$Stderr = @(), [string]$Exit = $null) {
    $o = New-Object PowerScap.Engine.Oval.CommandOutput
    $o.Handled = $true
    $o.ExitStatus = $Exit
    foreach ($l in $Stdout) { $o.Stdout.Add($l) }
    foreach ($l in $Stderr) { $o.Stderr.Add($l) }
    $o
}

function Invoke-Native([string]$Shell, [string]$Command) { [PowerScap.Engine.Oval.NativeShell]::Run($Shell, $Command) }

function Get-Collected($ctx, $id) { [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject($id), $ctx) }

Describe 'shellcommand_object items' {
    $obj = '<ind:shellcommand_object id="oval:t:obj:s" version="1"><ind:shell>powershell</ind:shell><ind:command>x</ind:command><ind:pattern>Alpha - (\d+):</ind:pattern></ind:shellcommand_object>'

    It 'yields one item per command with one stdout_line and subexpression per matching line' {
        $ctx = New-ShellContext $obj { param($s, $c) New-Output -Stdout 'Alpha - 1:', 'Beta - 2:', 'Alpha - 3:' -Exit '0' }
        $o = Get-Collected $ctx 'oval:t:obj:s'
        $o.Items.Count | Should Be 1
        @($o.Items[0].Get('stdout_line')).Count | Should Be 2
        ($o.Items[0].Get('subexpression') | ForEach-Object { $_.Value }) -join ',' | Should Be '1,3'
        $o.Items[0].Get('exit_status')[0].Value | Should Be '0'
    }

    It 'still yields the item when no line matches' {
        $ctx = New-ShellContext $obj { param($s, $c) New-Output -Stdout 'nothing' }
        $o = Get-Collected $ctx 'oval:t:obj:s'
        $o.Items.Count | Should Be 1
        @($o.Items[0].Get('stdout_line')).Count | Should Be 0
    }

    It 'reports an empty exit_status when no program ran, and stderr lines' {
        $ctx = New-ShellContext $obj { param($s, $c) New-Output -Stderr 'boom' }
        $item = (Get-Collected $ctx 'oval:t:obj:s').Items[0]
        $item.Get('exit_status')[0].Value | Should Be ''
        $item.Get('stderr_line')[0].Value | Should Be 'boom'
    }

    It 'keeps blank lines that match the pattern' {
        $all = '<ind:shellcommand_object id="oval:t:obj:all" version="1"><ind:shell>powershell</ind:shell><ind:command>x</ind:command><ind:pattern>.*</ind:pattern></ind:shellcommand_object>'
        $ctx = New-ShellContext $all { param($s, $c) New-Output -Stdout 'A:', '', 'B:' }
        @((Get-Collected $ctx 'oval:t:obj:all').Items[0].Get('stdout_line')).Count | Should Be 3
    }

    It 'marks the object not collected when the command has no native implementation' {
        $ctx = New-ShellContext $obj { param($s, $c) [PowerScap.Engine.Oval.CommandOutput]::Unhandled('no') }
        $o = Get-Collected $ctx 'oval:t:obj:s'
        $o.Flag.ToString() | Should Be 'NotCollected'
        $o.Items.Count | Should Be 0
    }
}

Describe 'NativeShell never runs scripts' {
    It 'does not run cmd builtins or operators' {
        [PowerScap.Engine.Oval.NativeShell]::IsSupported('cmd', 'echo hi') | Should Be $false
        [PowerScap.Engine.Oval.NativeShell]::IsSupported('cmd', 'hostname & whoami') | Should Be $false
    }

    It 'does not run arbitrary PowerShell' {
        [PowerScap.Engine.Oval.NativeShell]::IsSupported('powershell', '"pid=$PID"') | Should Be $false
        [PowerScap.Engine.Oval.NativeShell]::IsSupported('powershell', 'Get-Process | Stop-Process') | Should Be $false
        [PowerScap.Engine.Oval.NativeShell]::IsSupported('powershell', 'sort /?') | Should Be $false # alias for Sort-Object
        (Invoke-Native 'powershell' 'Write-Output hi').Handled | Should Be $false
    }

    It 'runs a plain program directly, with its exit code' {
        $o = Invoke-Native 'cmd' 'hostname'
        $o.Handled | Should Be $true
        $o.Stdout[0] | Should Be ([System.Net.Dns]::GetHostName())
        $o.ExitStatus | Should Be '0'
    }

    It 'runs a System32 program named in PowerShell content directly' {
        $o = Invoke-Native 'powershell' 'hostname'
        $o.Stdout[0] | Should Be ([System.Net.Dns]::GetHostName())
    }

    It 'icacls($env:windir) lists the Windows directory ACL' {
        $o = Invoke-Native 'powershell' 'icacls($env:windir)'
        $o.ExitStatus | Should Be '0'
        $o.Stdout[0] | Should Match ('^' + [regex]::Escape($env:windir) + ' ')
        @($o.Stdout | Where-Object { $_ -match 'NT AUTHORITY\\SYSTEM:' }).Count -gt 0 | Should Be $true
    }
}

Describe 'Native PowerShell snippets match PowerShell' {
    It 'registry ACL dump matches the content''s expected line format' {
        $cmd = '([Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("Software", [System.Security.AccessControl.RegistryRights]::ReadPermissions)).GetAccessControl().Access | Where-Object { $_.RegistryRights -notmatch ''\d+'' } | ForEach-Object { "Identity:$($_.IdentityReference), Rights: $($_.RegistryRights), Access: $($_.AccessControlType), IsInherited: $($_.IsInherited), InheritanceFlags: $($_.InheritanceFlags), PropagationFlags: $($_.PropagationFlags)" }'
        $o = Invoke-Native 'powershell' $cmd
        $o.Handled | Should Be $true
        $o.Stdout -contains 'Identity:NT AUTHORITY\SYSTEM, Rights: FullControl, Access: Allow, IsInherited: False, InheritanceFlags: ContainerInherit, PropagationFlags: None' | Should Be $true
        @($o.Stdout | Where-Object { $_ -match 'Rights: [^,]*\d' }).Count | Should Be 0
    }

    It 'Get-Service renders the 5.1 table exactly' {
        $svc = Get-Service | Where-Object { $_.Name.Length -gt 18 } | Select-Object -First 1
        $expected = @(Get-Service -Name $svc.Name | Out-String -Stream -Width 4096)
        $o = Invoke-Native 'powershell' "Get-Service -name $($svc.Name)"
        ($o.Stdout -join '|') | Should Be ($expected -join '|')
    }

    It 'Get-Service for a missing service writes an error' {
        $o = Invoke-Native 'powershell' 'Get-Service -name NoSuchServicePowerSCAP'
        $o.Stdout.Count | Should Be 0
        $o.Stderr[0] | Should Match 'Cannot find any service'
    }

    It 'Get-PnpDevice class lines match the cmdlet' {
        $expected = @(Get-PnpDevice -Class System -Status OK -ErrorAction SilentlyContinue).Count
        $o = Invoke-Native 'powershell' '(Get-PnpDevice -class System -status OK).class'
        $o.Stdout.Count | Should Be $expected
        @($o.Stdout | Sort-Object -Unique) -join ',' | Should Be 'System'
    }

    It 'get-winevent returns the newest events with their message first lines' {
        $expected = @(Get-WinEvent -LogName Application -MaxEvents 3)
        $o = Invoke-Native 'powershell' 'get-winevent -logname Application -MaxEvents 3'
        $rows = @($o.Stdout | Where-Object { $_ -match '^\S.*\s\d+ \S' -and $_ -notmatch '^(TimeCreated|-----)' })
        $rows.Count | Should Be 3
        for ($i = 0; $i -lt 3; $i++) {
            $first = ("$($expected[$i].Message)" -split "`r?`n")[0]
            $rows[$i].EndsWith($first) -or $rows[$i].EndsWith($first + '...') | Should Be $true
        }
    }

    It 'get-winevent on a missing log writes the cmdlet error' {
        $o = Invoke-Native 'powershell' 'get-winevent -logname NoSuchLogPowerSCAP -MaxEvents 5'
        $o.Stderr[0] | Should Be 'get-winevent : There is not an event log on the localhost computer that matches "NoSuchLogPowerSCAP".'
        $o.ExitStatus | Should Be $null
    }

    It 'Get-AppxPackage name filter finds installed packages' {
        $mine = Get-AppxPackage | Select-Object -First 1
        $o = Invoke-Native 'powershell' "Get-AppxPackage -AllUsers | Where-Object { `$_.Name -like '*$($mine.Name)*' }"
        @($o.Stdout | Where-Object { $_ -match "^Name\s+: $([regex]::Escape($mine.Name))$" }).Count -gt 0 | Should Be $true
        (Invoke-Native 'powershell' "Get-AppxPackage -AllUsers | Where-Object { `$_.Name -like '*NoSuchPackagePowerSCAP*' }").Stdout.Count | Should Be 0
    }

    It 'Confirm-SecureBootUEFI prints True/False, or the cmdlet error without the privilege' {
        $o = Invoke-Native 'powershell' 'Confirm-SecureBootUEFI'
        (@($o.Stdout) + @($o.Stderr)) -join '' | Should Match '^(True|False|Confirm-SecureBootUEFI : .*)$'
    }
}

Describe 'Confirm-SecureBootUEFI elevated' -Tag Admin {
    It 'matches the cmdlet' {
        (Invoke-Native 'powershell' 'Confirm-SecureBootUEFI').Stdout[0] | Should Be "$(Confirm-SecureBootUEFI)"
    }
}

Describe 'Native cmdlets match PowerShell' {
    function Invoke-Cmdlet($verb, $noun, [hashtable]$params, [string[]]$props) {
        $d = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($k in $params.Keys) { $d[$k] = $params[$k] }
        [PowerScap.Engine.Oval.NativeCmdlets]::Invoke($verb, $noun, $d, [System.Collections.Generic.List[string]]$props)
    }
    function Rows($output, [string[]]$props) {
        @($output.Objects | ForEach-Object { $o = $_; ($props | ForEach-Object { [PowerScap.Engine.Oval.NativeCmdlets]::Format($o.Values[$_]) }) -join '|' })
    }

    It 'formats values as SCC reports them' {
        [PowerScap.Engine.Oval.NativeCmdlets]::Format([uint32[]](2, 7)) | Should Be '{2,7}'
        [PowerScap.Engine.Oval.NativeCmdlets]::Format($true) | Should Be 'True'
        [PowerScap.Engine.Oval.NativeCmdlets]::Format($null) | Should Be ''
        [PowerScap.Engine.Oval.NativeCmdlets]::Format(393472) | Should Be '393472'
    }

    It 'Get-ChildItem Cert:\LocalMachine\Root matches the certificate provider' {
        $props = 'Issuer', 'Thumbprint'
        $native = Rows (Invoke-Cmdlet Get ChildItem @{ path = 'Cert:\LocalMachine\Root' } $props) $props | Sort-Object
        $real = @(Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object { "$($_.Issuer)|$($_.Thumbprint)" }) | Sort-Object
        $native -join "`n" | Should Be ($real -join "`n")
    }

    It 'Get-CimInstance with class and filter matches the cmdlet' {
        $props = 'Name', 'PasswordExpires', 'Disabled', 'LocalAccount'
        $filter = 'LocalAccount=True'
        $native = Rows (Invoke-Cmdlet Get CimInstance @{ class = 'Win32_UserAccount'; filter = $filter } $props) $props | Sort-Object
        $real = @(Get-CimInstance -ClassName Win32_UserAccount -Filter $filter | ForEach-Object { "$($_.Name)|$($_.PasswordExpires)|$($_.Disabled)|$($_.LocalAccount)" }) | Sort-Object
        $native -join "`n" | Should Be ($real -join "`n")
    }

    It 'Get-NetFirewallProfile -PolicyStore ActiveStore matches the cmdlet' {
        $props = 'Name', 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction', 'LogFileName', 'LogBlocked', 'LogMaxSizeKilobytes', 'AllowLocalFirewallRules', 'NotifyOnListen'
        $native = Rows (Invoke-Cmdlet Get NetFirewallProfile @{ policystore = 'ActiveStore' } $props) $props
        $real = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { $p = $_; ($props | ForEach-Object { "$($p.$_)" }) -join '|' })
        $native -join "`n" | Should Be ($real -join "`n")
    }

    It 'Get-ComputerInfo BiosFirmwareType matches the cmdlet' {
        $native = @(Rows (Invoke-Cmdlet Get ComputerInfo @{} @('biosfirmwaretype')) @('biosfirmwaretype'))
        $native[0] | Should Be "$((Get-ComputerInfo -Property BiosFirmwareType).BiosFirmwareType)"
    }

    It 'reports module identity from the module manifest' {
        $m = [PowerScap.Engine.Oval.NativeCmdlets]::ModuleOf('Get', 'Tpm')
        $m.Name | Should Be 'TrustedPlatformModule'
        $m.Id | Should Be '{17fc1f02-cff3-45fb-ac4f-126594c70b1e}'
        $m.Version | Should Be '2.0.0.0'
    }

    It 'does not support unknown cmdlets or parameters' {
        [PowerScap.Engine.Oval.NativeCmdlets]::IsSupported('Get', 'Item', (New-Object 'System.Collections.Generic.Dictionary[string,string]'), $null) | Should Be $false
        $d = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
        $d['computername'] = 'x'
        [PowerScap.Engine.Oval.NativeCmdlets]::IsSupported('Get', 'Tpm', $d, $null) | Should Be $false
    }
}

Describe 'Get-Tpm elevated' -Tag Admin {
    It 'matches the cmdlet' {
        $d = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $props = [System.Collections.Generic.List[string]]@('TpmPresent', 'TpmReady', 'TpmEnabled')
        $o = [PowerScap.Engine.Oval.NativeCmdlets]::Invoke('Get', 'Tpm', $d, $props).Objects[0]
        $t = Get-Tpm
        ($props | ForEach-Object { [PowerScap.Engine.Oval.NativeCmdlets]::Format($o.Values[$_]) }) -join '|' | Should Be "$($t.TpmPresent)|$($t.TpmReady)|$($t.TpmEnabled)"
    }
}
