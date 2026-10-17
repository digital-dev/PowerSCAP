$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$root = Join-Path $env:TEMP 'PowerSCAPFileTest'
function X([string]$s) { [System.Security.SecurityElement]::Escape($s) }

Describe 'File collectors' {
    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
    New-Item "$root\sub\deeper" -ItemType Directory -Force | Out-Null
    Set-Content "$root\settings.txt" -Value @('Setting=1', 'Other=2', 'Setting=3') -Encoding ASCII
    Set-Content "$root\app.exe.config" -Encoding ASCII -Value '<configuration><runtime><loadFromRemoteSources enabled="true"/></runtime></configuration>'
    Set-Content "$root\sub\deeper\b.exe.config" -Encoding ASCII -Value '<configuration/>'
    Set-Content "$root\hash.bin" -Value 'abc' -NoNewline -Encoding ASCII
    # A Windows servicing reverse delta, like WinSxS r-folder *.exe.config files: binary, not XML.
    [IO.File]::WriteAllBytes("$root\sub\delta.exe.config", [byte[]](0x2E, 0xD0, 0xD8, 0xA5, 0x50, 0x41, 0x33, 0x31, 0x01, 0x02))

    $r = X $root
    $rx = X ([regex]::Escape($root))
    $objects = @"
<win:file_object id="oval:t:obj:kernel32" version="1"><win:filepath>C:\Windows\System32\kernel32.dll</win:filepath></win:file_object>
<win:file_object id="oval:t:obj:missing" version="1"><win:filepath>$r\nope.txt</win:filepath></win:file_object>
<win:file_object id="oval:t:obj:configs" version="1"><win:behaviors recurse_direction="down" max_depth="-1"/><win:path>$r</win:path><win:filename operation="pattern match">\.exe\.config$</win:filename></win:file_object>
<win:file_object id="oval:t:obj:configs_pattern" version="1"><win:path operation="pattern match">^$rx(\\.*)?$</win:path><win:filename operation="pattern match">\.exe\.config$</win:filename></win:file_object>
<ind:textfilecontent54_object id="oval:t:obj:text" version="1"><ind:filepath>$r\settings.txt</ind:filepath><ind:pattern operation="pattern match">^Setting=(\d+)$</ind:pattern><ind:instance datatype="int" operation="greater than or equal">1</ind:instance></ind:textfilecontent54_object>
<ind:xmlfilecontent_object id="oval:t:obj:xml" version="1"><ind:filepath>$r\app.exe.config</ind:filepath><ind:xpath>/configuration/runtime/loadFromRemoteSources/@enabled</ind:xpath></ind:xmlfilecontent_object>
<ind:xmlfilecontent_object id="oval:t:obj:xmlall" version="1"><ind:behaviors recurse_direction="down" max_depth="-1"/><ind:path>$r</ind:path><ind:filename operation="pattern match">\.exe\.config$</ind:filename><ind:xpath>count(/configuration)</ind:xpath></ind:xmlfilecontent_object>
<ind:filehash58_object id="oval:t:obj:hash" version="1"><ind:filepath>$r\hash.bin</ind:filepath><ind:hash_type>SHA-256</ind:hash_type></ind:filehash58_object>
<win:wmi57_object id="oval:t:obj:wmi" version="1"><win:namespace>root\cimv2</win:namespace><win:wql>SELECT Caption FROM Win32_OperatingSystem</win:wql></win:wmi57_object>
"@
    $ctx = New-DefaultContext -Objects $objects
    function C($id) { [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject($id), $ctx) }

    It 'reads the file version of kernel32.dll' {
        $o = C 'oval:t:obj:kernel32'
        $o.Items.Count | Should Be 1
        $o.Items[0].Get('version')[0].Value | Should Match '^\d+\.\d+\.\d+\.\d+$'
        $o.Items[0].Get('version')[0].Datatype | Should Be 'version'
    }

    It 'a missing filepath gives DoesNotExist' {
        (C 'oval:t:obj:missing').Flag.ToString() | Should Be 'DoesNotExist'
    }

    It 'recurses down from a path to find files by pattern' {
        $names = @((C 'oval:t:obj:configs').Items | ForEach-Object { $_.Get('filename')[0].Value }) | Sort-Object
        $names -join ',' | Should Be 'app.exe.config,b.exe.config,delta.exe.config'
    }

    It 'matches directory paths by pattern' {
        (C 'oval:t:obj:configs_pattern').Items.Count | Should Be 3
    }

    It 'textfilecontent54 returns one item per match with subexpressions' {
        $o = C 'oval:t:obj:text'
        $o.Items.Count | Should Be 2
        ($o.Items | ForEach-Object { $_.Get('subexpression')[0].Value }) -join ',' | Should Be '1,3'
        ($o.Items | ForEach-Object { $_.Get('instance')[0].Value }) -join ',' | Should Be '1,2'
    }

    It 'xmlfilecontent evaluates the XPath' {
        (C 'oval:t:obj:xml').Items[0].Get('value_of')[0].Value | Should Be 'true'
    }

    It 'reads each directory once per scan, however many objects walk it' {
        $ctx2 = New-DefaultContext -Objects $objects
        [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx2.FindObject('oval:t:obj:configs'), $ctx2) | Out-Null
        $read = $ctx2.Collectors.Files.DirectoriesRead
        $read | Should Be 3
        [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx2.FindObject('oval:t:obj:xmlall'), $ctx2) | Out-Null
        $ctx2.Collectors.Files.DirectoriesRead | Should Be $read
    }

    It 'path .* with unlimited downward recursion walks each directory once' {
        # chain\a\b\c\d\e: recursing again from each of the 6 matched folders would list 6+5+4+3+2+1 = 21.
        $tree = Join-Path $root 'chain'
        New-Item (Join-Path $tree 'a\b\c\d\e') -ItemType Directory -Force | Out-Null
        Set-Content (Join-Path $tree 'a\b\c\d\e\x.exe.config') -Value '<configuration/>' -Encoding ASCII
        $o = '<win:file_object id="oval:t:obj:everywhere" version="1"><win:behaviors recurse_direction="down" max_depth="-1"/><win:path operation="pattern match">^' + (X ([regex]::Escape($tree))) + '.*</win:path><win:filename operation="pattern match">\.exe\.config$</win:filename></win:file_object>'
        $ctx2 = New-DefaultContext -Objects $o
        $r = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx2.FindObject('oval:t:obj:everywhere'), $ctx2)
        @($r.Items | ForEach-Object { $_.Get('filename')[0].Value }) -join ',' | Should Be 'x.exe.config'
        $walked = @(Get-ChildItem $root -Recurse -Directory).Count + 1
        # One parallel prefetch pass plus one walk over the tree, then 6 + 6 for the matched chain (not 21 + 6).
        $ctx2.Collectors.Files.Lookups | Should Not BeGreaterThan (2 * $walked + 6 + 6)
        Remove-Item $tree -Recurse -Force
    }

    It 'xmlfilecontent with an XPath that selects nothing is a does-not-exist item (as SCC reports it)' {
        $o = '<ind:xmlfilecontent_object id="oval:t:obj:noxpath" version="1"><ind:filepath>' + $r + '\app.exe.config</ind:filepath><ind:xpath>/configuration/system.net/defaultProxy/@enabled</ind:xpath></ind:xmlfilecontent_object>'
        $ctx2 = New-DefaultContext -Objects $o
        $res = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx2.FindObject('oval:t:obj:noxpath'), $ctx2)
        $res.Items.Count | Should Be 1
        $res.Items[0].Status.ToString() | Should Be 'DoesNotExist'
        $res.Items[0].Get('value_of')[0].Status.ToString() | Should Be 'DoesNotExist'
    }

    It 'xmlfilecontent skips files that are not XML (no item, object not in error)' {
        $o = C 'oval:t:obj:xmlall'
        $o.Flag.ToString() | Should Be 'Complete'
        @($o.Items | ForEach-Object { $_.Get('filename')[0].Value } | Sort-Object) -join ',' | Should Be 'app.exe.config,b.exe.config'
        ($o.Messages -join ' ') | Should Match 'delta\.exe\.config'
    }

    It 'filehash58 computes SHA-256' {
        (C 'oval:t:obj:hash').Items[0].Get('hash')[0].Value | Should Be 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    }

    It 'wmi57 returns a record with lower-case fields' {
        $o = C 'oval:t:obj:wmi'
        $o.Items.Count | Should Be 1
        $result = $o.Items[0].Get('result')[0]
        $result.Datatype | Should Be 'record'
        ($result.Fields | Where-Object { $_.Name -eq 'caption' }).Value | Should Match 'Windows'
    }

    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'File search over a whole drive' -Tag Slow {
    $ctx = New-DefaultContext -Objects '<win:file_object id="oval:t:obj:all" version="1"><win:behaviors max_depth="-1" recurse_direction="down"/><win:path>C:\</win:path><win:filename operation="pattern match">\.exe\.config$</win:filename></win:file_object>'

    It 'completes and reports unreadable directories as messages, not errors' {
        $o = [PowerScap.Engine.Oval.ObjectEvaluator]::Evaluate($ctx.FindObject('oval:t:obj:all'), $ctx)
        $o.Flag.ToString() | Should Not Be 'Error'
        $o.Items.Count | Should BeGreaterThan 0
    }
}
