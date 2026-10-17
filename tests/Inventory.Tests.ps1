$repo = Split-Path $PSScriptRoot -Parent
$tool = Join-Path $repo 'tools\Get-OvalInventory.ps1'
$content = Join-Path $PSScriptRoot 'content'

Describe 'Content inventory gate' -Tag Content {
    It 'supports every OVAL object type used by the test content' {
        Test-Path $content | Should Be $true
        $unsupported = @(& $tool -Path $content | Where-Object { -not $_.Supported } | ForEach-Object { $_.ObjectType })
        $unsupported -join ', ' | Should Be ''
    }
}

Describe 'Command inventory gate' -Tag Content {
    It 'implements every shell command and cmdlet in the test content natively (no script execution)' {
        $unsupported = @(& (Join-Path $repo 'tools\Get-CommandInventory.ps1') -Path $content | Where-Object { -not $_.Supported } |
            ForEach-Object { "$($_.Kind) $($_.Command)" } | Sort-Object -Unique)
        $unsupported -join "`n" | Should Be ''
    }
}
