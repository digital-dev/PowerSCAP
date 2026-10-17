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
