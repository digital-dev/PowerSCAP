<#
.SYNOPSIS
    Downloads the NIWC enhanced SCAP 1.4 benchmarks matching SCC session 2026-10-15_210812, for parity tests.
.EXAMPLE
    .\tools\Get-TestContent.ps1
#>
param(
    [string]$Destination = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tests\content')
)

$base = 'https://raw.githubusercontent.com/niwc-atlantic/scap-content-library/refs/heads/main/Current/'
$files = @(
    'U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip'
    'U_MS_Edge_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip'
    'U_Google_Chrome_V2R11_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip'
    'U_MOZ_Firefox_Windows_V6R8_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip'
    'U_MS_Defender_Antivirus_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip'
    'U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip'
    'U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip'
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not (Test-Path -LiteralPath $Destination)) { New-Item -ItemType Directory -Path $Destination -Force | Out-Null }

foreach ($f in $files) {
    $target = Join-Path $Destination $f
    if (Test-Path -LiteralPath $target) { Write-Host "Present:    $f"; continue }
    Write-Host "Downloading $f"
    Invoke-WebRequest -Uri ($base + $f) -OutFile $target -UseBasicParsing -ErrorAction Stop
}
