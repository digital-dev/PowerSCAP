# PowerSCAP

Local SCAP compliance scanner for Windows, built with Windows PowerShell 5.1, embedded C# and WPF.
Design: `docs/superpowers/specs/2026-10-16-powerscap-design.md`.

## Content

PowerSCAP gets SCAP content from NIST's National Checklist Program and keeps it in a versioned local cache
(`%ProgramData%\PowerSCAP\content`, or `$env:POWERSCAP_CACHEDIR`). It prefers NIWC enhanced SCAP 1.4 content,
then DISA SCAP 1.3.

```powershell
Find-PowerScapBenchmark -MatchSystem | Save-PowerScapBenchmark    # download what this machine needs
Import-PowerScapBenchmark -Path .\U_Some_Benchmark.zip             # or add local content
Get-PowerScapBenchmark -Latest | Invoke-PowerScapScan -OutputPath .\results
Test-PowerScapBenchmarkUpdate                                      # newer releases on NCP?
```

- Updates never replace cached content; a new release is downloaded beside the old one.
- Listing and scanning cached content work offline.
- Every file's XML signature is checked. A file modified after signing is not scanned unless
  `-AllowInvalidSignature` is given, and that override is written into the results.
- Scans never start PowerShell or cmd: commands named in SCAP content are answered natively
  (`tools/Get-CommandInventory.ps1` lists any that are not).

## Running the tests

Tests use the Pester 3.4 that ships with Windows and always run under Windows PowerShell 5.1:

```powershell
powershell -NoProfile -File build\Invoke-Tests.ps1
```

Tags:
- `Admin`: needs an elevated session
- `Slow`: long-running file system or Windows Update searches
- `Online`: needs internet
- `Content`: needs real SCAP content (`tools\Get-TestContent.ps1`)

Exclude tags when needed, for example:

```powershell
powershell -NoProfile -File build\Invoke-Tests.ps1 -ExcludeTag Admin,Slow,Online,Content
```

The C# engine is compiled on first import and cached in `%LOCALAPPDATA%\PowerSCAP\bin`. Set `POWERSCAP_BINDIR` to use another folder.
