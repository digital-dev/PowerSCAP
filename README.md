# PowerSCAP

Local SCAP compliance scanner for Windows, built with Windows PowerShell 5.1, embedded C# and WPF.
Design: `docs/superpowers/specs/2026-10-16-powerscap-design.md`.

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
