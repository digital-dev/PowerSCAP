# Contributing

Pull requests are welcome. Useful contributions include:

- bug fixes;
- OVAL object types, or commands embedded in content, that the engine does not support yet;
- report and checklist fixes;
- parity reports from your own SCC comparisons.

1. Fork, and branch off `master`.
2. Read [`CODEBASE_MAP.md`](CODEBASE_MAP.md) first. It covers how a scan flows through the code and the rules a
   change has to keep: results match a validated scanner, findings follow the STIG, no script execution during
   scans, collectors never throw, read-only. It also explains why each rule exists.
3. Match the surrounding code's idiom and comment density. The engine is C# 5 compiled by `Add-Type`, so newer
   syntax will not compile. Keep C# string literals ASCII.
4. Add or update tests. Engine changes get a small hand-written fixture with a known answer in
   `tests/fixtures`, or an inline one in the test.
5. Run the suite under Windows PowerShell 5.1, and if you have it PowerShell 7, before opening the PR:
   ```powershell
   powershell -NoProfile -File build\Invoke-Tests.ps1 -ExcludeTag Admin,Slow,Online,Content
   powershell -NoProfile -File build\Invoke-Tests.ps1 -Edition Core -ExcludeTag Admin,Slow,Online,Content
   ```
   If you can, also run it elevated and with `tools\Get-TestContent.ps1` content, without the exclusions.
6. **Changing how a result is decided?** Passing the tests is not enough. Compare against SCC with
   `tools\Invoke-ParityRun.ps1` or `tools\Compare-XccdfResults.ps1`, and say in the PR which benchmarks, content
   versions and machine you compared. Add a row to [`docs/parity.md`](docs/parity.md) for any rule whose result
   changes.
7. Open the PR against `master` and explain what changed and why. Small, focused PRs are reviewed faster.

**Found a result that differs from SCC?** Open a
[Result differs from SCC](../../issues/new?template=parity_mismatch.yml) issue. Include the rule's finding
details from both tools (PowerSCAP's All-Settings report and SCC's) and whether both ran elevated on the same
machine state.

**Found another bug?** Use the [bug report template](../../issues/new/choose).

Do not attach SCAP results from systems you are not allowed to share. Results contain host names, IP and MAC
addresses, account names and configuration details. Trim or redact them first.

By taking part in this project you agree to follow its [Code of Conduct](CODE_OF_CONDUCT.md).
