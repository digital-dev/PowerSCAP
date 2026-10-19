# Parity with SCC 5.15

## Paired run, 2026-10-18 (same machine state)

SCC 5.15 (`cscc.exe`) and PowerSCAP scanned the reference machine (Windows 11 Pro 25H2) back to back, both elevated,
with the same NIWC enhanced SCAP 1.4 content versions and profile (MAC-1 Classified), using
`tools\Invoke-ParityRun.ps1 -RunScc`. Every rule result and all four XCCDF scores (default, flat, flat-unweighted,
absolute) were compared.

| Benchmark | Version | Rules | Match | Scores |
|---|---|---:|---:|---|
| Google Chrome | 002.011.016 | 46 | 46 | identical |
| Mozilla Firefox (Windows) | 006.008.013 | 33 | 33 | identical |
| MS Defender Antivirus | 002.009.015 | 67 | 67 | identical |
| MS .NET Framework 4 | 002.008.015 | 17 | 17 | identical |
| MS Edge STIG | 002.005.016 | 61 | 61 | identical |
| Windows Defender Firewall | 002.003.014 | 21 | 21 | identical |
| **Total** | | **245** | **245** | |

The matched results cover every result kind present: 124 pass, 106 fail, 12 not checked, 3 error.

**Microsoft Windows 11 STIG could not be paired:** SCC crashed on all three attempts (access violation `0xC0000005`,
and `0xC0000028`), writing no results. SCC was unstable throughout on this machine: it also crashed on first attempts at
Firefox and .NET, and its Perl XML engine reported uninitialized values. PowerSCAP scanned all seven benchmarks without
a failure. The Windows 11 comparison below uses SCC's last complete Windows 11 run.

## Unpaired comparison (SCC session of 2026-10-15)

Reference: SCC 5.15 session `2026-10-15_210812`, same content. PowerSCAP: the elevated run of all seven benchmarks
on 2026-10-17 22:03.

| Benchmark | Rules | Match | Differ |
|---|---:|---:|---:|
| Microsoft Windows 11 STIG | 257 | 255 | 2 |
| MS Edge STIG | 61 | 61 | 0 |
| Google Chrome | 46 | 46 | 0 |
| Mozilla Firefox (Windows) | 33 | 33 | 0 |
| MS Defender Antivirus | 67 | 67 | 0 |
| Windows Defender Firewall | 21 | 21 | 0 |
| MS .NET Framework 4 | 17 | 17 | 0 |
| **Total** | **502** | **500** | **2** |

**Both differences are machine changes between the two scans, not differences in evaluation.** With the collected
values each tool saw, both tools give the same result (SV-253264, SV-253338 below).

History: the first elevated run matched 495 of 502. The fixes below brought it to 500. The SV-225232 filter change,
made after the 15:15 run, is confirmed by the 22:03 run: pass, the same evaluation SCC shows (definition true,
no collected items once Windows' own paths are excluded).

## Benchmarks SCC scanned that the paired run did not compare

| Benchmark | SCC | PowerSCAP |
|---|---|---|
| Windows Updates 001.001 (bundled with SCC, not on NCP) | **error**: SCC's Perl downloader could not reach microsoft.com (the outbound firewall blocks it) and it found no offline `wsusscn2.cab` | **pass**: Windows Update, queried through its own API, reports no missing operating system updates |
| Microsoft OneDrive 002.004.012 | applicability check only (OneDrive applies); SCC crashed before writing rule results | 12 rules: 11 open (the OneDrive and Internet zone Group Policy settings are not configured on this unmanaged machine), 1 pass (supported version) |

Neither is a parity result. Two PowerSCAP fixes came out of them:

- **Windows Updates was a false fail.** The content uses OVAL 5.12's `wuaupdatesearcher_item`: one item per update,
  with `is_installed` and `days_since_source_modified`. PowerSCAP built the 5.11 item (one item holding every update
  id), which a state on `is_installed` can only fail. It now builds 5.12 items, so a search that finds no missing
  update collects nothing and the rule passes.
- **OneDrive was all errors.** NIWC's data stream writes two of its catalog entries without the catalog namespace;
  one of them is the content's only link to its OVAL. SCC follows them, and PowerSCAP now does too.

## Differences and verdicts

| Rule | SCC | PowerSCAP | Verdict |
|---|---|---|---|
| SV-253290 (orphaned SIDs in user rights) | pass | error | **PowerSCAP bug, fixed.** The object asks for every user right; LSA rejects `SeUnsolicitedInputPrivilege` (no longer defined by Windows) with STATUS_NO_SUCH_PRIVILEGE, which failed the whole object. Now treated as no holders. |
| SV-253311 (audit PnP activity) | pass | fail | **PowerSCAP bug, fixed.** Wrong OVAL entity names: `pnp_activity` (was `plug_and_play_events`) and `audit_detailedtracking_tokenrightadjusted`. |
| SV-253498 (impersonate a client) | pass | fail | **PowerSCAP bug, fixed.** Trustee names keep their domain unless it is BUILTIN, NT AUTHORITY or the local computer: `RESTRICTED SERVICES\PrintSpoolerService`. |
| SV-225232, SV-225234 (.NET config XPath) | pass | fail | **PowerSCAP bug, fixed.** An XPath that selects nothing gives a *does not exist* item (as SCC reports it), which states do not judge. |
| SV-225232 (second cause) | pass | fail | **Changed to follow the STIG.** The content excludes OS paths with one filter whose `path` uses a variable of three patterns (System32, Microsoft.NET, WinSxS) and the default `var_check="all"`; read strictly no path matches all three, nothing is excluded, and Windows' own caspol.exe.config fails the rule, though the STIG says caspol and OS assemblies do not apply. Filters now match a multi-value variable when any value does, unless the content sets `var_check`. |
| SV-253338 (Security log size) | fail | pass | **Machine change.** The 5 GB Security log size was applied after SCC's scan. Not a difference in evaluation. |
| SV-253264 (antivirus in use) | fail | pass | **Machine change.** The rule requires a Security Center antivirus product whose `productState` has bit 4096 (running) set. SCC collected Avast with `270336` (bit clear); PowerSCAP collected `266240` (bit set). Same check, different machine state. |
| SV-253476 (admin password age) | fail | notapplicable | **PowerSCAP changed to follow the STIG, now fail.** The STIG makes any enabled local administrator with a password older than 60 days a finding (the local administrator account here: 523 days). The content's filter `group = Administrators` uses the default `entity_check="all"`, which read strictly would drop a user who is also in other groups (`HOST\docker-users`) and hide the finding. Filters now match a multi-valued entity when any value does, unless the content sets `entity_check`, as SCC does. Test states keep the OVAL default. Owner's rule: results follow what NIST/STIG deem a finding. |

Unelevated rescans of all seven benchmarks changed only the rules named here.
