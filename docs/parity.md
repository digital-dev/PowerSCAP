# Parity with SCC 5.15

Reference: SCC 5.15 session `2026-10-15_210812` on the reference machine (Windows 11 Pro 25H2), same NIWC enhanced
SCAP 1.4 content. PowerSCAP: elevated runs of all seven benchmarks on 2026-10-17 (three runs; identical
to each other rule for rule).

| Benchmark | Rules | Match | Differ |
|---|---:|---:|---:|
| Microsoft Windows 11 STIG | 257 | 256 | 1 |
| MS Edge STIG | 61 | 61 | 0 |
| Google Chrome | 46 | 46 | 0 |
| Mozilla Firefox (Windows) | 33 | 33 | 0 |
| MS Defender Antivirus | 67 | 67 | 0 |
| Windows Defender Firewall | 21 | 21 | 0 |
| MS .NET Framework 4 | 17 | 16 | 1 |
| **Total** | **502** | **500** | **2** |

First elevated run: 495 of 502 matched. After the fixes below, the elevated run of 2026-10-17 15:15 matched 500;
the remaining two are SV-253338 (machine change) and SV-225232 (fixed after that run; see below). The elevated
runs of 2026-10-17 22:03 confirm the SV-225232 fix: pass, as SCC reports it, so every remaining difference is a
machine change.

## Differences and verdicts

| Rule | SCC | PowerSCAP | Verdict |
|---|---|---|---|
| SV-253290 (orphaned SIDs in user rights) | pass | error | **PowerSCAP bug, fixed.** The object asks for every user right; LSA rejects `SeUnsolicitedInputPrivilege` (no longer defined by Windows) with STATUS_NO_SUCH_PRIVILEGE, which failed the whole object. Now treated as no holders. |
| SV-253311 (audit PnP activity) | pass | fail | **PowerSCAP bug, fixed.** Wrong OVAL entity names: `pnp_activity` (was `plug_and_play_events`) and `audit_detailedtracking_tokenrightadjusted`. |
| SV-253498 (impersonate a client) | pass | fail | **PowerSCAP bug, fixed.** Trustee names keep their domain unless it is BUILTIN, NT AUTHORITY or the local computer: `RESTRICTED SERVICES\PrintSpoolerService`. |
| SV-225232, SV-225234 (.NET config XPath) | pass | fail | **PowerSCAP bug, fixed.** An XPath that selects nothing gives a *does not exist* item (as SCC reports it), which states do not judge. |
| SV-225232 (second cause) | pass | fail | **Changed to follow the STIG.** The content excludes OS paths with one filter whose `path` uses a variable of three patterns (System32, Microsoft.NET, WinSxS) and the default `var_check="all"`; read strictly no path matches all three, nothing is excluded, and Windows' own caspol.exe.config fails the rule, though the STIG says caspol and OS assemblies do not apply. Filters now match a multi-value variable when any value does, unless the content sets `var_check`. |
| SV-253338 (Security log size) | fail | pass | **Machine change.** The 5 GB Security log size was applied after SCC's scan. Not a difference in evaluation. |
| SV-253476 (admin password age) | fail | notapplicable | **PowerSCAP changed to follow the STIG, now fail.** The STIG makes any enabled local administrator with a password older than 60 days a finding (the local administrator account here: 523 days). The content's filter `group = Administrators` uses the default `entity_check="all"`, which read strictly would drop a user who is also in other groups (`HOST\docker-users`) and hide the finding. Filters now match a multi-valued entity when any value does, unless the content sets `entity_check`, as SCC does. Test states keep the OVAL default. Owner's rule: results follow what NIST/STIG deem a finding. |

The SV-225232 filter change is confirmed by the elevated .NET run of 2026-10-17 22:03: pass, with no `.exe.config` file left
after the OS paths are excluded, the same evaluation SCC shows (definition true, no collected items). Unelevated rescans
of all seven benchmarks changed only the rules named here.
