# Parity with SCC 5.15

Reference: SCC 5.15 session `2026-10-15_210812` on the reference machine (Windows 11 Pro 25H2), same NIWC enhanced
SCAP 1.4 content. PowerSCAP: elevated runs of all seven benchmarks on 2026-10-17 (three runs; identical
to each other rule for rule).

| Benchmark | Rules | Match | Differ |
|---|---:|---:|---:|
| Microsoft Windows 11 STIG | 257 | 252 | 5 |
| MS Edge STIG | 61 | 61 | 0 |
| Google Chrome | 46 | 46 | 0 |
| Mozilla Firefox (Windows) | 33 | 33 | 0 |
| MS Defender Antivirus | 67 | 67 | 0 |
| Windows Defender Firewall | 21 | 21 | 0 |
| MS .NET Framework 4 | 17 | 15 | 2 |
| **Total** | **502** | **495** | **7** |

## Differences and verdicts

| Rule | SCC | PowerSCAP | Verdict |
|---|---|---|---|
| SV-253290 (orphaned SIDs in user rights) | pass | error | **PowerSCAP bug, fixed.** The object asks for every user right; LSA rejects `SeUnsolicitedInputPrivilege` (no longer defined by Windows) with STATUS_NO_SUCH_PRIVILEGE, which failed the whole object. Now treated as no holders. |
| SV-253311 (audit PnP activity) | pass | fail | **PowerSCAP bug, fixed.** Wrong OVAL entity names: `pnp_activity` (was `plug_and_play_events`) and `audit_detailedtracking_tokenrightadjusted`. |
| SV-253498 (impersonate a client) | pass | fail | **PowerSCAP bug, fixed.** Trustee names keep their domain unless it is BUILTIN, NT AUTHORITY or the local computer: `RESTRICTED SERVICES\PrintSpoolerService`. |
| SV-225232, SV-225234 (.NET config XPath) | pass | fail | **PowerSCAP bug, fixed.** An XPath that selects nothing gives a *does not exist* item (as SCC reports it), which states do not judge. |
| SV-253338 (Security log size) | fail | pass | **Machine change.** The 5 GB Security log size was applied after SCC's scan. Not a difference in evaluation. |
| SV-253476 (admin password age) | fail | notapplicable | **SCC departs from OVAL 5.11.** The filter state `group = Administrators` has the default `entity_check="all"`; the account's groups are `Administrators` and `HOST\docker-users`, so by the specification it does not match and the platform `local_enabled_administrators` is false. SCC includes the account (treats the filter as "at least one"). Open: owner to decide whether PowerSCAP follows the specification or SCC here. |

The five fixes still need confirming by an elevated run (they touch admin-only collection).
