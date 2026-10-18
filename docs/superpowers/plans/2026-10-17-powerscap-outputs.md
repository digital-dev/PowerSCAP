# PowerSCAP Plan 3: Outputs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every scan produces, per benchmark:
- SCC-style HTML All-Settings and Non-Compliance reports
- a STIG Viewer `.cklb` checklist
- XCCDF, OVAL results and ARF result XML

A combined summary page covers all benchmarks in the run.

**Architecture:**
- **Report model (C#):** `BenchmarkReport` is built once per scan from the content, profile, rule results, scores and target. It carries per-rule STIG metadata plus a text rendering of the OVAL evaluation ("finding details": tests, object and state requirements, collected items and their results).
- **Writers:** each output format reads only that model and is a pure writer. HTML is static and self-contained (inline CSS, a small inline script for filtering) and opens in the user's browser. Nothing is hosted in-process.

**Tech Stack:** C# 5 (`System.Xml`, `System.Web.Extensions` `JavaScriptSerializer`), PowerShell 5.1, Pester 3.4.

**Spec:** `docs/superpowers/specs/2026-10-16-powerscap-design.md` §6.5 (and §4 anti-goals: no browser engine in the scanner).

## Global Constraints

- Plan 1/2 Global Constraints hold (C# 5, PowerShell 5.1, no third-party code, no script execution during scans).
- **Reference outputs:** SCC 5.15 session `%USERPROFILE%\SCC\Sessions\2026-10-15_210812` (HTML and `.cklb` for the same benchmarks). Field names, status values and the finding-details layout follow it.
- **.cklb** (STIG Viewer 3 JSON, `cklb_version` `"1.0"`):
  - Top level: `title, id, active, mode, has_path, target_data{target_type "Computing", host_name, ip_address, mac_address, fqdn, role "Workstation", comments, ...}, stigs[], cklb_version`.
  - Per STIG: `stig_name, display_name, stig_id, release_info, version, uuid, reference_identifier, size, classification, rules[]`. Values come from the benchmark rear-matter (`title:--:`, `stigid:--:`, `releaseinfo:--:`, `version:--:`, `classification:--:`) and the rule's `reference`, which gives `dc:subject` (display_name) and `dc:identifier` (reference_identifier).
  - Per rule: `uuid, stig_uuid, group_id, group_id_src, rule_id (without _rule), rule_id_src, rule_version, rule_title, group_title, severity, weight, classification, discussion, false_positives, false_negatives, documentable, mitigations, potential_impacts, third_party_tools, mitigation_control, responsibility, security_override_guidance, ia_controls, check_content, check_content_ref{href,name}, fix_text, ccis[], legacy_ids[], group_tree[{id,title,description}], reference_identifier, status, finding_details, comments, overrides{}`.
  - Status mapping:

    | XCCDF result | `.cklb` status |
    |---|---|
    | pass | `not_a_finding` |
    | fail | `open` |
    | notapplicable | `not_applicable` |
    | everything else | `not_reviewed` |

- **Result source labels:** every result shown is labeled SCAP (layers 2/3 come in Plan 4).

## Review Focus

1. **Text from the content is untrusted:** rule titles, descriptions and collected values (registry data, file contents) must be HTML-encoded. *Test in Task 2:* a collected value of `<script>alert(1)</script>` appears escaped.
2. **Huge collected-item lists** (the .NET STIG collects 500+ files) must not make reports unusable. Show the first 50 items per test with a "+ N more" line. *Test in Task 1.*
3. **Rules without OVAL** (manual/OCIL, notchecked) still appear with their check text and status `not_reviewed`. *Test in Task 3.*
4. **Error/unknown results** carry the collector messages, so a reader knows why (e.g. "Access is denied"). *Test in Task 1.*
5. **Output names collide** when two runs land in the same second: the writer never overwrites; it uses the scan's own timestamp plus the benchmark short name, as XCCDF does. *Test in Task 5.*

---

### Task 1: Report model and finding details

**Files:** Create `src/PowerSCAP/Engine/Reports/ReportModel.cs`, `src/PowerSCAP/Engine/Reports/FindingDetails.cs`. Test: `tests/Reports.Model.Tests.ps1`.

**Interfaces:**
- Consumes: `ScapContent`, `ResolvedProfile`, `List<RuleResult>`, `List<Score>`, `TargetInfo` (Plan 1).
- Produces:
  - `class RuleReport { string GroupId /*V-…*/; string GroupTitle; string RuleId /*SV-…r…_rule*/; string StigId /*rule version*/; string Title; string Severity; string Cat /*"CAT I|II|III"*/; double Weight; string Discussion; string CheckText; string FixText; IList<string> Ccis; string DpmsTarget; string DpmsIdentifier; XccdfResult Result; string Source /*"SCAP"*/; string Details /*finding details text*/; string CheckHref; string CheckName; IDictionary<string,string> DescriptionTags /*FalsePositives, Documentable, ...*/; }`
  - `class BenchmarkReport { string BenchmarkId; string Title; string Version; string ReleaseInfo; string StigName; string StigId; string StigVersion; string Classification; string ProfileId; string ProfileTitle; DateTime Start; DateTime End; TargetInfo Target; List<Score> Scores; List<RuleReport> Rules; string ContentFile; static BenchmarkReport Build(ScapContent, ResolvedProfile, List<RuleResult>, List<Score>, TargetInfo, DateTime start, DateTime end); }`
  - `static class FindingDetails { string Render(RuleResult r, ScapContent c); }` produces SCC's layout: `Rule Result`, then per test the `Test ID / Result / Check Existence / Check`, `Object ID / Object Requirement` lines, `State ID / State Requirement` lines and `Collected Item/State Result` blocks with `entity equals 'value'` lines. Long item lists are capped at 50 with `… N more items`. Object and collector messages are included.
- [ ] Step 1: tests (fixture `mini-ds.xml` scanned with FakeCollector-free default context where possible; otherwise a hand-built `RuleResult`):
  - Build gives one `RuleReport` per selected rule.
  - `Discussion` is the text of `<VulnDiscussion>` decoded.
  - `Cat` maps high/medium/low → `CAT I/II/III`.
  - `Details` contains `Test ID`, the state requirement text and a collected value.
  - An error result's details contain the collector message.
  - 120 items render 50 plus `… 70 more items`.
- [ ] Step 2: run, expect FAIL. Step 3: implement. Step 4: run, PASS; full suite. Step 5: commit `feat: report model and finding details`.

### Task 2: HTML All-Settings and Non-Compliance

**Files:** Create `src/PowerSCAP/Engine/Reports/HtmlReport.cs`. Test: `tests/Reports.Html.Tests.ps1`.

**Interfaces:** `static class HtmlReport { void Write(BenchmarkReport r, string path, bool nonComplianceOnly); }`.
- Layout:
  1. **Header:** benchmark title, version, release info, profile, scan time, host.
  2. **Score tiles:** default score %, counts per result, CAT I/II/III open counts.
  3. **Target information:** host, FQDN, OS, addresses, identity, privileged.
  4. **Content information:** benchmark ID, file, signature.
  5. **Results table:** grouped by CAT I/II/III, sortable by result, with a text filter.
  6. **Per-rule detail:** a `<details>` block with discussion, check, fix, CCIs and finding details in `<pre>`.

  Non-Compliance shows only fail/error/unknown. Dark theme by default, light theme under `prefers-color-scheme: light`, and a toggle stored in `localStorage`.
- [ ] Tests:
  - All-Settings lists every rule; Non-Compliance lists only non-passing rules.
  - A `<script>` collected value is escaped.
  - The file is well-formed enough to parse as XML (`XmlDocument.LoadXml` on XHTML output).
- [ ] Commit `feat: HTML All-Settings and Non-Compliance reports`.

### Task 3: STIG Viewer checklist (.cklb)

**Files:** Create `src/PowerSCAP/Engine/Reports/CklbWriter.cs`. Test: `tests/Reports.Cklb.Tests.ps1`.

**Interfaces:** `static class CklbWriter { void Write(IList<BenchmarkReport> reports, string path); }` One file can hold several STIGs; the cmdlet writes one per benchmark, like SCC.
- [ ] Tests (Content tag, Edge benchmark):
  - The JSON has the reference top-level keys.
  - `stigs[0].stig_name` is `'Microsoft Edge Security Technical Implementation Guide'`, `stig_id` is `'MS_Edge_STIG'` and `release_info` is `'Release: 5 Benchmark Date: 01 Apr 2026'`.
  - `size` equals the rule count.
  - The rule for SV-235719 has `group_id` `'V-235719'`, `rule_id` `'SV-235719r1156558'`, `rule_version` `'EDGE-00-000001'`, `ccis` `@('CCI-001414')` and `reference_identifier` `'5280'`.
  - Statuses follow the mapping, and a manual rule is `not_reviewed`.
  - Every rule key of SCC's Edge `.cklb` is present in ours (compared key sets).
- [ ] Commit `feat: STIG Viewer .cklb checklists`.

### Task 4: OVAL results and ARF

**Files:** Create `src/PowerSCAP/Engine/Reports/OvalResultsWriter.cs`, `src/PowerSCAP/Engine/Reports/ArfWriter.cs`. Test: `tests/Reports.Xml.Tests.ps1`.

**Interfaces:**
- `static class OvalResultsWriter { XmlDocument Build(RuleResult[] results, ScapContent c); }` builds an OVAL 5.11 results document:
  - `generator` and `directives` (full results)
  - a copy of `oval_definitions`
  - `results/system`, with `definitions` (definition results), `tests` (`tested_item` entries) and `oval_system_characteristics`
  - the system characteristics hold `system_info`, `collected_objects` (`object` with `flag`, `reference item_ref`) and `system_data`. Items are written as `<{type} id status>` in the matching `-system-characteristics` namespace (windows or independent, chosen by item type), with entities as child elements carrying `datatype` and `status`. Record entities are written as `field` children.
- `static class ArfWriter { void Write(BenchmarkReport r, XmlDocument xccdfResults, XmlDocument ovalResults, string path); }` writes ARF 1.1: `asset-report-collection` with `report-requests` (the source data stream), `assets` (`ai:computing-device` with fqdn, hostname, IP and MAC) and `reports` (XCCDF TestResult, OVAL results), plus a `relationships` `isAbout` link to the asset.
- [ ] Tests:
  - The OVAL results file has one definition result per evaluated definition.
  - Every `tested_item/@item_id` exists in `system_data`.
  - The ARF has three report types/contents, and the XCCDF report inside ARF is the TestResult.
- [ ] Commit `feat: OVAL results and ARF output`.

### Task 5: Scan integration and summary

**Files:**
- Modify `src/PowerSCAP/Public/Invoke-PowerScapScan.ps1`.
- Create `src/PowerSCAP/Engine/Reports/SummaryReport.cs`.
- Test: `tests/Reports.Scan.Tests.ps1`.

**Interfaces:**
- `Invoke-PowerScapScan -Formats <string[]>` (default `Html,Cklb,Xccdf`; also `Oval,Arf,All`). Each format writes `<host>_<short>_<stamp>_<Kind>.<ext>`, where Kind is `All-Settings.html`, `Non-Compliance.html`, `Checklist.cklb`, `XCCDF-Results.xml`, `OVAL-Results.xml` or `ARF.xml`. `-PassThru` returns `Files`.
- `static class SummaryReport { void Write(IList<BenchmarkReport> reports, string path); }`. `Invoke-PowerScapScan` writes `<host>_<stamp>_Summary.html` once per call when more than one benchmark was scanned. It links each benchmark's reports and shows its score and open CAT I/II/III counts.
- [ ] Tests:
  - A scan of mini-ds writes the default files and the summary for two piped benchmarks.
  - `-Formats All` writes six files per benchmark.
  - A second scan within the same second does not overwrite the first (the name gets `_2`).
- [ ] Commit `feat: scans write HTML, .cklb, OVAL and ARF outputs`.
