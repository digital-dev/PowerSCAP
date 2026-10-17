# PowerSCAP — Design

Date: 2026-10-16 · Status: draft for review

## 1. Intent and why

PowerSCAP is a local SCAP compliance scanner for Windows. It is built only with PowerShell, embedded C# (compiled at run time with `Add-Type`) and a WPF/XAML desktop GUI.

Why: the owner's current tool, DISA/NIWC SCAP Compliance Checker (SCC) 5.15, crashes repeatedly on their workstation (Windows 11 Pro 25H2). Crash dumps show memory corruption inside SCC's bundled Perl runtime (`perl538.dll`). The crashes repeat at identical code addresses and happen within seconds of starting a scan. SCC's GUI also loads a web-view component, which pulls the system AMSI provider (Avast's `aswAMSI.dll`) into the process. The owner wants a scanner they control that gives the same answers.

The guiding principle, in the owner's words: **SCAP is a framework, black and white. Results must always match 1:1 what any other SCAP scan would return.** A second principle: **remove human error anywhere possible.** Automate everything that can be automated, and ask a person only when no script can decide.

## 2. Goals

1. **Exact SCAP parity.** For the same SCAP content and the same machine state, every XCCDF rule result (pass / fail / error / unknown / notapplicable / notchecked / notselected / informational) and every standard XCCDF score is identical to what a SCAP-validated scanner (SCC) produces.
2. **Automatic content.** The tool profiles the local system, finds the matching benchmarks in NIST's National Checklist Program (NCP), downloads them into a local cache, and detects when newer releases are published.
3. **Three result layers, never mixed** (§6):
   - SCAP results
   - automated manual checks
   - guided human answers
4. **SCC-equivalent outputs:**
   - HTML All-Settings and Non-Compliance reports
   - standard machine-readable result files
   - a STIG Viewer checklist
5. **A full desktop GUI with good UX:** low clutter, and not a console script.

## 3. Non-goals (this project)

- **Remediation** of any kind. The owner already has documented ways to apply STIGs (LGPO/GPO baselines). Remediation may become a separate later project.
- **Remote scanning** of other machines. Local only for now; don't block a later remote mode, but don't build it.
- **Non-Windows targets** (Linux, network devices).
- **Formal NIST SCAP validation.** Parity is proven by our own test harness, not by certification.

## 4. Anti-goals (failure even if it "works")

- A SCAP result or score that differs from a validated scanner's for the same content and state.
- Non-SCAP results (script checks, human answers) changing the SCAP score, or being shown without a clear label of where they came from.
- A crashing or freezing UI. Scans must not block the UI thread.
- Loading browser engines or script hosts into the scanner process (WebBrowser/IE/mshtml, WebView2, JScript/VBScript, AMSI-triggering hosts). That is what pulled antivirus hooks into SCC. HTML reports open in the user's default browser instead.
- Needing internet access to scan. Cached content must scan fully offline.

## 5. Constraints

- **Languages/runtime:** PowerShell with embedded C# only. No third-party binaries, NuGet packages or external tools (no oscap, no Perl). Only .NET and Windows built-ins.
- **Target runtime ★: Windows PowerShell 5.1 on .NET Framework 4.x**, because it is native to every default Windows install, including locked-down machines where PowerShell 7 is not allowed.
  - Embedded C# is compiled by `Add-Type`, which uses the in-box CodeDom compiler and limits code to **C# 5 language features** (no string interpolation, `?.`, tuples, or expression-bodied members).
  - WPF and `System.Xml` come from .NET Framework.
  - Running under PowerShell 7 is a nice-to-have, not a requirement.
- **Privileges:** runs elevated. Many checks need administrator rights (security policy, audit policy, user rights, BitLocker, SAM, protected registry keys).
- **Platform:** Windows 11 is the primary target. Windows 10 and Server 2016+ should work where the content applies.
- **Machine context:** the owner's PC runs Avast as its antivirus (Defender passive), has a default-outbound-Block firewall, VMware Workstation, and VBS/HVCI. The tool must not depend on Defender being active, and must handle "access denied" from security software as a reported error, never a crash.

## 6. How it works (owner's decisions marked ★)

### 6.1 Content: NCP, cache, updates ★
- **Source:** the NCP public JSON API (verified 2026-10-16; no authentication; works from PowerShell):
  - `GET https://ncp.nist.gov/public/service/rest/json/ncp/checklist/repository/metadata` returns checklist types, authorities, targets and content types.
  - `GET .../search/results?offset=&rowCount=&checklistTypeId=&authorityIdList=&targetId=&contentTypeIdList=&keyword=&sortOrder=&sortDirection=` returns checklists, each with `checklistId`, `name`, `version`, `lastModified`, `targets[]` and `resources[]`. Each resource has a `title`, a `location` (download URL) and a `resourceTypeName`.
  - Content types of interest: SCAP 1.2 (id 14), 1.3 (17), 1.4 (29).
- **Two flavors per Windows STIG:**
  - DISA SCAP 1.3 benchmarks on `dl.dod.cyber.mil`
  - NIWC "enhanced" signed SCAP 1.4 benchmarks on GitHub (`raw.githubusercontent.com/niwc-atlantic/scap-content-library/.../Current/`)

  The enhanced flavor is what SCC scans. It automates many more rules and carries OCIL questions. **Default: NIWC enhanced 1.4, with DISA 1.3 as the fallback.** Both hosts were verified reachable from PowerShell.
- **Local cache** of downloaded archives and extracted data streams, plus a manifest recording each item's NCP checklist id, version, `lastModified`, source URL, ETag/SHA and signature status.
- **Update detection:** on launch and on demand, query NCP and compare `lastModified`/version (plus ETag or the GitHub tree SHA) against the manifest. Show an "update available" badge per benchmark. Never replace cached content silently; the user chooses when to update, and previous versions are kept so older results stay reproducible.
- **Integrity:** verify XML digital signatures on signed content before use, and show the status. Unsigned DISA content is allowed but labeled.
- **Manual import:** the user can also add a local SCAP zip or data-stream file, for offline use or content not on NCP.

### 6.2 System profiling and benchmark selection ★
- Detect:
  - OS edition, build and architecture
  - domain or workgroup membership
  - installed software relevant to STIG content: browsers and versions, Office, .NET versions, Defender/AV state, firewall, IIS and so on
- Map the detected products to NCP checklists (by target, then keyword). Pre-tick the matching benchmarks; the user can tick or untick any.
- Final applicability of each benchmark is decided by the content itself (§6.3, CPE). Pre-ticking is a convenience, not a substitute for CPE.

### 6.3 Scan engine (exact SCAP semantics) ★
- **Inputs:** SCAP source data streams (SCAP 1.2/1.3/1.4: XCCDF 1.2, OVAL 5.11.x, OCIL 2.0, CPE 2.3 dictionary and applicability language), plus standalone XCCDF+OVAL where content ships that way.
- **XCCDF processing:**
  - Benchmark/profile resolution: selection, refine-value, set-value, extends, value selectors.
  - Rule applicability via CPE platforms, with CPE checks evaluated through the content's CPE OVAL.
  - Check dispatch by check system (OVAL, OCIL, CPE).
  - Multi-check and complex-check handling.
  - Result mapping exactly as the XCCDF 1.2 and SCAP specs define, including OVAL "error"/"unknown"/"not applicable" mapped to XCCDF results.
- **Scoring:** the four standard XCCDF scoring models:
  - `urn:xccdf:scoring:default`
  - `flat`
  - `flat-unweighted`
  - `absolute`
- **OVAL interpreter:**
  - Complete OVAL 5.11.x definition semantics: criteria operators and negation, extend_definition, test `check` and `check_existence`, state operators, entity operations and datatypes (string, int, float, boolean, version, binary, ipv4/ipv6, record), entity-level check/var_check, `var_ref`, local and external variables with every component function (concat, arithmetic, begin/end, escape_regex, split, substring, regex_capture, time_difference, unique, count, glob_to_regex), object `set` with filters, and behaviors (`windows_view` 32/64-bit, recursion, max_depth and so on).
  - Collected-item statuses (exists / does not exist / error / not collected) must flow through to results exactly per the spec. This is where non-validated tools usually diverge.
- **Windows collectors (probes):**
  - One collector per OVAL test type used by the content.
  - The required set is fixed by an inventory of the actual content, which is the first build step. Known in use: `registry`, `file`, `wmi57`, `xmlfilecontent`, `wuaupdatesearcher`.
  - Expected from DISA Windows content: `accesstoken`, `auditeventpolicysubcategories`, `lockoutpolicy`, `passwordpolicy`, `sid`/`sid_sid`, `user`/`user_sid55`, `group`/`group_sid`, `service`, `fileeffectiverights53`, `regkeyeffectiverights53`, `textfilecontent54`, `family`, `variable`, `environmentvariable58`, `sharedresource`, `filehash58`.
  - Collectors run with system-wide enumeration where the spec requires (file search patterns, registry recursion).
- **No script execution during scans ★:** content `shellcommand_object` and `cmdlet_object` checks are answered by native C# that reads the same sources (registry ACLs, WMI/CIM, event logs, certificate stores, UEFI variables) and reproduces the shell's output. Plain programs the content names (icacls, bcdedit, w32tm, caspol) start directly, with no shell. PowerShell and cmd are never started or hosted for a scan, because Avast's AMSI provider flags it and an antivirus exclusion for powershell.exe is not acceptable. A command with no native implementation is reported as not collected; `tools/Get-CommandInventory.ps1` and a content gate test list any.
- **Collector failures:** a collector that is denied access returns OVAL `error` with a message. Example: SCC hit "Access is denied" on the firewall policy keys because of Avast. A collector failure never crashes the scan.
- **Windows Update check:** support the offline `wsusscn2.cab` method and the online WUA method, matching how the content defines `wuaupdatesearcher`.

### 6.4 Three result layers ★
1. **SCAP:** exactly what the content automates, evaluated per §6.3. Manual rules stay `notchecked`, as in any validated scanner. This layer alone produces the SCAP scores and the standard result files.
2. **Automated manual checks:**
   - A PowerSCAP library of native (C#) checks, each keyed to a STIG rule (stable ID: STIG ID plus rule version), for rules the content leaves manual but a script can decide.
   - Examples: scanning `*.exe.config` for `loadFromRemoteSources`, BitLocker protectors and PIN, Secure Boot state, certificate stores, Wi-Fi Direct adapters.
   - Results carry a "PowerSCAP automated" label and feed a separate **STIG completeness** view and score. They never alter the SCAP score.
3. **Guided questions:**
   - Where no script can decide, the app asks the user. It uses the content's OCIL questions where present, otherwise the STIG check text.
   - Each answer is stored per machine, benchmark and rule, with the user's comment and a timestamp, and is reused on later scans.
   - An answer is flagged for re-review when the rule's version or text changes in new content.

Every reported result states its source: SCAP, Script, or Answered by \<user\> \<date\>.

### 6.5 Outputs ★ (formats beyond HTML are my call)
- **HTML reports per benchmark,** modeled on SCC's layout:
  - **All-Settings:** score block, system info, content info, results grouped by CAT I/II/III, and per-rule detail. Detail includes rule/STIG/CCI IDs, description, check and fix text, and the OVAL test breakdown with **expected vs. actual collected values**, which the owner relies on.
  - **Non-Compliance:** the same, filtered to findings.
  - Results from layers 2 and 3 appear in a clearly separate section.
- **Machine-readable output:** XCCDF 1.2 result XML (TestResult), OVAL 5.11 results XML, and ARF 1.1 bundling them, so other SCAP tools can consume the results.
- **STIG Viewer checklist (`.cklb`)** combining all three layers with their sources.
- **Combined summary page** across all scanned benchmarks.

### 6.6 GUI ★
- **Technology:** WPF/XAML loaded from PowerShell, with C# view-models where binding performance needs it. Launched from a shortcut with no console window visible.
- **Theme:** dark "security console" by default (near-black background, teal accent, green/amber/red status colors). A light mode is selectable in Settings. *My call:* also a "Follow Windows" option; the choice persists.
- **Layout:** a left side rail with four steps plus Settings:
  1. **System:** detected machine profile.
  2. **Content:** benchmark list with checkboxes, "detected" and "update available" badges, profile selection per benchmark, and NCP browse/search plus local import.
  3. **Scan:** per-benchmark progress with a cancel option.
  4. **Results:** score tiles per benchmark, then a filterable findings list (severity, status, source, text search). Clicking a rule opens a detail side panel with description, expected vs. actual, fix text and the guided-question answer box when relevant. Export buttons for reports and the checklist.
  5. **Settings:** theme, cache location, update-check behavior, default content flavor, output folder.
- **UX principles:** one main task per screen; details on demand; no modal dialogs during scans; scans run in a background runspace so the UI stays responsive and past results stay browsable during a scan; scan history is kept and comparable.

### 6.7 Proving parity ★
- A test harness diffs PowerSCAP's XCCDF results rule by rule against a validated scanner's results for the **same content version and the same machine state**. Any mismatch is a bug.
- The reference material is the existing SCC sessions in `%USERPROFILE%\SCC\Sessions\`, which hold SCC's XCCDF result XML for each benchmark: per-rule results and all scores. A clean comparison needs fresh paired runs, because the reference machine's settings changed between earlier SCC scans.
- **Reference scanner (open):** the owner has not yet chosen how fresh reference runs will be produced. SCC is currently uninstalled. *My call until decided:*
  - Measure against the SCC XCCDF results already on disk, rule by rule, for the content versions SCC used. Mismatches are investigated, not assumed to be bugs, because machine state changed between those scans.
  - Recommend reinstalling SCC's command-line scanner (`cscc.exe`) only to produce paired reference runs.
- Engine-level unit tests per OVAL operation, datatype, existence/check combination, variable function and collector, using small hand-written OVAL fixtures with known answers.

## 7. Left to the builder

- Internal architecture, module and file layout, and which parts are C# vs. PowerShell.
- Test framework (Pester assumed) and fixture organization.
- Cache, result and settings file locations and on-disk formats (sensible Windows defaults, e.g. `%ProgramData%\PowerSCAP` for content and answers).
- The exact HTML/CSS of reports, within §6.5.
- How elevation is requested at launch.
- Packaging and signing of the scripts.

## 8. Calls I made (not decided by the owner)

- NIWC enhanced SCAP 1.4 as the default flavor, DISA 1.3 as the fallback.
- Output formats beyond HTML: XCCDF/OVAL/ARF result XML and `.cklb`.
- A "Follow Windows" theme option.
- Only the four standard XCCDF scoring models. SCC also emits proprietary `spawar-adjusted`/`spawar-original` scores; on observed results these equal `default`, and they are not reproduced.
- The anti-goal of never loading web or script engines into the process.
- Keeping old content versions in the cache for reproducibility.
- Supporting manual import of local content.
- Signature verification failure on signed content: refuse to scan that benchmark until the user re-downloads it or explicitly overrides; the override is recorded in the results.
- First scope of the automated-manual-check library (layer 2): the manual rules in the benchmarks the reference machine uses (Windows 11, Edge, Chrome, Firefox, Defender AV, Defender Firewall, .NET 4). Other benchmarks get layer-2 checks over time.
- Windows Update check: the online Windows Update Agent search is the default; the offline `wsusscn2.cab` method is supported when the cab is present.
