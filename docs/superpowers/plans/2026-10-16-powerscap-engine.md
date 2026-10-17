# PowerSCAP Plan 1: Scan Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A headless engine that loads a SCAP source data stream, evaluates a profile on the local Windows machine with exact XCCDF/OVAL semantics, writes XCCDF 1.2 result XML, and proves parity against SCC's results.

**Architecture:**
- The OVAL and XCCDF engine and all Windows collectors are C# 5. The code is compiled at run time by `Add-Type` into a DLL that is cached by source hash.
- A thin PowerShell module (`PowerSCAP`) exposes the cmdlets. PowerShell holds no evaluation logic.
- Later plans build the GUI, NCP content management, reports and the extra result layers on top of this module.

**Tech Stack:**
- Windows PowerShell 5.1 and .NET Framework 4.8, with C# 5 via CodeDom `Add-Type`.
- `System.Xml`, `System.Management` (WMI) and `System.DirectoryServices.AccountManagement`.
- P/Invoke to `advapi32`/`netapi32`/`authz`.
- Pester 5 for tests only.

**Spec:** `docs/superpowers/specs/2026-10-16-powerscap-design.md` (§5, §6.3, §6.5 XCCDF output, §6.7)

**Plan series** (each a separate plan written after this one ships):
1. **Engine** (this plan)
2. Content (NCP, cache, updates, signatures, system profiling)
3. Outputs (HTML reports, OVAL/ARF XML, `.cklb`)
4. Result layers 2 and 3 (scripted manual checks, guided questions)
5. WPF GUI

## Global Constraints

- **Runtime:** must run under Windows PowerShell 5.1 (`powershell.exe`). PowerShell 7 is not required.
- **C# language:** C# 5 only. No `$"..."` interpolation, `?.`, `nameof`, expression-bodied members, tuples or `out var`.
- **Dependencies:** no third-party binaries or packages ship with the product. Pester is a dev-only dependency.
- **Evaluation semantics:**
  - OVAL: exactly as in the *OVAL Language Specification 5.11.2*.
  - XCCDF: exactly as in *NIST IR 7275 Rev 4 (XCCDF 1.2)*.
  - SCAP: exactly as in *NIST SP 800-126 Rev 3* (result mapping and data streams).
  - Where this plan and a spec disagree, the spec wins. Note the discrepancy in the commit message.
- **Collector failures:** a collector failure (including access denied) yields an item or object status of `error` with a message. It never throws past the collector boundary.
- **No web or script hosts:** nothing may load WebBrowser, mshtml, WebView2, JScript or VBScript, or call AMSI.
- **Elevation:** scans require elevation. Tests that need admin are tagged `Admin` and skipped when not elevated.
- **Namespace and module:** all C# lives in namespace `PowerScap.Engine`. The module name is `PowerSCAP`.

## Review Focus

1. **Access denied from security software** (e.g. Avast on the firewall policy keys): the affected tests come out `error`, the rule comes out `error`, the scan finishes. *Test in Task 8.*
2. **32- vs 64-bit registry and file views:** a `windows_view="32_bit"` behavior must read `WOW6432Node`/`SysWOW64`. The default is the 64-bit view, even though PowerShell may run 32-bit. *Test in Task 8.*
3. **Missing key vs. missing value:** a missing value under an existing key is a `does not exist` item, not an error. A missing key with a pattern-match name gives zero items with object flag `does not exist`. *Test in Task 8.*
4. **Version comparison:** `10.0.26100.1 > 10.0.9.0` as `version`, but string ordering would say the opposite. Versions with differing component counts compare with missing parts treated as 0. *Test in Task 3.*
5. **Huge file searches:** a `file_object` with a `path` pattern over `C:\` (like the .NET `*.exe.config` check) must finish without stack overflow and must skip unreadable directories, reporting them as messages, not errors that fail the whole object. *Test in Task 9.*

---

### Task 1: Project scaffold, C# build loader, test runner

**Files:**
- Create: `src/PowerSCAP/PowerSCAP.psd1`, `src/PowerSCAP/PowerSCAP.psm1`, `src/PowerSCAP/Engine/Version.cs`, `build/Invoke-Tests.ps1`, `tests/Build.Tests.ps1`, `README.md`

**Interfaces:**
- Produces:
  - `Import-PowerScapEngine [-Force]` (in the psm1, run at module import). It compiles every `src/PowerSCAP/Engine/**/*.cs` with `Add-Type -Path ... -OutputAssembly "$env:LOCALAPPDATA\PowerSCAP\bin\PowerScap.Engine.<sha256-of-sources-first12>.dll"`, then loads that DLL. Referenced assemblies: `System.Xml`, `System.Xml.Linq`, `System.Management`, `System.DirectoryServices.AccountManagement`, `System.Security`, `System.Core`.
  - C# `PowerScap.Engine.EngineInfo.Version` (const string `"0.1.0"`).
  - `build/Invoke-Tests.ps1 [-Tag <string[]>] [-ExcludeTag <string[]>]`. It installs Pester ≥5.5 for the current user if missing, then runs `tests/` under `powershell.exe`.

- [ ] **Step 1:** Write `tests/Build.Tests.ps1`:
  - `It 'compiles and exposes the engine version'`: after `Import-Module ./src/PowerSCAP -Force`, `[PowerScap.Engine.EngineInfo]::Version | Should -Be '0.1.0'`.
  - `It 'reuses the cached DLL when sources are unchanged'`: importing twice in fresh `powershell.exe` processes leaves exactly one `PowerScap.Engine.*.dll` in the bin folder.
- [ ] **Step 2:** Run `powershell -NoProfile -File build/Invoke-Tests.ps1`. Expected: FAIL (module not found).
- [ ] **Step 3:** Implement the module manifest (PowerShellVersion `'5.1'`), the psm1 loader and `Version.cs`. Add a README with how to run the tests.
- [ ] **Step 4:** Re-run. Expected: 2 passed.
- [ ] **Step 5:** Commit: `feat: module scaffold and cached C# engine build`.

### Task 2: SCAP data stream loader and test content

**Files:**
- Create: `src/PowerSCAP/Engine/Content/ScapContent.cs`, `tools/Get-TestContent.ps1`, `tests/fixtures/content/mini-ds.xml`, `tests/Content.Tests.ps1`

**Interfaces:**
- Produces:
  - `ScapContent ScapContentLoader.Load(string path)`. It accepts a `.zip` (extracting to `%LOCALAPPDATA%\PowerSCAP\extract\<sha256>`), a source data stream `.xml`, or a standalone XCCDF `.xml` with sibling OVAL files.
  - The `ScapContent` class has these properties:
    - `XmlDocument Benchmark`
    - `string BenchmarkId`
    - `IDictionary<string, XmlDocument> CheckComponents`: keyed by the exact `href` that XCCDF `check-content-ref` uses, after catalog resolution.
    - `XmlDocument CpeDictionary`
    - `IDictionary<string, XmlDocument> CpeChecks`
    - `XmlDocument Ocil`
    - `string SourcePath`
  - Resolution follows SP 800-126 data stream rules: `ds:data-stream` → `ds:checklists`/`ds:checks`/`ds:dictionaries` component-refs, plus the `cat:catalog` `uri` mappings.
  - `tools/Get-TestContent.ps1 -Destination tests/content`. It downloads the NIWC enhanced zips that match the SCC session `2026-10-15_210812` stream versions. Base URL: `https://raw.githubusercontent.com/niwc-atlantic/scap-content-library/refs/heads/main/Current/`. Files:
    - `U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip`
    - `U_MS_Edge_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip`
    - `U_Google_Chrome_V2R11_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip`
    - `U_MOZ_Firefox_Windows_V6R8_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip`
    - `U_MS_Defender_Antivirus_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip`
    - `U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-4_Benchmark-enhancedV14-signed.zip`
    - `U_MS_DotNet_Framework_4-0_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV15-signed.zip`

    `tests/content/` is git-ignored.

- [ ] **Step 1:** Write `mini-ds.xml`: a valid SCAP 1.3 source data stream with one XCCDF benchmark (2 rules, 1 profile), one OVAL component (2 definitions) and a catalog mapping `oval.xml` to `#scap_test_comp_oval`. Write the tests:
  - `It 'resolves check hrefs through the catalog'`: `$c.CheckComponents.Keys -contains 'oval.xml'`.
  - `It 'reads the benchmark id'`: `$c.BenchmarkId | Should -Be 'xccdf_test_benchmark_mini'`.
  - `It 'loads real NIWC content' -Tag Content`: for `tests/content/*Windows_11*.zip`, `BenchmarkId` is `xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG`, and every `check-content-ref/@href` in the benchmark is a key of `CheckComponents`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement the loader and `Get-TestContent.ps1`. Use `System.IO.Compression.ZipFile`; with ≥2 data streams, pick the first unless one is named.
- [ ] **Step 4:** Run `tools/Get-TestContent.ps1`, then the tests. Expected: all pass.
- [ ] **Step 5:** Commit: `feat: SCAP data stream loader and test content fetcher`.

### Task 3: OVAL datatypes and operations

**Files:**
- Create: `src/PowerSCAP/Engine/Oval/OvalTypes.cs`, `src/PowerSCAP/Engine/Oval/OvalOps.cs`, `tests/Oval.Ops.Tests.ps1`

**Interfaces:**
- Produces:
  - `enum OvalResult { True, False, Error, Unknown, NotEvaluated, NotApplicable }`
  - `OvalResult OvalOps.Compare(string datatype, string operation, string actual, string expected)`
    - Datatypes: `string`, `int`, `float`, `boolean`, `version`, `binary`, `ipv4_address`, `ipv6_address`, `evr_string`, `debian_evr_string` (EVR may return Error), `fileset_revision`, `ios_version`.
    - Operations: exactly the OVAL `OperationEnumeration` strings (`equals`, `not equal`, `case insensitive equals`, `case insensitive not equal`, `greater than`, `less than`, `greater than or equal`, `less than or equal`, `bitwise and`, `bitwise or`, `pattern match`, `subset of`, `superset of`).
    - An unparseable value or an operation invalid for the datatype gives `Error`.
  - `bool OvalOps.PatternMatch(string input, string perlRegex)`: translates Perl-only constructs (`\Z`, `\z`, POSIX classes) for .NET with `RegexOptions.CultureInvariant`, no `IgnoreCase` unless the pattern uses `(?i)`.

- [ ] **Step 1:** Write table-driven tests:
  - `version`, `greater than`, `10.0.26100.1` vs `10.0.9.0` → True
  - `version`, `equals`, `1.2` vs `1.2.0.0` → True
  - `int`, `equals`, `0x10` vs `16` → True
  - `int`, `less than or equal`, `abc` vs `1` → Error
  - `string`, `case insensitive equals`, `ABC` vs `abc` → True
  - `string`, `pattern match`, `HKLM\Software` vs `^HKLM\\` → True
  - `boolean`, `equals`, `1` vs `true` → True
  - `int`, `bitwise and`, `7` vs `5` → True
  - `binary`, `equals`, `0A0b` vs `0a0B` → True
  - `string`, `greater than`, `b` vs `a` → Error (strings only support equality/pattern)
  - `ipv4_address`, `greater than`, `10.0.0.2` vs `10.0.0.1` → True
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement, following OVAL 5.11.2 §5.3.6 (operation/datatype matrix).
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: OVAL datatype comparisons`.

### Task 4: OVAL result logic (operators, existence, check)

**Files:**
- Create: `src/PowerSCAP/Engine/Oval/OvalLogic.cs`, `tests/Oval.Logic.Tests.ps1`

**Interfaces:**
- Produces:
  - `OvalResult OvalLogic.Combine(string op, IList<OvalResult> results)`. `op` is one of `AND`, `ONE`, `OR`, `XOR`.
  - `OvalResult OvalLogic.Negate(OvalResult r)`. Only `True`/`False` flip.
  - `OvalResult OvalLogic.Existence(string checkExistence, int exists, int doesNotExist, int error, int notCollected)`. `checkExistence` is one of `all_exist`, `any_exist`, `at_least_one_exists`, `none_exist`, `only_one_exists`.
  - `OvalResult OvalLogic.Check(string check, IList<OvalResult> itemResults)`. `check` is one of `all`, `at least one`, `none satisfy`, `only one`, `none exist`.

- [ ] **Step 1:** Write tests copying the OVAL 5.11.2 truth tables (§5.3.3 Operator, §5.3.1 CheckEnumeration, §5.3.2 ExistenceEnumeration). Minimum rows:
  - AND: `[T,T]` → T; `[T,F,E]` → F; `[T,E,U]` → E; `[T,U]` → U; `[NA,NA]` → NA; `[T,NA]` → T; `[T,NE]` → NE.
  - OR: `[F,T,E]` → T; `[F,E]` → E; `[F,F]` → F.
  - ONE: `[T,F]` → T; `[T,T]` → F; `[T,U]` → U.
  - XOR: `[T,T,T]` → T; `[T,T]` → F.
  - Existence:
    - `all_exist(0,0,0,0)` → F
    - `all_exist(2,0,0,0)` → T
    - `all_exist(2,1,0,0)` → F
    - `all_exist(1,0,1,0)` → E
    - `none_exist(0,0,0,0)` → T
    - `at_least_one_exists(1,3,0,0)` → T
    - `at_least_one_exists(0,0,0,1)` → U
    - `only_one_exists(2,0,0,0)` → F
  - Check: `all [T,T]` → T; `all []` → T (vacuous); `none satisfy [F,F]` → T; `only one [T,F]` → T; `at least one [F,E]` → E.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement exactly per the spec tables. Results are counted by category, so order doesn't matter.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: OVAL operator, existence and check logic`.

### Task 5: Items, object specs, collector contract, sets and filters

**Files:**
- Create: `src/PowerSCAP/Engine/Oval/OvalItems.cs`, `src/PowerSCAP/Engine/Oval/ObjectEvaluator.cs`, `src/PowerSCAP/Engine/Oval/Collectors/ICollector.cs`, `tests/fixtures/oval/sets.xml`, `tests/Oval.Objects.Tests.ps1`

**Interfaces:**
- Produces:
  - `enum ItemStatus { Exists, DoesNotExist, Error, NotCollected }`
  - `enum CollectedFlag { Complete, Incomplete, DoesNotExist, Error, NotCollected, NotApplicable }`
  - `class OvalEntity { string Name; string Datatype; string Value; ItemStatus Status; List<OvalEntity> Fields /* record */ }`
  - `class OvalItem { int Id; string ItemType; ItemStatus Status; List<OvalEntity> Entities; List<string> Messages; IList<OvalEntity> Get(string name); }`
  - `class EntityCriterion { string Name; string Operation; string Datatype; IList<string> Values /* resolved var values */; string VarCheck; bool IsNil; }`
  - `class ObjectSpec { string ObjectId; string ObjectType; IDictionary<string, EntityCriterion> Entities; XmlElement Behaviors; }`
  - `class CollectedObject { string ObjectId; CollectedFlag Flag; List<OvalItem> Items; List<string> Messages; }`
  - `interface ICollector { string ObjectType { get; } CollectedObject Collect(ObjectSpec spec, OvalContext ctx); }`. `ObjectType` is the element local name, e.g. `registry_object`.
  - `class CollectorRegistry { void Register(ICollector c); ICollector Find(string objectType); }`
  - `CollectedObject ObjectEvaluator.Evaluate(XmlElement objectElement, OvalContext ctx)`. It handles `set` (`UNION`/`INTERSECTION`/`COMPLEMENT`, nested sets, `filter action="include|exclude"` against states), maps unregistered object types to `Flag = NotCollected`, and memoizes per object id.
  - `class OvalContext { XmlDocument Definitions; CollectorRegistry Collectors; IDictionary<string, CollectedObject> Cache; int NextItemId(); }`. Task 6 adds `Variables`. Until then, `var_ref` entities resolve to an empty list.

- [ ] **Step 1:** Write tests with a fake `ICollector` (C# test helper compiled in the test via `Add-Type`), which returns fixed items for `fake_object`:
  - `It 'unions two objects without duplicate items'`
  - `It 'complements object B from A'`
  - `It 'exclude filter drops items matching the state'`
  - `It 'unknown object type is NotCollected'`
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement per OVAL 5.11.2 §4.3 (Set) and the filter semantics. Items are identical when type and all entity values match.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: OVAL object evaluation, sets and filters`.

### Task 6: OVAL variables

**Files:**
- Create: `src/PowerSCAP/Engine/Oval/VariableResolver.cs`, `tests/fixtures/oval/variables.xml`, `tests/Oval.Variables.Tests.ps1`
- Modify: `src/PowerSCAP/Engine/Oval/OvalItems.cs` (add `VariableResolver Variables` to `OvalContext`), `src/PowerSCAP/Engine/Oval/ObjectEvaluator.cs` (fill `EntityCriterion.Values` from `var_ref`)

**Interfaces:**
- Consumes: `OvalContext`, `EntityCriterion` and `CollectedFlag` from Task 5.
- Produces:
  - `class VariableResult { IList<string> Values; CollectedFlag Flag; List<string> Messages; }`
  - `VariableResult VariableResolver.Resolve(string varId)`. It handles `constant_variable`, `external_variable` (from the supplied `IDictionary<string, IList<string>> externalValues`), and `local_variable` with every component and function in OVAL 5.11.2 §4.2 (literal, object_component with record_field, variable_component, arithmetic, begin, end, concat, count, escape_regex, glob_to_regex, regex_capture, split, substring, time_difference, unique). It is memoized.

- [ ] **Step 1:** Write tests:
  - `concat('a', var(['b','c']))` → `['ab','ac']` (cartesian)
  - `regex_capture('Version 10.0.1', '(\d+\.\d+)')` → `['10.0']`
  - `split('a;b',';')` → `['a','b']`
  - `substring('abcdef', start 2, length 3)` → `['bcd']` (1-based)
  - `count(['x','y'])` → `['2']`
  - `glob_to_regex('*.exe')` → `['^[^\\]*\.exe$']`
  - missing external var → `Flag = Error`
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: OVAL variable resolution`.

### Task 7: Test and definition evaluation

**Files:**
- Create: `src/PowerSCAP/Engine/Oval/OvalEvaluator.cs`, `tests/fixtures/oval/definitions.xml`, `tests/Oval.Evaluator.Tests.ps1`

**Interfaces:**
- Produces:
  - `class ItemResult { OvalItem Item; OvalResult Result; }`
  - `class TestResult { string TestId; string Comment; string Check; string CheckExistence; string StateOperator; OvalResult Result; CollectedObject Object; List<ItemResult> Items; List<string> StateIds; }`
  - `class DefinitionResult { string DefinitionId; string Title; OvalResult Result; List<TestResult> Tests; }`
  - `class OvalEvaluator { OvalEvaluator(XmlDocument definitions, CollectorRegistry collectors, IDictionary<string, IList<string>> externalValues); DefinitionResult Evaluate(string definitionId); IEnumerable<TestResult> AllTestResults(); }`
  - Test evaluation order: existence first, then state check (`state_operator`, entity `check`, `var_check`). A collected flag of `Error` makes the test `Error`; `NotCollected` makes it `Unknown`. Per §5.

- [ ] **Step 1:** Write tests against the fixture with the fake collector:
  - existence-only test (no state) → True
  - state mismatch with `check="all"` → False
  - `extend_definition` with `negate="true"` → flips
  - criteria `operator="OR"` with one error and one true → True
  - `applicability_check="true"` criterion false → NotApplicable
  - entity `var_check="at least one"` against a 2-value variable → True
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Evaluate each definition once (memoized for `extend_definition`).
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: OVAL test and definition evaluation`.

### Task 8: Collectors: registry, family, environment, variable

**Files:**
- Create: `src/PowerSCAP/Engine/Oval/Collectors/RegistryCollector.cs`, `FamilyCollector.cs`, `EnvironmentVariable58Collector.cs`, `VariableCollector.cs`, `tests/Collectors.Registry.Tests.ps1`

**Interfaces:**
- Consumes: `ICollector`, `ObjectSpec` and `CollectedObject` from Task 5.
- Produces:
  - `registry_object` (windows-def) with `hive`, `key`, `name` (any operation, including pattern match by enumeration); behaviors `windows_view`, `recurse_direction`, `max_depth`, `recurse_file_system` ignored. Item entities `hive`, `key`, `name`, `last_write_time`, `type` (`reg_dword`/`reg_sz`/...) and `value` (multi-sz gives multiple `value` entities).
  - `family_object` → `windows`.
  - `environmentvariable58_object`.
  - `variable_object`.
  - `static CollectorRegistry CollectorRegistry.CreateDefault()` (added to `ICollector.cs`) registers this task's collectors. Tasks 9–11 each add their collectors to it.

- [ ] **Step 1:** Write tests using `HKCU:\Software\PowerSCAPTest` (created and removed by the test):
  - existing DWORD → item `type=reg_dword`, `value=1`
  - missing value under an existing key → one item with `Status=DoesNotExist` for `name` (Review Focus 3)
  - pattern-matched key with no matches → `Flag=DoesNotExist`, 0 items (Review Focus 3)
  - `windows_view="32_bit"` reads a value written only under `HKLM\SOFTWARE\WOW6432Node\...` (`-Tag Admin`; Review Focus 2)
  - unreadable key → item/object `Error` with message containing `Access is denied` (simulated with a key whose ACL denies the current user; Review Focus 1)
  - `family` → `windows`
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement with `RegistryKey.OpenBaseKey(hive, RegistryView.Registry64|Registry32)` per `windows_view` (default 64-bit on a 64-bit OS).
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: registry, family, environment and variable collectors`.

### Task 9: Collectors: file, textfilecontent54, xmlfilecontent, filehash58, wmi57

**Files:**
- Create: `src/PowerSCAP/Engine/Oval/Collectors/FileCollector.cs`, `TextFileContent54Collector.cs`, `XmlFileContentCollector.cs`, `FileHash58Collector.cs`, `Wmi57Collector.cs`, `src/PowerSCAP/Engine/Oval/Collectors/FileSearch.cs`, `tests/Collectors.File.Tests.ps1`

**Interfaces:**
- Produces:
  - `FileSearch.Find(EntityCriterion path, EntityCriterion filename, EntityCriterion filepath, XmlElement behaviors, OvalContext ctx) : IEnumerable<FileHit>`. It is shared by all file-based collectors: iterative directory walk (no recursion stack); `recurse_direction`, `max_depth`, `recurse_file_system`; inaccessible directories added to `ctx` messages and skipped.
  - Collectors for the object types `file_object`, `textfilecontent54_object`, `xmlfilecontent_object` (XPath 1.0 via `XmlDocument.SelectNodes`, DTD processing off), `filehash58_object` and `wmi57_object` (record result fields).

- [ ] **Step 1:** Write tests on a temp tree:
  - file version entity on `C:\Windows\System32\kernel32.dll` → non-empty `version`
  - `textfilecontent54` with `pattern match` and `instance >= 1` → 2 items
  - `xmlfilecontent` XPath `/configuration/runtime/loadFromRemoteSources/@enabled` on a fixture → `value_of=true`
  - `filehash58` SHA-256 of a fixture → its known hash
  - `wmi57` `SELECT Caption FROM Win32_OperatingSystem` in `root\cimv2` → one record field
  - pattern search `C:\` for `.*\.exe\.config$` with `max_depth=-1` completes and reports access-denied directories as messages (`-Tag Slow`; Review Focus 5)
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: file, content, hash and WMI collectors`.

### Task 10: Collectors: policy and accounts

**Files:**
- Create: `src/PowerSCAP/Engine/Native/Advapi.cs`, `Netapi.cs`, and `src/PowerSCAP/Engine/Oval/Collectors/PasswordPolicyCollector.cs`, `LockoutPolicyCollector.cs`, `AuditEventPolicySubcategoriesCollector.cs`, `AccessTokenCollector.cs`, `SidCollector.cs`, `SidSidCollector.cs`, `UserCollector.cs`, `UserSid55Collector.cs`, `GroupCollector.cs`, `GroupSidCollector.cs`, `ServiceCollector.cs`, `tests/Collectors.Policy.Tests.ps1`

**Interfaces:**
- Produces the collectors for `passwordpolicy_object`, `lockoutpolicy_object`, `auditeventpolicysubcategories_object`, `accesstoken_object`, `sid_object`, `sid_sid_object`, `user_object`, `user_sid55_object`, `group_object`, `group_sid_object` and `service_object`. Sources:
  - `NetUserModalsGet` (levels 0, 3) for password and lockout policy
  - `AuditQuerySystemPolicy` with the subcategory GUIDs for audit policy. Entity values are `AUDIT_SUCCESS`, `AUDIT_FAILURE`, `AUDIT_SUCCESS_FAILURE` or `AUDIT_NONE`.
  - `LsaOpenPolicy`/`LsaEnumerateAccountRights` for access tokens
  - `LookupAccountSid`/`LookupAccountName` for SIDs
  - `NetUserEnum`/`NetLocalGroupGetMembers` for users and groups
  - `QueryServiceConfig` plus `QueryServiceStatusEx` for services

- [ ] **Step 1:** Write tests (all `-Tag Admin`):
  - `passwordpolicy` `min_passwd_len` equals `(net accounts)` "Minimum password length"
  - `auditeventpolicysubcategories` `credential_validation` matches `auditpol /get /subcategory:"Credential Validation"`
  - `accesstoken` for `BUILTIN\Administrators` has `sedebugprivilege=1`
  - `sid_object` for `S-1-5-32-544` → `trustee_name` `BUILTIN\Administrators`
  - `service_object` `wuauserv` has `start_type`
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement the P/Invoke wrappers (free every buffer with `NetApiBufferFree`/`LsaFreeMemory`) and the collectors.
- [ ] **Step 4:** Run the tests elevated. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: policy, account and service collectors`.

### Task 11: Collectors: effective rights, shares, Windows Update

**Files:**
- Create: `src/PowerSCAP/Engine/Native/Authz.cs`, `src/PowerSCAP/Engine/Oval/Collectors/FileEffectiveRights53Collector.cs`, `RegKeyEffectiveRights53Collector.cs`, `SharedResourceCollector.cs`, `WuaUpdateSearcherCollector.cs`, `tests/Collectors.Rights.Tests.ps1`

**Interfaces:**
- Produces:
  - `fileeffectiverights53_object` and `regkeyeffectiverights53_object`: `AuthzInitializeContextFromSid` + `AuthzAccessCheck` per trustee SID, with standard/generic/specific rights entities per OVAL.
  - `sharedresource_object`: `NetShareEnum` level 2.
  - `wuaupdatesearcher_object`: COM `Microsoft.Update.Session` via `Type.GetTypeFromProgID`, with the `search_criteria` from the object. Online search by default. When `%ProgramData%\PowerSCAP\wsusscn2.cab` exists, use `ServiceManager.AddScanPackageService` offline.

- [ ] **Step 1:** Write tests:
  - effective rights of `S-1-5-32-544` on `C:\Windows\System32\config` include `generic_all` or `file_read_data`
  - shares include `IPC$`
  - WUA search `IsInstalled=1` returns ≥1 item (`-Tag Slow,Online`)
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests elevated. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: effective rights, share and Windows Update collectors`.

### Task 12: Content inventory gate

**Files:**
- Create: `tools/Get-OvalInventory.ps1`, `tests/Inventory.Tests.ps1`

**Interfaces:**
- Produces: `tools/Get-OvalInventory.ps1 -Path <content zip or dir>`. It outputs objects `{ObjectType, TestCount, Supported}` across all OVAL components, where `Supported` means `CollectorRegistry.CreateDefault().Find(type) -ne $null`.

- [ ] **Step 1:** Write `It 'supports every object type used by the test content' -Tag Content`: `Get-OvalInventory tests/content` has no row with `Supported -eq $false`.
- [ ] **Step 2:** Run it. Expected: FAIL only if the content uses a type outside Tasks 8–11. For each such type, add a collector in the matching task's style, with its own test, before continuing.
- [ ] **Step 3:** Run it. Expected: PASS.
- [ ] **Step 4:** Commit: `test: content inventory gate`.

### Task 13: XCCDF profile resolution and CPE applicability

**Files:**
- Create: `src/PowerSCAP/Engine/Xccdf/XccdfModel.cs`, `src/PowerSCAP/Engine/Xccdf/ProfileResolver.cs`, `src/PowerSCAP/Engine/Xccdf/CpeApplicability.cs`, `tests/Xccdf.Profile.Tests.ps1`

**Interfaces:**
- Produces:
  - `class ResolvedRule { string RuleId; string Severity; double Weight; string Role; bool Selected; List<string> PlatformIds; XmlElement RuleElement; List<string> GroupPath; }`
  - `class ResolvedProfile { string ProfileId; List<ResolvedRule> Rules; IDictionary<string, string> Values /* value id → selected value */; }`
  - `ResolvedProfile ProfileResolver.Resolve(ScapContent content, string profileId)`. It handles `extends`, `select`, `refine-rule` (weight, severity, role, selector), `refine-value`, `set-value` and group selection inheritance per XCCDF 1.2 §6.2.
  - `bool CpeApplicability.IsApplicable(ScapContent content, IList<string> platformIds, CollectorRegistry collectors)`. It evaluates CPE names via the dictionary's check (OVAL definitions in `CpeChecks`) and `cpe2:platform` logical tests (`AND`/`OR`, negate).

- [ ] **Step 1:** Write tests against `mini-ds.xml`, extended with a group, a profile that refines one rule's weight to 5 and deselects one rule, and a `platform` whose CPE OVAL check returns false:
  - deselected rule has `Selected=false`
  - refined weight is `5`
  - inapplicable platform → `IsApplicable` is false
  - against real Windows 11 content (`-Tag Content`): profile `xccdf_mil.disa.stig_profile_MAC-1_Classified` selects 257 rules (SCC's rule-result count for that stream)
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: XCCDF profile resolution and CPE applicability`.

### Task 14: XCCDF rule evaluation and scoring

**Files:**
- Create: `src/PowerSCAP/Engine/Xccdf/RuleEvaluator.cs`, `src/PowerSCAP/Engine/Xccdf/Scoring.cs`, `tests/Xccdf.Eval.Tests.ps1`

**Interfaces:**
- Produces:
  - `enum XccdfResult { Pass, Fail, Error, Unknown, NotApplicable, NotChecked, NotSelected, Informational, Fixed }`
  - `class RuleResult { ResolvedRule Rule; XccdfResult Result; List<DefinitionResult> OvalResults; string CheckSystem; string Message; }`
  - `List<RuleResult> RuleEvaluator.Evaluate(ScapContent content, ResolvedProfile profile, CollectorRegistry collectors, IProgress<ScanProgress> progress)`. Behavior:
    - Not selected → `NotSelected`. Platform not applicable → `NotApplicable`.
    - OVAL `check` → map the definition result per SP 800-126r3: true→Pass, false→Fail, unknown→Unknown, error→Error, not evaluated→NotChecked, not applicable→NotApplicable. Then apply `check/@negate`.
    - `check-export` → OVAL external variables from profile values.
    - `multi-check="true"` → one result per definition.
    - `complex-check` → XCCDF operator table.
    - OCIL-only rules → `NotChecked`.
    - Role `unscored` is still evaluated; role `unchecked` → `NotChecked`.
  - `class ScanProgress { int Done; int Total; string CurrentRuleId; }`
  - `class Score { string System; double Value; double Maximum; }`
  - `List<Score> Scoring.Compute(ResolvedProfile profile, List<RuleResult> results)`. It covers `urn:xccdf:scoring:default`, `flat`, `flat-unweighted` and `absolute` per XCCDF 1.2 §7.3. Error and Unknown count as not passing; NotApplicable, NotChecked, NotSelected and Informational are excluded.

- [ ] **Step 1:** Write the scoring tests with SCC's observed numbers:
  - 194 Pass + 40 Fail + 13 NotApplicable + 10 NotChecked, all weight 10, flat group structure: `default` = 82.9059829059829 (max 100), `flat` = 1940 (max 2340), `flat-unweighted` = 194 (max 234), `absolute` = 0 (max 1).
  - 17 Pass + 3 Error → `default` = 85 (SCC's Firewall result).
  - all Pass → `absolute` = 1.

  Then the evaluation tests on mini content: negated check flips pass/fail; OVAL `not evaluated` → NotChecked.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: XCCDF rule evaluation and scoring`.

### Task 15: XCCDF results output and the scan cmdlet

**Files:**
- Create: `src/PowerSCAP/Engine/Xccdf/ResultsWriter.cs`, `src/PowerSCAP/Public/Invoke-PowerScapScan.ps1`, `tests/Scan.Tests.ps1`
- Modify: `src/PowerSCAP/PowerSCAP.psm1` (dot-source `Public/*.ps1`, export functions)

**Interfaces:**
- Produces:
  - `void ResultsWriter.WriteXccdf(ScapContent content, ResolvedProfile profile, List<RuleResult> results, List<Score> scores, TargetInfo target, string path)`. It writes an XCCDF 1.2 `Benchmark` copy containing one `TestResult`, with `rule-result` (`result`, `check` with `check-content-ref`, `ident`s), `target`, `target-address`, `target-facts`, `score` and `set-value`. The structure must be loadable by `Compare-XccdfResults` (Task 16) and by SCC's own consumers.
  - `class TargetInfo { string HostName; string Fqdn; List<string> Addresses; string OsName; string OsVersion; string Identity; bool Privileged; }` with `TargetInfo.Collect()`.
  - `Invoke-PowerScapScan -ContentPath <string> [-ProfileId <string>] -OutputPath <string> [-PassThru]`:
    - Requires elevation; throws `"PowerSCAP must run elevated."` otherwise.
    - The default profile is the first profile in the benchmark.
    - Writes `<OutputPath>\<host>_<benchmarkShortName>_<yyyyMMdd_HHmmss>_XCCDF-Results.xml`.
    - With `-PassThru`, returns `[pscustomobject]@{ BenchmarkId; ProfileId; Scores; Results }`.

- [ ] **Step 1:** Write tests:
  - mini content scan writes a file whose `TestResult/rule-result` count equals the selected rule count and whose `score[@system='urn:xccdf:scoring:default']` matches `-PassThru`
  - non-elevated run throws the exact message (run in a child `powershell.exe` with a filtered token via `runas /trustlevel:0x20000`, or skip when that's unavailable)
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests elevated. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: XCCDF results writer and Invoke-PowerScapScan`.

### Task 16: Parity harness and acceptance run

**Files:**
- Create: `tools/Compare-XccdfResults.ps1`, `tests/Parity.Tests.ps1`, `docs/parity.md`

**Interfaces:**
- Consumes: XCCDF result files from Task 15 and SCC (`%USERPROFILE%\SCC\Sessions\<session>\Results\SCAP\XML\*_XCCDF-Results_*.xml`).
- Produces: `tools/Compare-XccdfResults.ps1 -Reference <file> -Actual <file>`. It outputs one object per rule id in either file: `{RuleId, Reference, Actual, Match}`, plus a summary line `"<n> rules, <m> mismatches"`, and exits with code 1 on any mismatch.

- [ ] **Step 1:** Write tests:
  - two identical files → 0 mismatches
  - one changed `result` → exactly that rule reported
  - rule present only in the reference → reported with `Actual = '(missing)'`
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Acceptance run (elevated):
  - For each of the 7 benchmarks: `Invoke-PowerScapScan -ContentPath tests/content/<zip> -ProfileId xccdf_mil.disa.stig_profile_MAC-1_Classified -OutputPath out/`, then compare against the matching file in SCC session `2026-10-15_210812`.
  - Record every mismatch in `docs/parity.md` with rule id, both results, the OVAL test details, and a verdict: *engine bug* (fix it with a regression test in the owning task's test file) or *machine state changed since the SCC scan* (with evidence, e.g. the setting's current value).
  - Done when every mismatch has a verdict and no *engine bug* remains open.
- [ ] **Step 6:** Commit: `test: parity harness and acceptance results`.
