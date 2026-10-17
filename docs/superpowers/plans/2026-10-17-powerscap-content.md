# PowerSCAP Plan 2: Content Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** PowerSCAP finds the right SCAP benchmarks for this machine in NIST's National Checklist Program (NCP), downloads them into a versioned local cache, verifies their signatures, detects newer releases, and scans cached content offline.

**Architecture:**
- C# 5 in `PowerScap.Engine` does the work: an NCP catalog client, a content cache with a JSON manifest, an update checker, a signature verifier, a system profiler and a benchmark matcher.
- All network access goes through one `IHttpTransport` interface, so every test except those tagged `Online` runs from fixtures.
- Thin PowerShell cmdlets expose each piece. Plan 5's GUI calls the same cmdlets/classes.

**Tech Stack:** Windows PowerShell 5.1, .NET Framework 4.8 (C# 5 via `Add-Type`), `System.Net` (`HttpWebRequest`, TLS 1.2), `System.Web.Extensions` (`JavaScriptSerializer`), `System.Security.Cryptography.Xml` (`SignedXml`), Pester 3.4.

**Spec:** `docs/superpowers/specs/2026-10-16-powerscap-design.md` §5, §6.1, §6.2. Plan 1: `docs/superpowers/plans/2026-10-16-powerscap-engine.md`.

## Global Constraints

- Everything in Plan 1's Global Constraints still holds (PowerShell 5.1, C# 5 only, namespace `PowerScap.Engine`, no third-party binaries, no web or script hosts, collector failures never throw).
- **No script execution during scans** (spec §6.3): nothing in this plan starts PowerShell or cmd. System profiling uses the registry, WMI and the file system only.
- **NCP API** (no authentication):
  - Metadata: `https://ncp.nist.gov/public/service/rest/json/ncp/checklist/repository/metadata`
  - Search: `https://ncp.nist.gov/public/service/rest/json/ncp/checklist/repository/search/results?offset={o}&rowCount={n}&contentTypeIdList={ids}&keyword={k}&sortOrder=4&sortDirection=2`
  - Response shape: `response[0].grid` = `{ resultsPerPage, startIndex, totalResults, checklists[] }`. Each checklist: `checklistId, name, version, authority, lastModified, targets[], resources[]`. Each resource: `checklistResourceId, title, location, resourceTypeName`.
  - Content type ids: SCAP 1.2 = `14`, SCAP 1.3 = `17`, SCAP 1.4 = `29`. Resource type names: `"SCAP 1.4 Content"`, `"SCAP 1.3 Content"`, `"SCAP 1.2 Content"`.
- **Flavor:** NIWC enhanced SCAP 1.4 is the default, then DISA SCAP 1.3, then SCAP 1.2.
- **Cache location:** `%ProgramData%\PowerSCAP\content`, overridable with env `POWERSCAP_CACHEDIR` (tests always override).
- **Never replace cached content silently.** Old versions stay in the cache; the user picks when to download an update.
- **Offline:** listing and scanning cached content must never touch the network.
- **Downloads are user-initiated.** Tests never download benchmark zips. `Online` tests may only query NCP JSON and send `HEAD` requests.

## Review Focus

1. **NCP unreachable** (offline, DNS failure, timeout, HTTP 5xx, HTML error page instead of JSON): catalog calls fail with one clear `NcpException` message; cached content still lists and scans. *Test in Task 1.*
2. **Interrupted or bogus download** (connection drops, HTTP 404 page, a zip that holds no data stream): nothing enters the cache or manifest, and no partial file is left behind. *Test in Task 2.*
3. **Damaged cache** (manifest.json hand-edited into invalid JSON, a cached zip deleted): listing still works. A bad manifest is renamed `manifest.json.bad-<timestamp>` and rebuilt from the files present. Missing files show `Missing = true`. *Test in Task 2.*
4. **Odd NCP data** (`targets` or `resources` null or empty, the same checklist returned twice, a checklist with Linux and Windows 1.4 zips): skipped, deduplicated, and the Windows resource picked. *Test in Task 1.*
5. **Signature outcomes** (tampered content vs. valid content signed by a CA this machine doesn't trust): tampered content is `Invalid` and blocks the scan; an untrusted chain is `Valid` with `ChainTrusted = false` and scans. *Test in Task 3.*

---

### Task 1: NCP catalog client

**Files:**
- Create: `src/PowerSCAP/Engine/Ncp/NcpModels.cs`, `src/PowerSCAP/Engine/Ncp/NcpClient.cs`, `src/PowerSCAP/Engine/Ncp/HttpTransport.cs`
- Modify: `src/PowerSCAP/PowerSCAP.psm1` (add `'System.Web.Extensions'` to `$script:EngineReferences`)
- Fixture: `tests/fixtures/ncp/search-scap14.json` (already saved: the seven benchmarks the reference machine uses, real NCP data from 2026-10-17)
- Test: `tests/Ncp.Tests.ps1`

**Interfaces:**
- Produces:
  - `interface IHttpTransport { string GetString(string url); HttpHead Head(string url); void Download(string url, string destinationPath); }`. `HttpHead { int Status; string ETag; DateTime? LastModified; long? Length; }`.
  - `class HttpTransport : IHttpTransport`: `HttpWebRequest`, `SecurityProtocolType.Tls12`, 60 s timeout, `User-Agent: PowerSCAP/<EngineInfo.Version>`. Any `WebException`, timeout or non-2xx becomes `NcpException(url, message)`.
  - `class NcpChecklist { int Id; string Name; string Version; string Authority; DateTime LastModified; IList<string> Targets; IList<NcpResource> Resources; }`
  - `class NcpResource { int Id; string Title; string Location; string TypeName; string FileName /* last URL segment */; }`
  - `class NcpClient(IHttpTransport http)`:
    - `IList<NcpChecklist> Search(string keyword, int[] contentTypeIds)` pages with `rowCount=200` until `totalResults` is reached and deduplicates by `checklistId`.
    - `static NcpResource PickScapResource(NcpChecklist c)` picks the first of 1.4 / 1.3 / 1.2. Within a type, drop titles matching `(?i)linux|rhel|red hat|ubuntu|suse|macos|solaris|aix|hp-ux`. Returns null when nothing is left.
  - `class NcpException : Exception`

- [ ] **Step 1: Write the failing tests** in `tests/Ncp.Tests.ps1`. Use a PowerShell-side fake: an Add-Type class `FakeTransport : IHttpTransport` that maps URL substrings to file contents and records the URLs requested.
  - `It 'parses checklists, targets and resources'`: searching with the fixture gives 7 checklists; checklist 1028 has `Name` `'Microsoft Windows 11 STIG'`, `Targets[0]` `'Microsoft Windows 11'` and `LastModified` `2026-10-06 13:57:42.310`.
  - `It 'picks the Windows SCAP 1.4 resource'`: for checklist 356 the pick's `FileName` is `'U_MOZ_Firefox_Windows_V6R8_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip'`. For 1028 it is `'U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip'`.
  - `It 'falls back to SCAP 1.3'`: a checklist with only a `"SCAP 1.3 Content"` resource picks it.
  - `It 'deduplicates and skips null targets/resources'`: a fixture with checklist 356 twice and one checklist with `"targets": null, "resources": null` gives 356 once. The null checklist is returned with empty lists, and `PickScapResource` returns `$null` for it.
  - `It 'pages until totalResults'`: a fake with `totalResults: 3` served in pages of 2 issues 2 requests with `offset=0` and `offset=2`.
  - `It 'reports NCP failures as NcpException'`: the fake throws `NcpException` / returns `'<html>error</html>'`. `Search` throws `NcpException` with the URL in its message for both.
  - `Describe 'NCP live' -Tag Online`: a real `Search('Windows 11', @(29))` returns a checklist whose `Targets` contains `'Microsoft Windows 11'`.
- [ ] **Step 2: Run** `powershell -File build/Invoke-Tests.ps1 -Path tests/Ncp.Tests.ps1 -ExcludeTag Online`. Expected: FAIL (types not defined).
- [ ] **Step 3: Implement** the three files. Parse with `JavaScriptSerializer.DeserializeObject` into dictionaries, not typed classes, so missing fields are tolerated. `lastModified` parses with `DateTime.Parse(…, InvariantCulture)`.
- [ ] **Step 4: Run** the same command. Expected: PASS. Then run the full suite: `powershell -File build/Invoke-Tests.ps1 -ExcludeTag Admin,Slow,Online`. Expected: no failures.
- [ ] **Step 5: Commit** `feat: NCP catalog client`.

### Task 2: Versioned content cache

**Files:**
- Create: `src/PowerSCAP/Engine/Cache/ContentCache.cs`, `src/PowerSCAP/Engine/Cache/CacheEntry.cs`
- Test: `tests/Cache.Tests.ps1` (uses `tests/fixtures/content/mini-ds.xml` zipped on the fly as a stand-in benchmark)

**Interfaces:**
- Consumes: `IHttpTransport`, `NcpChecklist`, `NcpResource` (Task 1). `ScapContentLoader.Load(path)` (Plan 1).
- Produces:
  - `class CacheEntry { string Id /* sha256 first 16 hex */; int? ChecklistId; string ChecklistName; string ChecklistVersion; DateTime? NcpLastModified; string SourceUrl; string ResourceType; string FileName; string Sha256; string ETag; DateTime AddedUtc; string BenchmarkId; string BenchmarkVersion; string BenchmarkTitle; bool Imported; string RelativePath; bool Missing /* computed, not stored */; SignatureReport Signature /* Task 3; null until then */; }`
  - `class ContentCache(string root, IHttpTransport http)`, plus `static ContentCache OpenDefault(IHttpTransport http)` (root from `POWERSCAP_CACHEDIR`, else `%ProgramData%\PowerSCAP\content`):
    - `IList<CacheEntry> List()` returns entries newest first. It never touches the network.
    - `CacheEntry Download(NcpChecklist c, NcpResource r)`. The flow:
      1. Download to `<root>\.partial\<guid>.zip`.
      2. Compute SHA-256 and load the file with `ScapContentLoader.Load`.
      3. Fill the benchmark id, version and title, store the ETag from `Head(r.Location)`, and move the file to `<root>\<ChecklistId>\<sha16>_<FileName>`.
      4. Add the manifest entry.

      If the SHA-256 is already cached, return the existing entry and add no duplicate.
    - `CacheEntry Import(string path)` follows the same validation, stores under `<root>\imported\<sha16>_<name>`, and sets `Imported = true`.
    - `string PathOf(CacheEntry e)`
  - Manifest: `<root>\manifest.json`, written atomically (write `manifest.json.tmp`, then `File.Replace`). Use `JavaScriptSerializer`.
  - `class CacheException : Exception`

- [ ] **Step 1: Write the failing tests:**
  - `It 'downloads, validates and records a benchmark'`: the fake transport copies the zipped mini-ds and returns ETag `"abc"`. The entry has `BenchmarkId` from mini-ds, `ETag` `'"abc"'` and `ChecklistId` `1028`. `PathOf(entry)` exists, and `List().Count` is `1`.
  - `It 'keeps old versions'`: downloading two different zips for the same checklist gives `List().Count` `2`, and both files exist.
  - `It 'does not duplicate identical content'`: downloading the same bytes twice gives `List().Count` `1`.
  - `It 'rejects a download that is not SCAP content'`: the fake writes `'<html>404</html>'`, so `Download` throws `CacheException`, `List().Count` is `0`, and `<root>\.partial` is empty.
  - `It 'rejects an interrupted download'`: the fake writes half a file and then throws `NcpException`. Same assertions.
  - `It 'imports a local file'`: `Imported` is `$true` and `ChecklistId` is `$null`.
  - `It 'survives a corrupt manifest'`: overwrite manifest.json with `'{not json'`. `List()` returns the entries rebuilt from the cached zips (`BenchmarkId` filled), and a `manifest.json.bad-*` file exists.
  - `It 'flags missing files'`: delete a cached zip, then `List()[0].Missing` is `$true`.
  - `It 'lists without network'`: a transport whose every method throws still gets `List()` working.
- [ ] **Step 2: Run** `powershell -File build/Invoke-Tests.ps1 -Path tests/Cache.Tests.ps1`. Expected: FAIL.
- [ ] **Step 3: Implement.** Rebuilding a corrupt manifest walks `<root>\**\*.zip` and `*.xml` (excluding `.partial`), loads each one, and recovers `ChecklistId` from the folder name when it is numeric.
- [ ] **Step 4: Run.** Expected: PASS. Then run the full suite (as in Task 1). Expected: no failures.
- [ ] **Step 5: Commit** `feat: versioned content cache with manifest`.

### Task 3: Signature verification

**Files:**
- Create: `src/PowerSCAP/Engine/Content/SignatureVerifier.cs`
- Modify: `src/PowerSCAP/Engine/Cache/ContentCache.cs` (verify on `Download`/`Import`, store the `Signature` on the entry), `src/PowerSCAP/PowerSCAP.psm1` (no new reference: `System.Security` already carries `SignedXml`)
- Test: `tests/Signature.Tests.ps1`

**Interfaces:**
- Produces:
  - `enum SignatureState { Unsigned, Valid, Invalid }`
  - `class SignatureReport { SignatureState State; string Signer /* cert Subject */; string Thumbprint; DateTime? NotAfter; bool ChainTrusted; string Message; }`
  - `static class SignatureVerifier { SignatureReport Verify(string contentPath /* .zip or .xml */); SignatureReport Verify(XmlDocument doc); }`
- Facts the implementer needs:
  - NIWC data streams carry one enveloped `ds:Signature` (Reference `URI=""`) whose canonicalization and transform are **C14N 1.1** (`http://www.w3.org/2006/12/xml-c14n11`). .NET Framework's `SignedXml` does not implement it. Register it as an alias of `XmlDsigC14NTransform` (C14N 1.0) with `CryptoConfig.AddAlgorithm(typeof(XmlDsigC14NTransform), "http://www.w3.org/2006/12/xml-c14n11")`, and add the URI to `SignedXml.SafeCanonicalizationMethods`. The two differ only in `xml:id`/`xml:base` inheritance, which a whole-document enveloped signature never exercises.
  - Load with `PreserveWhitespace = true`, `DtdProcessing.Prohibit`, `XmlResolver = null`.
  - The signer is a DoD ID CA certificate. Many machines do not trust the DoD roots, so chain trust is reported, not required. `ChainTrusted` comes from `X509Chain.Build` with revocation mode `NoCheck`, so verification stays offline.
  - Documents with no `ds:Signature` (DISA SCAP 1.3) are `Unsigned`.
- [ ] **Step 1: Write the failing tests:**
  - `It 'validates each NIWC benchmark' -Tag Content`: for each `tests/content/*.zip`, `State` is `'Valid'` and `Signer` matches `'NIWC'`.
  - `It 'detects tampering' -Tag Content`: load the Edge data stream, change one rule title's text, then `Verify(doc).State` is `'Invalid'`.
  - `It 'reports unsigned content'`: `Verify('tests/fixtures/content/mini-ds.xml').State` is `'Unsigned'`.
  - `It 'signs and verifies a fixture with a self-signed cert'`: create the cert in memory with `New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My`, sign mini-ds in the test with `SignedXml`, verify it (`Valid`, `ChainTrusted` `$false`), and remove the cert in `finally`.
  - `It 'records the signature in the cache'`: a cache download of the Edge zip (fake transport copying the file) has `Signature.State` `'Valid'`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** Pick the signature element with `GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)`. More than one signature means `Invalid` with the message "multiple signatures".
- [ ] **Step 4: Run.** Expected: PASS (with the `Content` tag included). Then run the full suite. Expected: no failures.
- [ ] **Step 5: Commit** `feat: verify SCAP content XML signatures (C14N 1.1)`.

### Task 4: Update detection

**Files:**
- Create: `src/PowerSCAP/Engine/Cache/UpdateChecker.cs`
- Test: `tests/Updates.Tests.ps1`

**Interfaces:**
- Consumes: `NcpClient`, `ContentCache`, `CacheEntry` (Tasks 1–2).
- Produces:
  - `enum UpdateState { Current, UpdateAvailable, NotInCatalog, CheckFailed }`
  - `class UpdateInfo { CacheEntry Cached; NcpChecklist Checklist; NcpResource Latest; UpdateState State; string Reason; }`
  - `class UpdateChecker(NcpClient ncp, IHttpTransport http) { IList<UpdateInfo> Check(IList<CacheEntry> cached); }`
- Rules (one result per `ChecklistId`, judged against the newest cached entry for it; imported entries are skipped):
  - The checklist is absent from NCP: `NotInCatalog`.
  - `PickScapResource` gives a different `FileName` than cached: `UpdateAvailable`, Reason `"new release <FileName>"`. Compare file names, not the checklist `version`, because NCP's STIG version can be ahead of the enhanced zip (Windows 11 checklist "Ver 2, Rel 11" still ships `…V2R10…enhancedV18`).
  - Same file name but `Head(location).ETag` differs from the cached ETag (and both are non-empty): `UpdateAvailable`, Reason `"republished"`.
  - Otherwise: `Current`.
  - An `NcpException` marks every entry `CheckFailed` with its message. It never throws.
  - Cached content is never modified.
- [ ] **Step 1: Write the failing tests**, one per rule above, using the fake transport plus the Task 2 cache. Add `It 'does not touch the cache'`, which checks the manifest bytes are identical before and after `Check`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** Use one `Search("", {29,17,14})` per `Check` call, not one call per entry.
- [ ] **Step 4: Run.** Expected: PASS. Then run the full suite. Expected: no failures.
- [ ] **Step 5: Commit** `feat: detect updated SCAP content`.

### Task 5: System profile

**Files:**
- Create: `src/PowerSCAP/Engine/Profile/SystemProfile.cs`
- Test: `tests/Profile.Tests.ps1`

**Interfaces:**
- Produces:
  - `class DetectedProduct { string Name; string Version; string NcpTarget; string Evidence /* e.g. registry path */; }`
  - `class SystemProfile { string ComputerName; string OsCaption; string OsBuild /* e.g. 10.0.26200 */; string OsEdition; string Architecture; bool DomainJoined; string DomainOrWorkgroup; IList<DetectedProduct> Products; static SystemProfile Collect(); }`
- Detection sources (registry 64-bit view and WMI only):
  - OS caption and build: `Win32_OperatingSystem`.
  - Edition: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EditionID`.
  - Domain: `Win32_ComputerSystem.PartOfDomain` / `Domain`.
  - Installed programs: `HKLM\…\Uninstall`, `HKLM\SOFTWARE\WOW6432Node\…\Uninstall` and `HKCU\…\Uninstall` (`DisplayName`, `DisplayVersion`).
- Product → NCP target (exact strings from NCP):

  | Product | Detected when | `NcpTarget` |
  |---|---|---|
  | Windows 11 | caption contains `Windows 11` | `Microsoft Windows 11` |
  | Windows 10 | caption contains `Windows 10` | `Microsoft Windows 10` |
  | Edge | `HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}` `pv` | `Microsoft Edge` |
  | Chrome | Uninstall `DisplayName` `Google Chrome` | `Google Chrome` |
  | Firefox | Uninstall `DisplayName` starting with `Mozilla Firefox` | `Mozilla Firefox` |
  | .NET Framework 4 | `HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full` `Release` present | `Microsoft .NET Framework 4.0` |
  | Defender Antivirus | service `WinDefend` exists | `Microsoft Windows Defender` |
  | Defender Firewall | service `mpssvc` exists | `Windows Firewall` |
- Office and IIS (spec §6.2) are added the same way: first read their exact target strings from the NCP metadata endpoint, then add a table row and a test. Do not guess target names.
- [ ] **Step 1: Write the failing tests:**
  - `It 'describes this machine'`: `OsBuild` matches `^10\.0\.\d+$`, and `ComputerName` is `$env:COMPUTERNAME`.
  - `It 'detects Windows, Defender and Firewall'`: `Products.NcpTarget` contains `'Windows Firewall'` and `'Microsoft Windows Defender'`, plus `'Microsoft Windows 11'` when the caption says Windows 11.
  - `It 'detects Edge when installed'`: the test's own check of the EdgeUpdate key decides the expected outcome.
  - `It 'detects .NET Framework 4'`: always true on a supported OS.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** Each detector catches its own exceptions and records nothing on failure.
- [ ] **Step 4: Run.** Expected: PASS. Then run the full suite. Expected: no failures.
- [ ] **Step 5: Commit** `feat: system profile and product detection`.

### Task 6: Benchmark matching

**Files:**
- Create: `src/PowerSCAP/Engine/Profile/BenchmarkMatcher.cs`
- Test: `tests/Matcher.Tests.ps1`

**Interfaces:**
- Consumes: `SystemProfile`, `DetectedProduct` (Task 5). `NcpChecklist`, `NcpClient.PickScapResource` (Task 1).
- Produces:
  - `class BenchmarkMatch { NcpChecklist Checklist; NcpResource Resource; DetectedProduct Product; }`
  - `static class BenchmarkMatcher { IList<BenchmarkMatch> Match(SystemProfile p, IList<NcpChecklist> catalog); }`
- Rule: a checklist matches when one of its `Targets` equals (case-insensitive) a product's `NcpTarget` and `PickScapResource` returns non-null. Results are ordered by checklist name. This is a pre-tick only; CPE applicability still decides at scan time (spec §6.2).
- [ ] **Step 1: Write the failing tests** with the Task 1 fixture and a hand-built profile containing all eight products. The match has exactly the seven checklist ids `1028, 807, 356, 686, 483, 986, 432`; Windows 10 matches nothing in the fixture; and a profile with only Chrome matches only `483`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS. Then run the full suite. Expected: no failures.
- [ ] **Step 5: Commit** `feat: match NCP benchmarks to the system profile`.

### Task 7: Content cmdlets and scan integration

**Files:**
- Create: `src/PowerSCAP/Public/Content.ps1`
- Modify:
  - `src/PowerSCAP/Public/Invoke-PowerScapScan.ps1`
  - `src/PowerSCAP/Engine/Xccdf/ResultsWriter.cs` (signature remark)
  - `src/PowerSCAP/PowerSCAP.psd1` (exports)
  - `README.md` (a short "Content" section)
- Test: `tests/ContentCmdlets.Tests.ps1`

**Interfaces:**
- Consumes: everything above.
- Produces these cmdlets (all accept `-CacheRoot` for tests; the default is the `ContentCache.OpenDefault` root):
  - `Get-PowerScapSystemProfile` → `SystemProfile`
  - `Find-PowerScapBenchmark [-Keyword <string>] [-MatchSystem]` → `NcpChecklist` (with `-MatchSystem`: `BenchmarkMatch`)
  - `Save-PowerScapBenchmark -Checklist <NcpChecklist> | -Match <BenchmarkMatch>` → `CacheEntry` (pipeline input; this is the only cmdlet that downloads)
  - `Import-PowerScapBenchmark -Path <string>` → `CacheEntry`
  - `Get-PowerScapBenchmark [-Latest]` → `CacheEntry` (offline; with `-Latest`, one entry per checklist/benchmark id)
  - `Test-PowerScapBenchmarkUpdate` → `UpdateInfo`
  - `Invoke-PowerScapScan` gains a `-Benchmark <CacheEntry>` parameter set (pipeline input), which scans `PathOf(entry)`. It also gains `-AllowInvalidSignature`. Behavior:
    - Before the scan it verifies `ContentPath` (or the entry). `Invalid` throws `"Signature check failed for <file>: <message>. Re-download the content or pass -AllowInvalidSignature."`
    - With the override, the scan runs, and the TestResult gets `<remark>Signature verification failed and was overridden by the operator: <message></remark>`.
    - `Unsigned` and untrusted-chain content scans normally.
- [ ] **Step 1: Write the failing tests** (fake transport injected through a module-scoped `$script:PowerScapHttp` that tests set):
  - `It 'saves a matched benchmark into the cache'`
  - `It 'lists cached benchmarks offline'`: `$script:PowerScapHttp` throws on every call, and `Get-PowerScapBenchmark` still works.
  - `It 'scans a cached benchmark'`: `Get-PowerScapBenchmark | Select -First 1 | Invoke-PowerScapScan -AllowUnelevated -PassThru` with mini-ds gives results.
  - `It 'refuses tampered content and records an override'`: a tampered, signed fixture (built as in Task 3) throws the message above. With `-AllowInvalidSignature`, the result XML contains the remark.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full suite including `Content`: `powershell -File build/Invoke-Tests.ps1 -ExcludeTag Admin,Slow,Online`. Expected: no failures.
- [ ] **Step 5: Commit** `feat: content cmdlets; scans verify signatures`.
