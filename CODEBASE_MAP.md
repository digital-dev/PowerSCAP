# Codebase map

This map is for someone opening PowerSCAP for the first time. It covers:

- how a scan flows through the code;
- where each part lives;
- the rules every change has to keep, and why each rule exists.

Read it before you change the engine.

## The layers

```
Start-PowerScapGui / Invoke-PowerScapScan          PowerShell: thin commands (src/PowerSCAP/Public)
        |
   Gui/*ViewModel  ----------------+               C#: WPF view-models over loose XAML (no code-behind)
        |                          |
   Scan/ScanRunner          Content side: Ncp/NcpClient -> Cache/ContentCache -> Content/SignatureVerifier
        |                                 Profile/SystemProfile + BenchmarkMatcher, Cache/UpdateChecker,
        |                                 Cache/SccContent (an installed SCC's bundled content, for import)
   Content/ScapContentLoader   (data stream -> XCCDF benchmark + OVAL/CPE/OCIL components)
        |
   Xccdf/ProfileResolver -> Xccdf/RuleEvaluator -> CpeApplicability
        |                         |
        |                   Oval/OvalEvaluator   definitions, tests, criteria (OvalLogic)
        |                         |
        |                   Oval/ObjectEvaluator  object sets, filters, variables (VariableResolver)
        |                         |
        |                   Oval/Collectors/*     one ICollector per OVAL object type
        |                         |
        |                   Oval/StateEvaluator + OvalOps   states, datatypes, operations
        |
   Xccdf/Scoring, Xccdf/ResultsWriter (XCCDF 1.2)
   Reports/ReportModel -> HtmlReport, CklbWriter, OvalResultsWriter, ArfWriter, SummaryReport
   Scan/ScanHistory (JSON per scan, for the app)
```

`Import-PowerScapEngine` (in `PowerSCAP.psm1`) compiles everything under `Engine/` with `Add-Type`. The DLL is
named by a hash of the sources and cached in `%LOCALAPPDATA%\PowerSCAP\bin`. The app's view-models under `Gui/`
compile the same way into a second DLL that references the engine.

Under PowerShell 7 the same sources compile against .NET's reference assemblies (`$PSHOME\ref`) plus the Windows
packages PowerShell ships, into `bin\pwsh`. .NET has no `System.Web.Extensions`, so `Compat\JavaScriptSerializer.cs`
(compiled only there) stands in for the JSON serializer and writes the same JSON, so files are shared between editions.

.NET cannot unload an assembly. A PowerShell window that loaded an older engine keeps running it, and the
module warns when this happens. **After you change C#, test in a new PowerShell window.**

## A scan, step by step

1. `ScanRunner.Run` verifies the content's XML signature. Invalid content is refused unless the operator
   overrides it, and the override is written into the results.
2. `ScapContentLoader` resolves the data stream's catalog, so every check `href` points at a loaded component.
3. `ProfileResolver` applies the profile: `extends`, selections, refined values and weights.
4. `RuleEvaluator`, per rule:
   - selection, then CPE applicability;
   - then the check: OVAL, complex-check or OCIL (OCIL-only rules stay *notchecked*).
   - It checks for cancellation between rules.
5. `OvalEvaluator` evaluates definitions and tests. Each test's object goes through `ObjectEvaluator`, which:
   - expands variables;
   - applies set operations and filters;
   - asks the registered `ICollector` for items.
   Objects are memoized by id within a scan.
6. `Scoring` computes the four standard XCCDF scoring models.
7. Nothing is written until evaluation finishes, so a cancelled scan leaves no files. Then the XCCDF results,
   the `ReportModel` and every requested format are written.

## Where things live

| Path | What |
|---|---|
| `Engine/Oval/OvalLogic.cs` | Operator, existence and check truth tables (OVAL 5.11.2 §5.3) |
| `Engine/Oval/OvalOps.cs` | Datatype comparisons and pattern match (POSIX classes, .NET regex quirks) |
| `Engine/Oval/StateEvaluator.cs` | `entity_check`, `var_check`, `check_existence` for states and filters |
| `Engine/Oval/VariableResolver.cs` | Constant, local and external variables and every OVAL function |
| `Engine/Oval/Collectors/ICollector.cs` | `ICollector`, `CollectorRegistry.CreateDefault()` (the list of supported object types) |
| `Engine/Oval/Collectors/FileSystemCache.cs`, `RegistryTreeCache.cs` | Per-scan directory and registry listings shared by every object |
| `Engine/Oval/Collectors/NativeShell.cs`, `NativeCmdlets.cs` | Native answers to commands embedded in content (see below) |
| `Engine/Native/*.cs` | P/Invoke: LSA, Authz effective rights, NetApi, registry hives |
| `Engine/Reports/FindingDetails.cs` | The SCC-style "expected vs. collected" text shown for each rule |
| `Engine/Review/ManualChecks.cs`, `ManualCheckFacts.cs` | Layer 2: native checks for manual rules (by STIG ID) and the machine facts they read |
| `Engine/Reports/AnswerStore.cs`, `OcilQuestions.cs` | Layer 3: stored answers per machine and STIG ID; the content's OCIL question for a manual rule |
| `Gui/Views/MainWindow.xaml`, `Gui/Themes/*.xaml` | The whole UI. Colors are theme tokens used through `DynamicResource` |

## Rules a change must keep

### Results match a validated scanner

Any rule whose result differs from SCC's, for the same content on the same machine state, is a bug until proven
otherwise. Proof goes in [docs/parity.md](docs/parity.md) with a verdict. Use `tools\Invoke-ParityRun.ps1` or
`tools\Compare-XccdfResults.ps1` to produce the diff.

### Findings follow the STIG

Sometimes a strict reading of the OVAL contradicts what the STIG says is a finding. For example, a filter
written with the default `var_check="all"` would exclude nothing. In those cases PowerSCAP reports what the STIG
says, keeps the change narrow (filters only, not test states), and documents it in `docs/parity.md`.

### No script execution

SCAP content embeds PowerShell and cmd snippets (`cmdlet_object`, `shellcommand_object`). Running them would
mean starting `powershell.exe` or `cmd.exe` with content-supplied text, which antivirus rightly treats as
suspicious and which runs code the user never reviewed. Instead:

- `NativeShell` and `NativeCmdlets` recognize each snippet and answer it in C# (WMI/CIM, registry, Win32),
  matching the original's output byte for byte (5.1 table formats included).
- A command with no native implementation is reported as *not collected*. It is never run.
  `tools\Get-CommandInventory.ps1` and the `Inventory` tests list any such command in the test content.
- The only external programs a scan starts are System32 executables: ones the content names directly (such as
  `icacls.exe`) and `secedit.exe`, which exports the security policy. They are started directly, without a shell,
  operators or redirection.

Never add a code path that runs a PowerShell script block or `cmd /c` during a scan. Never work around antivirus
or self-protection blocks: a denied read is an *error* result with its message.

### Collectors never throw

A collector that fails returns an `Error` item or flag with a message. One collector failure must never stop a
scan. Access denied, missing privileges and timeouts are all results.

### Review layers never touch SCAP

A manual rule keeps its SCAP result (`notchecked`); a `RuleReview` beside it carries the PowerSCAP check or the
answer, and `EffectiveResult` is what checklists and the app show. XCCDF, OVAL, ARF and the four scores use SCAP
results only; STIG completeness is computed separately. A new manual check follows its STIG check text literally and
decides only where that text states the outcome; anything needing judgement is evidence for the reviewer.

### Read-only

Nothing in PowerSCAP changes system configuration. Reports describe fixes; they never apply them.

### Code style

- **C# 5:** `Add-Type` uses the .NET Framework compiler, so no string interpolation, `nameof`, expression-bodied
  members or `?.`.
- **ASCII only inside C# string literals.**
- Comments explain *why*, at the density of the surrounding code.
- Windows PowerShell 5.1 for everything at run time. Tests run there too.

## Tests

- `tests/*.Tests.ps1` (Pester 3.4) cover the engine with small hand-written OVAL and XCCDF fixtures that have
  known answers (`tests/fixtures`). They also cover each collector against the live machine, outputs, content
  handling, and the app's view-models. The GUI is shown off screen, and the tests fail on any WPF binding error.
- Tests that need elevation, real SCAP content, the network, or a long time are tagged `Admin`, `Content`,
  `Online` and `Slow`.
- Passing the tests is necessary but not sufficient for an evaluation change. Run a parity comparison and say
  in the PR what you compared against.
