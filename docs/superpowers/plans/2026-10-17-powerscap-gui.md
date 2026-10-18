# PowerSCAP GUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A WPF desktop app over the existing engine: System, Content, Scan, Results and Settings screens, dark/light/follow-Windows themes, background scans with cancel, and scan history.

**Architecture:** Scan orchestration moves from `Invoke-PowerScapScan` into C# (`Engine/Scan/ScanRunner.cs`) so the cmdlet and the GUI run the same code. The GUI is a second assembly (`src/PowerSCAP/Gui/*.cs`, compiled on first launch like the engine, referencing it) holding view-models; views are loose XAML (`Gui/Views/*.xaml`, no `x:Class`) loaded with `XamlReader` and bound to the view-models through commands. PowerShell only compiles, loads and shows the window (`Start-PowerScapGui`). Scans run on a worker thread (no script runs during a scan, so no runspace is needed); progress is marshalled to the UI with `Progress<T>`.

**Tech Stack:** PowerShell 5.1, C# 5 via `Add-Type`, WPF (.NET Framework 4.x: PresentationFramework, PresentationCore, WindowsBase, System.Xaml), Pester 3.

**Spec:** docs/superpowers/specs/2026-10-16-powerscap-design.md §6.6 (also §6.1-6.2 content, §6.5 outputs).

## Global Constraints

- No script execution during scans; no web or script engines in the process.
- No modal dialogs during scans; the UI stays responsive and past results stay browsable while a scan runs.
- Dark "security console" theme by default (near-black background, teal accent, green/amber/red status); Light and Follow Windows selectable; the choice persists.
- C# 5 only; C# string literals ASCII only.
- Launch from a shortcut with no console window; scans need elevation, so the shortcut runs as administrator.
- Results must stay identical to the CLI (same `ScanRunner`).

## Review Focus

- A scan cancelled midway leaves no half-written result files and the UI returns to idle.
- The GUI started unelevated says so and offers to restart elevated instead of failing every check.
- No network (offline machine): System, cached Content, Scan and Results all work; update checks report "check failed", never block.
- A cached benchmark whose file is missing or whose signature is invalid cannot be scanned silently.
- A history file that fails to load (corrupt or from an older version) is skipped, not fatal.

---

### Task 1: ScanRunner (shared scan orchestration, cancel, history)

**Files:**
- Create: `src/PowerSCAP/Engine/Scan/ScanRunner.cs`, `src/PowerSCAP/Engine/Scan/ScanHistory.cs`
- Modify: `Engine/Xccdf/RuleEvaluator.cs` (CancellationToken overload), `Engine/Reports/ReportModel.cs` (public setters for JSON round trip), `Public/Invoke-PowerScapScan.ps1` (delegates)
- Test: `tests/Scan.Runner.Tests.ps1`

**Interfaces:**
- `[Flags] enum OutputFormats { None=0, Html=1, Cklb=2, Oval=4, Arf=8, All=15 }`
- `class ScanRequest { string ContentPath; string ProfileId; string OutputPath; OutputFormats Formats; bool AllowInvalidSignature; string DisplayName }`
- `class ScanRunner { ScanRunner(CollectorRegistry); BenchmarkReport Run(ScanRequest, IProgress<ScanProgress>, CancellationToken); static string WriteSummary(IList<BenchmarkReport>, string outputPath); string HistoryRoot }` — throws `ScanException` on invalid signature.
- `class ScanHistory { ScanHistory(string root); static string DefaultRoot(); string Save(BenchmarkReport); IList<HistoryEntry> List(); BenchmarkReport Load(string path) }`; env `POWERSCAP_HISTORYDIR`, default `%ProgramData%\PowerSCAP\history`.

- [ ] Tests: cancel token already cancelled → OperationCanceledException and no files in OutputPath; Run writes the same file kinds as the cmdlet; history Save/List/Load round-trips rule results, scores and target; corrupt history file is skipped by List.
- [ ] Implement; cmdlet keeps all existing tests green.
- [ ] Commit.

### Task 2: GUI assembly, themes, launcher

**Files:**
- Create: `src/PowerSCAP/Gui/*.cs` (ViewModelBase, RelayCommand, Settings, MainViewModel and per-screen view-models), `Gui/Views/MainWindow.xaml`, `Gui/Themes/Dark.xaml`, `Gui/Themes/Light.xaml`, `Gui/Themes/Controls.xaml`, `Public/Gui.ps1` (`Start-PowerScapGui`, `New-PowerScapShortcut`), `src/PowerSCAP/Start-PowerSCAP.ps1`
- Test: `tests/Gui.Tests.ps1`

**Interfaces:**
- `Import-PowerScapGui` compiles `Gui/*.cs` to `PowerScap.Gui.<hash>.dll` referencing the engine DLL and WPF.
- `GuiSettings { Theme ("Dark"|"Light"|"System"), CacheRoot, OutputPath, CheckUpdatesOnLaunch, Flavor ("1.4"|"1.3") ; static Load(path); Save(path) }` at `%LOCALAPPDATA%\PowerSCAP\settings.json`.
- `ThemeManager.Apply(ResourceDictionary appResources, string theme, string themeDir)`; System reads `HKCU\...\Themes\Personalize\AppsUseLightTheme`.
- `New-PowerScapShortcut [-Path]` writes a .lnk: `powershell.exe -NoProfile -STA -WindowStyle Hidden -File Start-PowerSCAP.ps1`, Run-as-administrator flag set.

- [ ] Tests: settings round-trip and defaults; theme resolution (System → Dark/Light from registry value); every XAML file parses with `XamlReader` against the view-models (no binding exceptions at load); shortcut has the runas flag.
- [ ] Commit.

### Task 3: Screens

- **System:** `SystemProfile.Collect()` on a worker; elevation banner with Restart-as-admin.
- **Content:** cached list (checkbox, title, version, signature, Detected badge = name matches a detected product, Update badge from `UpdateChecker` on demand or at launch), profile picker (profiles read from the content on a worker), NCP search + download (flavor preference), Import local file.
- **Scan:** per-benchmark rows with progress bar, current rule, status; Cancel; Open output folder. Benchmarks share one CollectorRegistry; summary page when more than one.
- **Results:** run picker (this session + history), score tiles per benchmark, findings grid filtered by status, CAT, source and text, detail side panel (discussion, check, fix, finding details = expected vs actual), buttons to open the HTML reports, checklist and folder; "changed since previous run" filter.
- **Settings:** theme (applies live), cache folder, output folder, update check on launch, content flavor.

- [ ] Tests: view-model filters (status/CAT/text) and changed-since-previous; Content view-model with the fake NCP transport; Scan view-model runs the mini fixture to completion and reports progress.
- [ ] Launch, screenshot each screen in dark and light, fix layout.
- [ ] Commit.
