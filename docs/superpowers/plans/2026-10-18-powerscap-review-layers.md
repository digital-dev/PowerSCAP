# PowerSCAP Review Layers (Plan 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Layers 2 and 3 of the design (§6.4): native checks that decide manual rules a script can decide, and guided
questions with stored answers for the rest, shown everywhere with their source, never changing SCAP results or scores.
Plus "evaluate anyway" for benchmarks whose platform check excludes the machine.

**Architecture:** A rule keeps its SCAP result untouched; a separate `RuleReview` (status, source, author, time, comment,
evidence) carries the layer 2/3 outcome. `ManualCheckLibrary` (C#, one class per STIG ID) runs during a scan on the
rules the content leaves manual. `AnswerStore` keeps answers per machine in `%ProgramData%\PowerSCAP\answers`. The
effective status (SCAP if decided, else answer, else script) feeds the checklist, the app and a separate STIG
completeness score; XCCDF/OVAL/ARF stay pure SCAP.

**Spec:** docs/superpowers/specs/2026-10-16-powerscap-design.md §6.4, §6.5, §6.6.

## Global Constraints

- SCAP results and the four XCCDF scores never change. XCCDF, OVAL and ARF output stay SCAP only.
- Every non-SCAP result is labelled: Script (PowerSCAP automated) or Answered by <user> <date>.
- Script checks follow the STIG check text literally; where judgement is needed they give evidence, not a verdict.
- No script execution: checks are native C# (registry, WMI, Win32), like the collectors.
- Answers are stored per machine, benchmark and rule (STIG ID), with the rule revision and a hash of the check text;
  a changed rule flags its answer for re-review instead of applying it silently.
- Read-only toward the system; answers live only in PowerSCAP's own store.

## Review Focus

- A rule decided by SCAP is never overridden by a script or an answer.
- An answer to a rule whose revision or check text changed is shown as "needs re-review", not as current.
- Answering needs write access to %ProgramData%; unelevated, the app says so and changes nothing.
- A script check that cannot read its source (access denied) leaves the rule Not Reviewed with the reason as evidence.
- Regenerated reports after an answer keep the scan's own SCAP results byte-for-byte in XCCDF.

---

### Task 1: Review model, answer store, OCIL questions
- `RuleReview { Status (XccdfResult), Source ("Script"|"Answer"), Author, When, Comment, Evidence, NeedsReReview }`;
  `RuleReport.Review`, `RuleReport.Question` (OCIL question_text, else check text), `RuleReport.EffectiveResult`,
  `RuleReport.EffectiveSource`.
- `AnswerStore(root)`: `Get/Save/Remove(host, benchmarkId, rule)`, `Apply(report)`; JSON per host; default
  `%ProgramData%\PowerSCAP\answers` (`POWERSCAP_ANSWERSDIR`).
- `BenchmarkReport.Completeness` (share of rules whose effective status is not Not Reviewed).
- Tests: round trip; revision change flags re-review; SCAP-decided rules ignore answers; completeness.

### Task 2: Manual check library (layer 2)
- `IManualCheck { string StigId; ManualCheckOutcome Check(ManualCheckContext) }`; outcome = decided status or
  evidence only. Checks: WN11-00-000400, -000065, -000085, -000060, -000075, -000035, -000080; WNFWA-000100;
  EDGE-00-000004/-000039/-000042/-000064; DTBC-0065; evidence-only for admin group, browser versions.
- Tests per check with injected facts (fake environment), plus live smoke tests.

### Task 3: Scan, reports, checklist
- ScanRunner applies layer 2 then answers before writing outputs. HTML: STIG completeness tile and a separate
  "Beyond SCAP" section; checklist: effective status, source in finding details, answer comment in comments.
- `ReviewWriter.Rewrite(report)` regenerates a run's HTML and checklist after answers change.

### Task 4: App
- Rule detail: question, evidence, choices (Finding / Not a Finding / Not Applicable / Not Reviewed), comment, Save;
  re-review flag. Source column and filter (SCAP, Script, Answered, Manual). Tile shows completeness.

### Task 5: Evaluate anyway
- `ScanRunner.RunOutsideScap` evaluates with platform applicability ignored into `_Outside-SCAP.html`, labelled,
  never in history, scores or checklists. App: button on a run whose rules are all Not Applicable.
