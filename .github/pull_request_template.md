## What and why

<!-- What does this change, and why? -->

## Testing

- [ ] `powershell -NoProfile -File build\Invoke-Tests.ps1 -ExcludeTag Admin,Slow,Online,Content` passes
- [ ] Also ran elevated and/or with real content (`Admin`, `Content` tags), if relevant
- [ ] Opened a new PowerShell window after changing C# (an old window keeps running the old engine)

## Effect on results (if any)

<!-- Does this change any rule's result? If so, say which benchmarks and content versions you compared
     against SCC (tools\Invoke-ParityRun.ps1 or tools\Compare-XccdfResults.ps1), on what machine state, and
     add the verdict to docs/parity.md. The rules in CODEBASE_MAP.md still apply: no script execution during
     scans, collectors never throw, findings follow the STIG. -->

---

By submitting this PR, I agree to license my contribution under the project's [GPL-3.0 license](../LICENSE).
