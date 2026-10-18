# Security Policy

## Supported versions

PowerSCAP is pre-1.0. Only the latest commit on `master` is supported. Please update before you report an issue.

## Reporting a vulnerability

Please **do not** open a public issue for a security vulnerability.

Use GitHub's private vulnerability reporting instead: open the
**[Report a vulnerability](../../security/advisories/new)** form on the Security tab. It reaches the maintainers
privately, so a fix can be coordinated before anything is disclosed publicly.

Include what you would put in any good bug report: the affected commit, steps to reproduce, and the impact as
you understand it. We will acknowledge your report as soon as we can and keep you updated.

## Scope

PowerSCAP runs elevated and reads the configuration of the machine it runs on. It downloads SCAP content from
NIST's National Checklist Program over HTTPS and writes reports to a folder you choose. It never changes system
configuration.

Relevant reports include:

- Crafted SCAP content (data stream, zip, OVAL or XCCDF) that causes code execution, writes outside the output
  or cache folders, or runs a program other than the System32 executables described in
  [CODEBASE_MAP.md](CODEBASE_MAP.md#no-script-execution).
- A way to make a scan run a PowerShell or cmd command supplied by the content.
- Content with an invalid or tampered XML signature being scanned without the operator's override.
- Script or markup injection through collected values or content text in the HTML reports.
- Path traversal through zip entries or cache manifest fields.
- A dependency or Windows API misuse that can actually be reached from this code.

Out of scope:

- Findings about the scanned machine's own configuration. Reporting those is what PowerSCAP is for.
- Attacks that need an attacker who is already an administrator on the machine.
