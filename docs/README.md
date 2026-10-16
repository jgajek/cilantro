# Documentation

Start with the analyst workflow. This tree targets **1.0.0**; the [preparation notes](releases/1.0.0.md) distinguish the new console presentation from the **0.10.6** recovery-validation baseline. These pages do not announce a published release.

## Analyze a sample

| Your question | Read |
| --- | --- |
| How do I install it and recover my first file? | [Quick start and CLI reference](quick-start.md) |
| Which output is the payload, and how do I follow another stage? | [Analyst workflows](analyst-workflows.md) |
| What do the summary, warnings and artifact states mean? | [Reading the output](reading-the-output.md) |
| Why did it stop, and what should I try next? | [Troubleshooting](troubleshooting.md) |
| Which protections are covered, and what remains outside scope? | [Support and limitations](compatibility.md) |
| How do I supply an environment fact, dependency or budget? | [Declarations](declarations.md) |
| How do I automate recovery? | [Automation and MCP](agents.md), [JSON schemas](../schema/README.md) |

## Investigate the recovery

- [Virtualized methods](devirtualization.md): rebuilt CIL, listings, comparisons and their limits.
- [Recovery architecture](how-recovery-works.md): interpreter, recovery passes and emission checks.
- [How Reactor works](how-net-reactor-works.md) and [How ConfuserEx works](how-confuserex-works.md): protection background.
- [Current corpus status](status-report.md): final 43-root decision, evidence summary and explicit scope. The investigation log below its summary is historical.
- [Corpus validation](corpus.md): manifests, static gates and reconstruction checks for contributors. It is not a list of commands required for routine malware triage.

## Build and release

[Development](development.md) covers builds, tests and release preparation. [Code organization](code-organization.md) maps the implementation. Read the [0.10.6 release notes](releases/0.10.6.md) for the current shipped changes.

[Completion progress](completion-progress.md), the older parts of the status report and [historical notes](history/README.md) preserve experiments. Their open-gap statements and counts describe the builds used at the time; use [compatibility](compatibility.md) for current support claims.
