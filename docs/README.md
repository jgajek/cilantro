# Documentation

Start with the analyst workflow. These pages describe CILantro **1.0.0**; see the [release notes](releases/1.0.0.md) for features and validation scope.

The normal command is `cilantro sample.exe`. It follows embedded stages and keeps all artifacts in a fresh case folder; `-o DIR` chooses that folder. Follow **OUTPUT** when it finishes. See the [option reference](quick-start.md); `--help-all` lists specialist controls.

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

- [Protection removal: before and after](protection-removal.md): malware payload-loading and command-execution examples for Reactor and ConfuserEx, with captured evidence.
- [Virtualized methods](devirtualization.md): rebuilt CIL, listings, comparisons and their limits.
- [Recovery architecture](how-recovery-works.md): interpreter, recovery passes and emission checks.
- [How Reactor works](how-net-reactor-works.md) and [How ConfuserEx works](how-confuserex-works.md): protection background.
- [Validation scope and results](status-report.md): coverage, checks and their limits.
- [Corpus validation](corpus.md): manifests, static gates and reconstruction checks for contributors. It is not a list of commands required for routine malware triage.

## Build and release

[Development](development.md) covers builds, tests and local publishing. [Code organization](code-organization.md) maps the implementation. The [1.0.0 release notes](releases/1.0.0.md) describe the release.
