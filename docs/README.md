# Documentation

Start with the question you are trying to answer about the sample. The normal command is `cilantro sample.exe`; follow **OUTPUT** to the recommended assembly and report when it finishes.

The [malware walkthrough](protection-removal.md) shows the approach in practice: explain the protection, compare the code, then follow the behavior it exposes. It includes VM lifting and reconstruction, PowerShell execution and in-memory payload loading.

## Work a case

| Your question | Read |
| --- | --- |
| How do I recover my first file and choose options? | [Quick start and CLI reference](quick-start.md) |
| Which stage contains the code I need? | [Analyst workflows](analyst-workflows.md) |
| Which file should I open, and what do the warnings mean? | [Reading the output](reading-the-output.md) |
| Can I read a VM-protected method? | [VM reconstruction](devirtualization.md) |
| Is the result sufficient for my investigation? | [Assess recovery completeness](completion-progress.md) |
| Why did recovery stop, and what can I try next? | [Troubleshooting](troubleshooting.md) |
| How do I supply a missing fact, dependency or budget? | [Declarations](declarations.md) |
| Which protection layers are covered? | [Support and limitations](compatibility.md) |

## Understand the protection

- [How recovery works](how-recovery-works.md): follow the wrapper, hidden code, calls, branches and extracted stages.
- [Recognize Reactor protection](how-net-reactor-works.md): identify method encryption, strings, proxies, flattening and VM stubs.
- [Recognize ConfuserEx protection](how-confuserex-works.md): connect encrypted sections, constants and dispatchers to recovered behavior.
- [Validation scope and results](status-report.md): understand the project's test evidence and how it relates to a new case.

## Automate or contribute

| Task | Reference |
| --- | --- |
| Collect cases in scripts or MCP | [Automation and MCP](agents.md), [JSON schemas](../schema/README.md) |
| Build and validate a change | [Development](development.md), [corpus validation](corpus.md) |
| Find the source for a behavior | [Code organization](code-organization.md) |
| Inspect a recovery rule's technical boundaries | [Implementation reference](assets/recovery-implementation-reference.md) |
| Investigate a detailed VM comparison | [VM validation reference](assets/vm-validation-reference.md) |
| Reproduce the walkthrough captures | [Evidence appendix](assets/protection-removal-notes.md) |

Published binaries are available from [Releases](https://github.com/jgajek/cilantro/releases). See the [1.0.4 release notes](releases/1.0.4.md) for that release's changes.
