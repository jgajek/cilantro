# Read the result and choose an artifact

When a run finishes, answer three questions: **which file contains the code I need, what was recovered in that file, and what still needs investigation?** Start with **OUTPUT**, then inspect the recommended artifact's own report.

## Read the console summary

| Section | What to do |
| --- | --- |
| Result | Check whether the run wrote a cleaned assembly, completed analysis only or stopped short. |
| Output | Open the recommended assembly and HTML report. |
| Needs review | Start with failures or reconstruction differences affecting your target stage. |
| Artifacts | Follow the wrapper, loaded assemblies, resources and dependencies. |
| What changed in the input | See the bodies, strings, calls and control flow recovered in this input. |
| Remaining | Find the unresolved work and assumptions relevant to your investigation. |
| Validation | Check structural verification and any VM comparison results. |
| Next | Use the suggested next action to continue the case. |

The HTML report has expandable details. Add `--verbose` when you need pass diagnostics; scripts should use `--json` and the [JSON contract](agents.md).

## Choose the right file

**Example:** a dropper's cleaned root may show only its loading routine. The useful payload code may be in a cleaned child DLL. A separate resource assembly may simply hold that DLL's encrypted source bytes.

| Artifact | How to use it |
| --- | --- |
| Cleaned input | Read the transformed wrapper or application supplied to the tool. |
| Extracted original | Preserve recovered bytes and use them for an independent child trial. |
| Cleaned child | Read a recovered managed stage; check its own remaining work and validation. |
| Restored resource bundle | Investigate the resources and their consumers. |
| Bundled dependency | Inspect the library's role and callers. |
| Native-wrapper stage | Follow the extracted managed assembly and its recovery result. |
| Preserved reviewed dependency | Use the unchanged bytes and recorded reference identity. |

The recommendation favors an assembly observed at a load operation over a resource bundle. Use the graph and hashes to follow the chain; one deduplicated child can have several parents.

A native root can have a null `Wrote.Cleaned` while its managed child has an output. A cleaned root can also have an incomplete child. If traversal stopped at a limit, continue from the child's extracted original in a separate trial.

## Interpret validation without losing useful results

| Signal | What it tells you | What to inspect next |
| --- | --- | --- |
| Cleaned file written | The emission policy allowed an analysis copy. | Open the relevant methods and read remaining issues. |
| `Success: true` | The run met its configured success policy. | Review the child results and recovery qualifications. |
| `Verified: true` | Structural checks passed. | Check the code and any reconstruction comparisons for the behavior you need. |
| `RebuiltCheck: agreed` | Captured reconstruction observations matched. | Read which inputs, paths and state the trial covered. |
| `RebuiltCheck: disagreed` | An observed state or outcome differed. | Investigate the first difference. |
| `RebuiltCheck: notMade` | Comparison did not establish agreement. | Look for an unexercised path, unsupported operation or budget limit. |

**Example:** a decoded command handler can be readable and structurally verified while another method's VM comparison disagrees. The handler is still useful evidence; retain the disagreement and investigate the affected path separately.

A successful run is not a blanket verdict that every protection is gone or that behavior matches on every input. The [VM guide](devirtualization.md) explains how to assess reconstructed methods and differences in startup state.

## Understand residual code and warnings

| What remains | How to investigate it |
| --- | --- |
| Switches | Follow their selectors and targets. Application decisions and async/iterator state machines can be legitimate. |
| Tiny methods | Check the original body and callers. Returning zero or null can be application logic. |
| Resources | Trace their consumers. Icons, payloads and dependencies may still be required. |
| Calls beside recovered strings/constants | Check whether they preserve initialization or other effects. |
| Replacement names | Use `NAME.renames.json` to find the original declaration. |
| Decompiler warnings | Identify the exact artifact and method, then inspect the CIL and validation details. |

String counts generally describe call sites or uses, rather than distinct strings. `HostProfile` records consulted environment facts; `ContinuedPast` records unsupported calls passed during permissive interpretation.

Blockers record stops encountered during recovery. A later route can recover the same content, or cleanup can remove the protector routine that encountered the stop. Correlate a blocker with the final result before deciding it is unresolved application work.

## Keep the useful outputs

Read actual paths from `Wrote`. These names are typical:

| File or directory | Use |
| --- | --- |
| `NAME.report.html` | Offline report and artifact links |
| `NAME.analysis.json` | Detailed recovery, protection and verification results |
| `NAME.changes.json` | Changes and affected locations |
| `NAME.blockers.json` | Interpretation stops and suggested remedies |
| `NAME.renames.json` | Original-to-replacement names |
| `NAME.config.json` | Recovered constants, when available |
| `NAME.embedded.json` | Child nodes, links, hashes, statuses and manifests |
| `NAME.status.json` | CLI progress and terminal state; opt-in for core callers |
| `NAME.virtualized/` | VM programs and lifted IL listings |
| Extracted files and cleaned assemblies | Recovered original bytes and transformed analysis copies |

Keep the report with its referenced files. Continue with [analyst workflows](analyst-workflows.md) to investigate the recovered behavior or [troubleshooting](troubleshooting.md) when a result needs another trial.
