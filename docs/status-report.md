# Validation scope and results

Use this page to understand what the project has tested. For your own case, start with the recovered behavior and the artifact's report; the [completeness guide](completion-progress.md) gives a practical review sequence.

The checks below answer different questions: can code be recovered, are extracted bytes preserved, is identified VM machinery gone, and do known benign programs still produce the expected results?

## Coverage

The pinned validation corpus accounts for **43 roots**, including **28 undamaged captured Reactor-tagged samples**. It contains protected inputs, extracted stages, negative controls and explicit generic-recovery cases. These are not 43 independent malware families.

| Check | Scope and recorded evidence |
| --- | --- |
| Root coverage | 37 ordinary recoveries, three declared negative controls and three successful explicit generic followups account for the 43 roots. |
| Physical VM removal | 18 inspected contexts cover 14 intact virtualized identities. Reconstructed application methods and retired protector bodies are accounted for. |
| Protector cleanup | 104 managed outputs were inspected with structural checks and dispositions for retained VM/proxy/string-resolver/guard/integrity/trial candidates. |
| Application preservation | Surviving-body, switch, reconstruction and payload checks distinguish application behavior from attributable protector infrastructure. |
| Payload chains | Required captured identities and payloads were accounted for across the roots. Reviewed dependency copies retain their bytes and recorded provenance. |

Support includes Reactor 6 samples, source-built Reactor 7.5 probes, and two pinned ConfuserEx samples. Configuration and implementation determine support; a protector version label alone is insufficient. An input damaged by another recovery tool is outside the undamaged-input scope and may remain unsupported.

## Apply this evidence to a case

A passing extraction hash check establishes the recovered bytes. A physical VM-removal check establishes that identified machinery is absent and reconstructed/retired bodies are accounted for. Structural verification checks the assembly. Controlled VM comparisons describe the inputs and state actually exercised.

For example, recovering a readable command handler is useful even if another path needs investigation. Record that specific result and keep the unresolved findings with it. The [output guide](reading-the-output.md) explains the report fields; the [VM guide](devirtualization.md) explains reconstruction comparisons.

These checks support the stated corpus scope. They do not establish behavior for every input or complete protection removal on an unfamiliar file.

## 1.0.2 release validation

The performance update passed all 2,931 tests with private fixtures available: zero failures or skips. Tests ran in `C:/cilantro-verify`. Two optimized pinned-corpus runs each passed all 24 cases, and all 110 detailed reports/listings matched the original build after excluding pass durations and output paths. Corpus wall time fell by 59.5% on the measured host; see the [performance report](performance.md) for the complete measurements and GC tradeoff.

## 1.0.1 release validation

The banner/documentation-packaging update passed 2,848 public tests, with 37 sample-dependent skips. CI and both release build jobs passed. Downloaded Windows x64 and Linux x64 archives passed checksum and documentation-link checks; both CLI/MCP pairs passed version, help, benign recovery, JSON-error and MCP initialization/tool-list smoke checks. The updated banner was confirmed on both platforms.

Recovery behavior was unchanged in this release. The private-fixture results below belong to the 1.0.0 validation, rather than a fresh 1.0.1 private-corpus run.

## 1.0.0 release validation

Validation on 2026-10-16 used Windows with .NET SDK 10.0.402 and Linux x64 executable checks in Ubuntu 24.04 under WSL.

| Check | Result |
| --- | --- |
| Public tests | 2,848 passed; 37 sample-dependent groups require private fixtures. |
| Private tests | All 37 groups covered in partitioned runs: 72 expanded cases passed. Combined public/private coverage accounts for 2,920 distinct passing cases. |
| Pinned static corpus | Reactor 6: 13/13 cases in two independent runs with byte-identical serialized outcomes; Reactor 7: 9/9; ConfuserEx: 2/2. These cases include declared controls, not just protected malware. |
| Fresh benign runtime probes | Nine configurations across .NET Framework 4.8, .NET 8 and .NET 10; both protected and cleaned builds matched their unprotected oracles on all ten reported behaviors. |
| Reconstruction and retirement | Two qualified reconstruction runs passed their gates; five fresh identities passed physical VM-removal audits; 20 generated retirement/refusal cases matched their expected outcomes. |
| Executables | Self-contained Windows/Linux CLI and MCP builds passed version, help, JSON/error, benign recovery and MCP initialization/tool-list checks. Windows strict, analysis-only, verbose and ordinary malware reporting were inspected. |
| Terminal output | A classic Windows console started with VT processing disabled; the published CLI enabled it and rendered green/cyan cells. |
| Documentation | All local links resolved in the 17-page documentation package; archived history and preparation/checklist sections are excluded. |

Private sample checks use a dedicated analysis temporary directory. Malware analysis is static; runtime comparisons execute only the source-built benign probes.

Oracle checks keep raw differences visible. Exact cleanup attributions account for three protector resources and one unused private helper retained by the comparison oracles; unexplained losses still fail. The Mlfhntkcvb payload's mutation ceiling is pinned to the measured 20,132 changes. Reconstruction gates retain cold-start and independently evolved full-state disagreements even where separately captured non-VM state matches; agreement after original warm-up does not override them.

These release checks are separate from the frozen 43-root baseline above. See [corpus validation](corpus.md), [VM validation](devirtualization.md), and [support and limitations](compatibility.md) for their bounds.
