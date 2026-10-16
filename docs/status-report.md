# Validation scope and results

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

## Reading the evidence

A structural pass is not a behavior-equivalence verdict. Bounded reconstruction checks cover exercised inputs and captured state; disagreements and inconclusive trials remain visible. Deliberate protector-metadata removal does not justify dismissing an unrelated application-state difference.

Ordinary application switches, initialization effects and bundled libraries may remain. Native dependencies are extraction artifacts, not a claim of native-code decompilation or deprotection. No extracted file or successful report establishes that malware is safe to execute.

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
