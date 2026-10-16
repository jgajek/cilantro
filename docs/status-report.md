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

## Candidate checks

The Windows candidate's focused CLI suite passed **37 tests**. The suite with private samples disabled passed **2,833 tests**, with **37 sample-dependent skips**. Static Reactor and ConfuserEx CLI smoke checks produced structurally verified cleaned output and reports. A real Windows console check confirmed rendered colors with VT processing enabled by the tool.

These checks do not replace the full pinned-corpus and packaged-platform release gates. Validate the actual candidate against matching fixtures, preserve failures and inconclusive evidence, and record the tested scope. See [corpus validation](corpus.md), [development](development.md), and [support and limitations](compatibility.md).
