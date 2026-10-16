# Support and limitations

CILantro supports static recovery of selected .NET Reactor and ConfuserEx implementations. Identify support by the sample's actual protection layers and the recovery evidence, not by its marketing version alone.

## What is supported

| Protection or packaging layer | What recovery delivers | Boundary on new samples |
| --- | --- | --- |
| Reactor encrypted methods / NecroBit | Restored managed method bodies | A different loader or unavailable body source can prevent recovery |
| Reactor strings and numeric constants | Readable literals and proven constants; removal of obsolete supporting machinery | Unknown state, unsupported decoding and effects can prevent replacement |
| Reactor virtualization | Supported bytecode reconstructed as CIL, with original VM machinery removed when retirement checks permit | Unsupported semantics or unresolved paths can block reconstruction or cleanup |
| Flattened control flow and opaque guards | Simplified branches and proven dispatcher removal while preserving application decisions | Ordinary switches and async/iterator state machines must remain; unknown selectors are not guessed |
| Proxies and protector infrastructure | Explicit call targets and removal of attributable code/resources | Live application references, reflection, metadata tokens and initialization effects constrain removal |
| Native Reactor bootstrap | Supported wrapper extraction followed by managed-stage recovery | Not a general native unpacker, NativeAOT decompiler or mixed-mode recovery engine |
| Managed wrappers and embedded assemblies | Extraction, bounded recursive cleanup and reassembly for supported managed bootstrap shapes | Not every loader shape can be rewritten; inspect each child's result |
| Resource entries and dependencies | Supported embedded content and Costura/dependency extraction with provenance | Resource discovery is not exhaustive payload discovery |
| ConfuserEx | Supported encrypted-section recovery, constants, control-flow simplification and resolvable proxies | Validation is narrower than Reactor: two pinned samples, not every fork/configuration |
| Readability | Recovered types, consistent references and useful replacement names | Original names, comments, project files and source layout cannot generally be restored |

Evidence includes real-world Reactor 6 samples and Reactor 7.5 benign probes targeting .NET Framework 4.8, .NET 8 and .NET 10. Family detection does not claim to determine an exact marketing version from ambiguous structures.

## Current corpus result

The frozen validation corpus accounts for **43 roots**: 37 ordinary recoveries, three declared negative controls and three successful explicit generic followups. It includes all **28 undamaged hashes** from a captured 29-sample Reactor-tagged inventory; one input damaged by another recovery tool is excluded. The captured inventory defines the measurement scope; a release candidate must be validated against its pinned inputs.

Independent physical VM-removal checks pass **18 contexts / 14 intact virtualized identities**. Final inspection covers **104 structurally verified managed outputs**, with application-identity and captured-payload preservation checks passing for every root. These are root, identity and output-context counts, not interchangeable counts of malware families. The [status report](status-report.md) records the exact scope and evidence.

The preservation contract covers the corpus application and payload behavior, allows deliberate protector-metadata removal, and retains application switch statements. It does not preserve hypothetical callers reflecting over deleted protector types. Tiny original application methods, bundled libraries and payload resources are not removal obligations. One resource-manager method retains harmless discarded constants; zero redundant instructions is not the completion criterion.

## What to expect on an unfamiliar sample

A new sample can still retain protections, lose a recoverable path to an unsupported operation, or produce only an extracted stage. Review the root and every relevant child. The corpus result is evidence of capability, not an automatic verdict for your file.

CILantro does not provide:

- Universal support for all Reactor versions, custom builds or ConfuserEx forks.
- Guaranteed discovery of every payload, downloaded stage or environment-specific execution path.
- Automatic malware-family attribution or a general family-specific configuration extractor.
- Reconstruction of the original source project or a guarantee of warning-free decompilation.
- A guarantee that a cleaned assembly is runnable, behaviorally identical for all inputs, or safe to execute.
- Arbitrary native-code deprotection. Extracted native dependencies may need separate analysis.

An input already rewritten by another tool may have lost metadata, resources or bodies needed for recovery. Prefer the untouched protected original. Reports should distinguish unsupported or damaged input from a successful recovery; do not treat a produced file as proof that missing code was restored.

## Defaults and explicit choices

Ordinary CLI runs enable renaming, supported VM reconstruction and runtime cleanup. Static interpretation may use bundled host assumptions and continue past some unsupported calls with unknown values; those qualifications are recorded.

`--strict` disables implicit assumptions and permissive interpretation and leaves names and VM stubs unchanged. Compare it with an ordinary run to investigate differences; the simplified CLI has no positive renaming/reconstruction overrides in strict mode. Core/MCP callers retain independent controls. Strict mode does not validate facts you supplied yourself, and it is not a stronger full-unprotection certificate.

`--generic-recovery` permits supported generic rewrites when no protector is recognized. It does not establish a protector identity or bypass other emission checks. `--keep-runtime` and `--no-devirtualize` deliberately retain material that default recovery may remove or reconstruct.

## Read the evidence at the right level

| Evidence | What it establishes |
| --- | --- |
| `Success` | The run met its configured policy |
| `Verified` | Structural checks and recorded rewrite invariants passed |
| Rebuilt comparison agreement | Observations matched for the bounded trials actually exercised |
| Physical VM-removal check | Identified VM machinery is absent and reconstructed/retired bodies are accounted for |
| Payload hash match | The compared bytes match; it does not prove every application method |
| Corpus completion decision | The documented goal was met for the specific frozen scope and preservation contract |

A raw reconstruction disagreement may include deliberately removed protector state. It remains visible and must be read with the application-contract evidence; do not automatically dismiss a disagreement on a new sample. Conversely, matching a few trials does not prove arbitrary future behavior.

Recovery interprets modeled instructions and APIs; it does not run sample code in the host CLR. That distinction does not make parsers or decompilers invulnerable. Use the handling controls appropriate to your malware-analysis environment, and retain originals and case provenance.
