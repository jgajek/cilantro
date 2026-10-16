# Support and limitations

CILantro recovers supported .NET Reactor and ConfuserEx code and embedded stages. Match support to the layers present in your file: method encryption, string decoding, control-flow flattening, VM bytecode or a wrapper. A product name or version label alone does not describe the whole case.

For concrete results, see the [malware walkthrough](protection-removal.md). For a new sample, use its report to identify what was recovered and what still needs work.

## What is supported

| Layer | What you can investigate after recovery |
| --- | --- |
| Reactor encrypted methods / NecroBit | Restored method bodies and their API use. |
| Reactor strings and numeric constants | Readable values at supported decoder/lookup sites. |
| Reactor virtualization | Supported VM programs lifted into CIL and reconstructed bodies that can be decompiled. |
| Control-flow flattening and opaque predicates | Readable branches after established dispatcher transitions and fixed conditions are simplified. |
| Reference proxies | Explicit API or method targets where binding can be resolved. |
| Protector support code | A clearer application after obsolete, attributable helpers/resources are removed. |
| Native Reactor bootstrap | An extracted managed stage followed by its recovery. |
| Managed wrappers and embedded assemblies | Extracted stages, bounded recursive recovery and reassembly for supported wrapper shapes. |
| Resource entries and bundled dependencies | Recovered content with hashes and parent/source information. |
| ConfuserEx | Supported encrypted sections, constants, control-flow cleanup and resolvable proxies. |
| Types and identifiers | More useful types and replacement names for navigation. |

The validation evidence includes Reactor 6 malware, Reactor 7.5 source-built probes targeting .NET Framework 4.8, .NET 8 and .NET 10, and two pinned ConfuserEx samples. Implementation and protection options determine how far recovery gets. Custom decoders, forks and unresolved runtime behavior can leave a layer in place.

## What to expect on an unfamiliar sample

A useful result may be a fully readable method, a partially recovered assembly, or an extracted stage ready for another tool. Open the artifact containing the behavior you are investigating and inspect its remaining work.

CILantro does not fetch downloaded stages, attribute malware families, decode every family's configuration, or recreate the original source project. Native extraction gives you another artifact to analyze; it is not general native-code decompilation or NativeAOT recovery.

Prefer the untouched protected input. A file already rewritten by another recovery tool may have lost bodies, metadata or resources needed for further recovery.

## Defaults and explicit choices

The ordinary CLI enables readable replacement names, supported VM reconstruction and protector cleanup. Interpretation may use recorded host assumptions and continue past some unsupported calls with unknown values.

Use `--strict` to compare a run without implicit assumptions or permissive interpretation. It also leaves names and VM stubs unchanged. For narrower comparisons, use `--keep-names`, `--keep-runtime` or `--no-devirtualize`.

Use `--generic-recovery` when you explicitly want supported structural cleanup of a root with no recognized protector. Core and MCP callers have independent controls; MCP reconstruction must be enabled explicitly.

## Read the evidence at the right level

| Evidence | What it establishes |
| --- | --- |
| `Success` | The run met its configured policy. |
| `Verified` | Structural checks and recorded rewrite invariants passed. |
| Reconstruction agreement | Observations matched in the stated controlled trials. |
| Physical VM-removal check | Identified VM machinery is absent and reconstructed/retired bodies are accounted for. |
| Matching payload hash | The compared recovered bytes are identical. |

These results answer different questions. Keep a reconstruction disagreement visible even when the assembly is readable and structurally valid. Inspect the difference and the trial's coverage before drawing a behavioral conclusion.

Application switches, required initialization calls, bundled libraries and payload resources can legitimately survive cleanup. A cleaned file remains a malware analysis artifact, rather than a guarantee of safe execution or equivalent behavior for all inputs.

## Current corpus result

The frozen corpus accounts for **43 roots**, including **28 undamaged captured Reactor-tagged identities**. Its checks include protected inputs, extracted stages, controls and explicit generic recovery. These counts describe test scope rather than independent malware families.

Physical VM-removal checks cover **18 contexts across 14 intact virtualized identities**. Detailed cleanup inspection covers **104 structurally verified managed outputs**. The [status report](status-report.md) records those measurements and the release checks separately. Contributors use the [corpus gates](corpus.md) to validate changes.
