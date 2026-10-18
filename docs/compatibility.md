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
| Babel .NET | Generated strings, numeric tables, token-bound delegate adapters, interpreted resource streams and legacy assembly-bundle extraction. |
| Types and identifiers | More useful types and replacement names for navigation. |

The validation evidence includes Reactor 6 malware, Reactor 7.5 source-built probes targeting .NET Framework 4.8, .NET 8 and .NET 10, and two pinned ConfuserEx samples. Implementation and protection options determine how far recovery gets. Custom decoders, forks and unresolved runtime behavior can leave a layer in place.

### Babel .NET coverage

Babel recognition uses an applied `BabelAttribute` / `BabelObfuscatorAttribute`, the `Babel` metadata stream, a connected generated-string/numeric-table runtime, or the combination of a stream decoder and a successfully decoded legacy resource envelope. The generated-runtime match requires an integer-indexed string getter using an AppDomain/Hashtable cache, a nested `MethodBuilder(TypeBuilder)` factory that emits IL, a resource initializer connected to a stream decoder, and the four numeric getter types. Stream decoders may return `Stream` or `MemoryStream`. The report token is `babel`; recognition does not establish the protector version.

Supported string calls are recovered through independent bounded interpreter trials. The early Babel literal-string pass runs before payload extraction so decoded resource names can expose embedded stages. Rewrites retain required type initialization and fresh string allocations. Calls with effects or unsupported behavior remain in place.

Resource recovery interprets the module's own stream decoder twice in fresh bounded machines and accepts matching concrete bytes only after the complete encoded input is consumed. This covers the newer encrypted/compressed streams observed in the captured corpus. Decoded data is exported separately with source and output hashes in the analysis report and a `.babel-resources.json` index. Stream ranges exclude unused buffer capacity. Reactor-wrapped layers are revisited after outer recovery.

Legacy unpacking also handles the Babel 3.0 envelope and the 3.5–4.x header envelope, including the eight-byte XOR header mask, embedded or assembly-public-key-derived DES keys, CBC/PKCS7 and standard zlib compression. Plaintext must validate as a managed PE or a complete count/name/length/PE assembly bundle before assembly extraction. Encrypted source resources remain available. Legacy bundle layouts have synthetic ground truth tests; the captured streams contain runtime tables rather than assembly bundles.

Token-bound delegate adapters are reconstructed only when independent initializer trials in opposite orders agree on their targets and the fields have closed initialization paths. Rewrites preserve type initialization and reconcile erased arguments, constructed generics, constructors and boxed value-type receivers. Adapters needing private access or a nonvirtual dispatch context that ordinary CIL cannot express remain intact, with their resolved targets reported. Caller-derived typing preserves these adapters' erased contracts.

The extracted-corpus scan covered 5,103 readable copies, 86 unique hashes and 82 managed images; fifteen unreadable paths were logged and excluded. The [Babel corpus](../corpus/babel-static.manifest.json) pins nine original inputs: `Zebekeadu.dll`, `Ggdzylx.dll`, `Frzfqnvunjz.dll`, `Ktjtiuwiixd.dll`, `Msfhjjpkive.dll`, the Reactor-wrapped `Lqcuzgc.dll`, `Uescfpvjk.dll` and `Ptnifif.dll`, and the additional Malware Vault `pin_mxi_decoded_stage.exe`. Zebekeadu recovery includes all 152 string sites, 461 numeric reads and both resource streams (`Cdte`, 4,762 bytes; `lVVE`, 380 bytes). The pin_mxi sample resolves 2,353 delegate bindings, rewrites 1,990 adapters and retains 363 for their access/dispatch context. It recovers 1,221 string sites; its numeric initializer requests `YQLy`, which is absent from the original input. That missing-data diagnostic is an explicit corpus expectation, and its numeric reads remain unresolved.

Coverage does not establish recovery of Babel's encrypted method-image format, arbitrary object deserialization or every modern configuration. Unsupported or damaged inputs remain partial. Decoded resource satellites can be inspected separately; stream export does not replace runtime resource hooks. Sample validation uses static parsing and the bounded interpreter, without loading or executing the malware.

Validation on 2026-10-18 passed all nine Babel corpus entries, recovered 17 hash-verified streams and introduced no broken or worsened methods under differential Microsoft ILVerify checks. The full test run passed 2,903 tests with 37 unrelated private-fixture tests skipped. Pin_mxi retains its original 69 verifier findings and the missing numeric resource described above.

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
