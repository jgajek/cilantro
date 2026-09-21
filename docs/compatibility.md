# Support and limitations

CILantro 0.10.0 is an analyst preview for static recovery of supported .NET Reactor and ConfuserEx samples. Coverage follows the sample's protection configuration and implementation, not just the product name or version.

## Coverage

| Area | Supported work | Relevant boundary |
| --- | --- | --- |
| Reactor method protection | Restore supported NecroBit/JIT-loader method bodies | Unrecognized loaders or bodies never supplied by the loader can remain unresolved |
| Reactor strings and constants | Recover supported string decoders, numeric tables, and bounded pure helpers | Unknown state or side effects prevent folding |
| ConfuserEx | Supported encrypted-section recovery, constants, control-flow cleanup, and resolvable proxies | Narrower corpus; forks, resource protection, and runtime-dependent binding need case-specific verification |
| Control flow | Constant propagation, dispatcher solving, path simplification, and dead-code removal | Complex exception regions, shared state, and unknown expressions remain difficult |
| VM reconstruction | Decode supported Reactor VM programs, infer operations, emit marked CIL bodies and helpers | Not a universal devirtualizer; unsupported semantics and unexercised paths remain |
| Embedded assemblies | Supported load capture, resource decoding, Costura extraction, and bounded recursive recovery | No exhaustive extraction claim; no fetching downloaded stages |
| Native wrappers | Extract the known Reactor bootstrap shape and continue managed recovery | Not arbitrary native unpacking, mixed-mode recovery, or NativeAOT decompilation |
| Cleanup and names | Remove attributable unused protector code; assign readable names where safe | Reflection, metadata tokens, serialization, interop, and public contracts constrain changes |

Reactor detection reports the family rather than asserting a marketing version from ambiguous structure. Current evidence includes real-world Reactor 6 samples and purpose-built Reactor 7.5 probes targeting .NET Framework 4.8, .NET 8, and .NET 10. The ConfuserEx corpus contains two pinned samples; do not generalize it to every fork.

## The two modes

The ordinary CLI run enables readability renaming and supported VM reconstruction. Interpretation may use the bundled host profile and continue past certain unsupported calls with unknown values. The report records assumptions and skipped interpretation. Unknown values are not a license to invent a branch decision or decoded payload.

`--strict` disables these implicit assumptions and permissive continuation, and defaults renaming and reconstruction off. Explicit `--rename` and `--devirtualize` enable those transformations in strict mode. Declared facts and authorized declared call outcomes remain inputs to the analysis; strict mode does not prove those assertions true.

## Validation baseline for this preview

The pre-release recovery baseline recorded 788 passing selected tests, 24/24 corpus gates, 10/10 additional static runs, 41/41 successful decompilations, and 9/9 benign runtime-oracle matches. These are different measurements, not 852 independent proofs of correct recovery. Documentation and presentation changes are validated separately in the release notes.

The corpus gates cover their manifest assertions. A decompiler accepting a file proves neither its behavior nor extraction completeness. Runtime-oracle trials execute only the benign programs built from repository source; they exercise selected inputs, not all reconstructed VM paths. See [corpus validation](corpus.md).

## Known gaps in the current corpus

- Mlfhntkcvb's reconstructed method has a controlled-trial disagreement: the original throws with the debugger-present input while the reconstruction completes. Whether this is intentional anti-debug removal or a semantic defect requires investigation. It must not be presented as proven equivalent.
- `mc.dll` has one catalogued method body that the recovery trace never writes. Its remaining stub needs investigation rather than a guessed implementation.
- Large Reactor outputs retain substantial dispatcher patterns and runtime infrastructure. Numeric token resolution and reflective construction restrict deletion.
- Some extraction passes remain unsupported or incomplete. Each recovered child needs its own result review.
- Some reconstructed operations are retained as fail-fast placeholders in regions classified unreachable by the recovered graph. That classification depends on the recovered semantics.

## Release claim

The supported claim is **recovery and simplification for analysis, with evidence and explicit limitations**. Complete unprotection, original-source reconstruction, exhaustive payload discovery, and universal behavioral equivalence are not release guarantees.
