# Support and limitations

CILantro 0.10.3 is a regular release for static recovery of supported .NET Reactor and ConfuserEx samples. Coverage follows the sample's protection configuration and implementation, not just the product name or version.

## Coverage

| Area | Supported work | Relevant boundary |
| --- | --- | --- |
| Reactor method protection | Restore supported NecroBit/JIT-loader method bodies | Unrecognized loaders or bodies never supplied by the loader can remain unresolved |
| Reactor strings and constants | Recover supported string decoders, numeric tables, and bounded pure helpers | Unknown state or side effects prevent folding |
| ConfuserEx | Supported encrypted-section recovery, constants, control-flow cleanup, and resolvable proxies | Narrower corpus; forks, resource protection, and runtime-dependent binding need case-specific verification |
| Control flow | Constant propagation across stack/local state, dispatcher solving, and specialization of proven paths while retaining calls and field reads | Unknown selectors, unsupported paths, and exception-boundary cleanup remain; ordinary switches and async state machines must not be mistaken for protection |
| VM reconstruction | Decode supported Reactor VM programs, infer operations, emit marked CIL bodies and helpers | Not a universal devirtualizer; unsupported semantics and unexercised paths remain |
| Embedded assemblies | Supported load capture, resource decoding, Costura extraction, and bounded recursive recovery | No exhaustive extraction claim; no fetching downloaded stages |
| Native wrappers | Extract the known Reactor bootstrap shape and continue managed recovery | Not arbitrary native unpacking, mixed-mode recovery, or NativeAOT decompilation |
| Cleanup and names | Remove attributable unused protector code; assign readable names where safe | Reflection, metadata tokens, serialization, interop, and public contracts constrain changes |

Reactor detection reports the family rather than asserting a marketing version from ambiguous structure. Current evidence includes real-world Reactor 6 samples and purpose-built Reactor 7.5 probes targeting .NET Framework 4.8, .NET 8, and .NET 10. The ConfuserEx corpus contains two pinned samples; do not generalize it to every fork.

## The two modes

The ordinary CLI run enables readability renaming and supported VM reconstruction. Interpretation may use the bundled host profile and continue past certain unsupported calls with unknown values. The report records assumptions and skipped interpretation. Unknown values are not a license to invent a branch decision or decoded payload.

`--strict` disables these implicit assumptions and permissive continuation, and defaults renaming and reconstruction off. Explicit `--rename` and `--devirtualize` enable those transformations in strict mode. Declared facts and authorized declared call outcomes remain inputs to the analysis; strict mode does not prove those assertions true.

## Validation baseline

The final pre-release recovery build passed 1,208 selected regression tests and all 24 standard corpus gates. All 25 standard assembly reports and nine reports from four additional recursive inputs verified structurally, with no extracted payload hashes lost against the preceding baseline. All 46 saved-output pass trials also verified. New behavioral tests execute generated benign CLR fixtures; malware trials remain static. These configurations and observations are distinct, not a single equivalence score. See the [0.10.3 release notes](releases/0.10.3.md) and [completion measurements](completion-progress.md).

The corpus gates cover their manifest assertions. A decompiler accepting a file proves neither its behavior nor extraction completeness. Runtime-oracle trials execute only the benign programs built from repository source; they exercise selected inputs, not all reconstructed VM paths. See [corpus validation](corpus.md).

## Known gaps in the current corpus

- Development tracing identifies Mlfhntkcvb's debugger-present disagreement as an original protector initializer throwing before VM dispatch. Expanded snapshots also expose cold-start VM-state differences in Mlfhntkcvb and Qbjuef. Both match on the repeat-call zero-stream fixture after identical original setup, including captured static state, but retain overall disagreement. This is bounded evidence, not proof that startup effects can be discarded; see [VM validation](devirtualization.md).
- With the workstation profile and a declared 32-million-step budget, full-protection Reactor 7.5 benign probes for .NET Framework 4.8, .NET 8, and .NET 10 now agree on the repeat-call zero-stream fixture after identical original initialization. The comparison includes captured managed state, native regions, ordered writes, and image-protection records. Cold-start trials expose static-state differences and retain overall disagreement; their earlier inconclusive verdicts did not show those differences. Their cleaned outputs remain unchanged and pass structural verification. This is bounded evidence, not full equivalence. The default comparison budget remains four million steps; registrations without complete captured state still make a trial inconclusive.
- `mc.dll` has one stub-shaped method that the recovery trace never writes: `EmptyList.Count()`, returning zero. That body is plausible for an empty list, so the heuristic does not by itself establish missing recovery. Do not substitute a guessed implementation.
- Large Reactor outputs retain substantial dispatcher patterns and runtime infrastructure. Numeric token resolution and reflective construction restrict deletion.
- The latest default Mlf payload run retains 23 switches in 16 methods, including functional choices and unresolved routing. It restores all 700 numeric-table constants and 172 strings and removes 561 runtime types; the older reconstruction cleanup gate still expects 564. Its 672 unreachable instructions are retained through the current exception-boundary cleanup policy. The 24 standard gates passing does not mean this separate cleanup gate passes.
- WindowsManagement's managed stage retains 179 dispatcher-shaped methods in the standard configuration; `mc.dll` retains 26, and the full Reactor 7.5 fixtures retain three per framework. These heuristic counts include ordinary control flow and are not counts of proven protector dispatchers.
- Some extraction passes remain unsupported or incomplete. Each recovered child needs its own result review.
- Some reconstructed operations are retained as fail-fast placeholders in regions classified unreachable by the recovered graph. That classification depends on the recovered semantics.

## Release claim

The supported claim is **recovery and simplification for analysis, with evidence and explicit limitations**. Complete unprotection, original-source reconstruction, exhaustive payload discovery, and universal behavioral equivalence are not release guarantees.
