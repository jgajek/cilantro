# Parity with NETReactorSlayer

This matrix maps ReactorUnpack's passes onto the fifteen stages that
NETReactorSlayer ships under `NETReactorSlayer.Core/Stages/`. It records what is
implemented, where ReactorUnpack is stronger or weaker, and what remains a
deliberate, fail-closed boundary. Everything here is static: no protected
assembly is executed, and every mutating pass rolls back unless structural
verification passes.

Slayer is GPL-3.0 throughout and bundles a de4dot-derived renamer
(`NETReactorSlayer.De4dot.Renamer`). ReactorUnpack re-derives every equivalent
capability from its own CFG, use-site dataflow, and naming primitives rather
than porting any of it.

The most important architectural difference is not in this table. Slayer loads
the target with `Assembly.Load`/`UnsafeLoadFrom` and reflectively invokes the
sample's own decrypter methods, defeating Reactor's caller check by patching
`StackTrace.GetMethod`. That makes its string recovery correct for codec
variants nobody has modeled, and it makes running the tool on malware an
execution event. ReactorUnpack never loads or invokes protected code.

## Stage-by-stage matrix

| # | Slayer stage | ReactorUnpack pass | Status |
|---|--------------|--------------------|--------|
| 1 | `MethodDecrypter` | `method-body-recovery` | Parity. Static JIT-hook body recovery with write-log identity checks and per-body verification. |
| 2 | `AntiManipulationPatcher` | `antitamper-neutralization` | Parity. Removes only the proven integrity/verification subtree and guarded failure paths, using the static machine's RSA and hashing models. |
| 3 | `StrongNamePatcher` | `antitamper-neutralization` | Parity. The strong-name verdict is proven through the same modeled verification before any edit. |
| 4 | `BooleanDecrypter` | `boolean-recovery` | Parity by construction. Detects the `bool(int32)` resolver, proves each offset, and interprets the real resolver to fold sites. No corpus sample exercises it yet. |
| 5 | `StringDecrypter` | `string-table-recovery` + `string-recovery` | Stronger on proof, weaker on reach. Table capture and site rewriting are separate, all-or-nothing, and offset-proven; Slayer invokes the real decrypter and so handles unmodeled codecs. |
| 6 | `TokenDeobfuscator` | `token-recovery` | Parity by construction. Rewrites constant-fed `Module.Resolve*` proxies to direct `ldtoken`, validating every decoded token first. No corpus sample exercises it yet. |
| 7 | `ProxyCallFixer` | `delegate-proxy-analysis` | Stronger. Bijective field-to-target validation; the stream codec is derived structurally rather than by hash. |
| 8 | `TypeRestorer` | `type-restoration` | Weaker/conservative, clean-room. Promotes non-public `object` fields only when every writer agrees; no public-API signature changes. |
| 9 | `MethodInliner` | `method-inlining` | Parity. Redirects proven single-call pass-through forwarders, collapsing chains to their end, with stack-neutrality proof and full-body rollback. |
| 10 | `AssemblyResolver` (payload dumping) | `payload-extraction` | Parity. Bounded, strictly framed managed-metadata extraction; the `Assembly.Load` sink is never invoked. |
| 11 | `ResourceResolver` (reattach) | `resource-restoration` + `resource-hook-elision` | Parity. Interprets the module's own bundle reader under the bounded machine, reads the decrypted satellite assembly's streams back onto the module, and drops the resolve subscription those streams made unreachable. |
| 12 | `CosturaDumper` | `costura-extraction` | Parity. Extracts `costura.*.dll(.compressed)` assemblies into the payload writer. |
| 13 | `ControlFlowDeobfuscator` | `dispatcher-deobfuscation` + `control-flow-completion` | Clean-room. Proves dispatcher edges, folds constant branches, and deletes all unreachable code with EH regions preserved and per-method verification. |
| 14 | `Cleaner` | `runtime-cleanup` (on by default; `--keep-runtime` disables) | Weaker. Slayer also strips attributes and unused resources and fixes the entry point and metadata header. We delete any type or method that is unreachable, invisible outside the assembly, unexposed to reflection, unreferenced by survivors, and attributable to the protector. |
| 15 | `SymbolRenamer` | `symbol-renaming` (opt-in `--rename`) | Much weaker. Slayer renames the full de4dot surface including public types and restores properties and events. We rename only non-public, non-virtual, structurally proven names to synthetic identifiers. |
| — | anti-debug (folded into `AntiManipulationPatcher`) | `antitamper-neutralization` | Partial. Debugger-probe sites are neutralized only where the value provably feeds a Reactor termination path. |
| — | `Helper/NativeUnpacker` + `QuickLZ` | `metadata-preflight` (`NativePackDetector`) | Deferred. Native-packed input is detected and reported unsupported with a specific diagnostic rather than mis-processed. Slayer unpacks it. |
| — | `Helper/CodeVirtualizationUtils` | `reactor-detection` | Parity. Both tools only detect code virtualization; neither lifts it. |

## Where ReactorUnpack is intentionally different

- **Fail-closed everywhere.** Any pass that cannot prove its transform preserves
  behavior makes no edit. Partial or unsupported recovery blocks emit by default.
- **Static only.** There is no dynamic execution, so protections that only reveal
  themselves at runtime (native stubs, VM lifting) are boundaries, not features.
- **Identity is policy-aware, not bypassed.** Cleanup and renaming declare the
  exact removals, additions, and renames they perform; the verification gate still
  fails on anything undeclared.
- **Deletion needs provenance, not just deadness.** Slayer removes what it
  recognizes as Reactor's. We remove what recovery can account for: the pass that
  replaced a resolver call, redirected a call past a forwarder, or elided an inert
  loader call records what it left without a use, and only those declarations are
  candidates. A program's own unused internal class stays, which costs some
  parity against a tool that tree-shakes, and keeps the output an unobfuscated
  version of the input rather than a smaller program.

## Corpus coverage gaps

The corpus proves method-body recovery, proxy fixing, string recovery,
anti-tamper neutralization, control-flow completion, encrypted-resource
restoration, and payload extraction on real samples. Boolean protection, token
proxies, Costura packaging, and native packing are implemented and unit tested
but not yet represented by a real corpus sample; the manifest schema and runner
already carry the gates (`minimumBooleansRecovered`, `minimumTokensRestored`,
`minimumResourcesRestored`, `maximumRemainingSwitchDispatchers`,
`maximumUnreachableInstructions`, `expectUnsupportedReason`) so those samples can
be added without code changes.

"Parity by construction" on a stage no corpus sample exercises is weaker than
it sounds, and `resource-restoration` was the cautionary case. It was present,
unit tested, and recovered nothing on any of the three real samples carrying an
encrypted bundle, because it looked for a zero-argument `byte[]` decryptor
naming the bundle and Reactor has never emitted one: the plaintext is a
by-product of a resolver installer that returns nothing. Keying on the anchor
every version does share — a static method that names the bundle and reads it as
a manifest resource — and then taking the plaintext out of machine state rather
than off the stack recovers all three.

Two things Slayer's `Cleaner` and `SymbolRenamer` do have no corpus evidence
behind them and are therefore not implemented. Reactor 6 strips neither
properties nor events from these samples (the protected and oracle assemblies
carry identical `Property` and `Event` rows, with no orphaned accessor in
either), and it leaves the metadata header, runtime version, and custom
attributes byte-identical to the oracle's. Restoring what was never removed
would be untestable code. The oracle gate now counts properties and events as
preserved-name members in their own right, so a sample that does lose them
fails rather than passing quietly.

## Current corpus standing

Last full run: 9 passed, 0 failed, 0 missing, against 175 passing unit tests.

The three JIT-hook samples restore every protected body (199, 312, and 253),
fold their constant predicates, complete control flow, inline forwarders,
restore every string site, decrypt and reattach every resource stream their
bundle held, and emit verified output that clears the structural oracle gate
with every preserved name intact.

What remains is surplus rather than failure, and it is measured per sample as a
ratchet in the manifest:

| Sample | Types emitted / oracle | Surplus methods | Unattributed dead methods |
| --- | --- | --- | --- |
| `database` | 51 / 49 | 107 | 87 |
| `reason-pac` | 51 / 50 | 205 | 101 |
| `service-controller` | 45 / 44 | 179 | 79 |

The three clean oracle assemblies are the control: cleanup removes nothing from
any of them, which is the evidence that attribution is not quietly tree-shaking
the program.

The surplus is now dominated by one thing rather than by scattered dead code.
Reactor injects a call to each of its loader entry points at the head of every
type initializer in the module, so the JIT-hook installer and the string-table
initializer are reached from everywhere and keep their shared cipher and
compression library — about 170 methods — alive. Recovery has made both
redundant, exactly as it made the resource hook redundant, but the resource hook
was separable: its subscription is five stack-neutral instructions that can be
proved in place, whereas the remaining two write loader state and eliding them
means reasoning about the whole bootstrap. That is the next lever, and it is
worth roughly the entire remaining surplus.

The oracle gate itself compares structure — type and method counts, the
preserved-name subset, resource names, and entry-point kind — because the
oracle's own type names are `Class0`, `Class1`, and `Class3/Delegate9`: it was
produced by a de4dot-style renamer, not built from original source. Requiring
exact name equality would mean reproducing another tool's arbitrary `ClassN`
numbering, which is not a correctness property. Names Reactor preserved, such as
`Reason.rsServiceController.ServiceUtils`, do appear verbatim in both, and those
are what the preserved-name subset checks.

Resources are compared by name and not only by count, under
`requireOracleResourceParity`. Counting alone could not tell apart a module that
kept the application's resources alongside the protector's bundle from one that
lost them, and it was in fact reporting a *smaller* surplus for the second case:
before restoration the three samples each carried three Reactor resources and
were missing two of the oracle's, for a surplus of one. They now carry all three
of the oracle's resources plus the three Reactor ones, which reads as a surplus
of three and is strictly better.

## Emission policy

Emission is gated on the emitted module being trustworthy, so only passes that
can affect the module withhold output. `payload-extraction`,
`costura-extraction`, and `resource-restoration` recover side artifacts, so they
report `Unsupported` without blocking an otherwise verified assembly; when
restoration succeeds it does reattach, and that addition is declared to the
identity gate like any other mutation. `--fail-on-partial` restores the strict policy in which any
incomplete pass, artifacts included, withholds output.

Two separate questions are asked before output is kept. The module in memory is
compared against the input, and may differ only by what the passes declared. The
file is then compared against that module, by member name rather than by
metadata token: deleting a row forces the writer to renumber everything after it,
so tokens legitimately differ between memory and file while names do not. Token
preservation is requested whenever nothing was deleted, and dropped exactly when
it has become unachievable.
