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
| 6 | `TokenDeobfuscator` | `token-recovery` | Parity by construction. Rewrites constant-fed `Module.Resolve*` proxies and Reactor's own `int`-to-handle forwarders to direct `ldtoken`, validating every decoded token first and proving the forwarder's cached module handle is this module's by interpretation. Sixteen to seventeen sites per JIT-hook sample. |
| 7 | `ProxyCallFixer` | `delegate-proxy-analysis` | Stronger. Bijective field-to-target validation; the stream codec is derived structurally rather than by hash. |
| 8 | `TypeRestorer` | `type-restoration` | Weaker/conservative, clean-room. Promotes non-public `object` fields only when every writer agrees; no public-API signature changes. |
| 9 | `MethodInliner` | `method-inlining` | Parity. Redirects proven single-call pass-through forwarders, collapsing chains to their end, with stack-neutrality proof and full-body rollback. Covers Reactor's object-laundering wrappers over framework calls, whose declared types are allowed to differ from the target's only by a widening to `object`. Four hundred to six hundred sites per JIT-hook sample. |
| 10 | `AssemblyResolver` (payload dumping) | `payload-extraction` | Stronger on reach, equal on framing. The general route interprets whatever unpacker the module carries and takes the bytes as they reach `Assembly.Load`, so a crypter's cipher, container, and stage count need not be known and need not be Reactor's; a driver written as a constructed object is entered as readily as a static one. The sink is never invoked, and a recovered buffer is believed only after it parses as managed metadata twice over. A crypter whose setup is itself virtualized is reached by running its virtual machine as the IL it is, at the cost of a much longer interpretation. |
| 11 | `ResourceResolver` (reattach) | `resource-restoration` + `resource-hook-elision` | Parity. Interprets the module's own bundle reader under the bounded machine, reads the decrypted satellite assembly's streams back onto the module, and drops the resolve subscription those streams made unreachable. |
| 12 | `CosturaDumper` | `costura-extraction` | Parity. Extracts `costura.*.dll(.compressed)` assemblies into the payload writer. |
| 13 | `ControlFlowDeobfuscator` | `dispatcher-deobfuscation` + `control-flow-completion` | Clean-room. Proves dispatcher edges, folds constant branches, and deletes all unreachable code with EH regions preserved and per-method verification. |
| 14 | `Cleaner` | `runtime-cleanup` (on by default; `--keep-runtime` disables) | Weaker. Slayer also strips attributes and unused resources and fixes the entry point and metadata header. We delete any type or method that is unreachable, invisible outside the assembly, unexposed to reflection, unreferenced by survivors, and attributable to the protector, plus attributed type initializers whose bodies cannot do anything, for which reachability is beside the point. |
| 15 | `SymbolRenamer` | `symbol-renaming` (opt-in `--rename`) | Much weaker. Slayer renames the full de4dot surface including public types and restores properties and events. We rename only non-public, non-virtual, structurally proven names to synthetic identifiers. |
| — | no equivalent | `loader-call-elision` | Beyond Slayer. Cuts the loader calls Reactor injects at the head of type initializers throughout the assembly, once the bounded interpretation accounts for everything a call does and nothing that survives can read what it wrote. Slayer removes the runtime by recognizing it; this reaches the same code by proving the calls inert, and is what leaves the runtime unreachable for cleanup. The initializers left empty by the cut are handed to cleanup by the same pass, on the grounds that it is what emptied them. |
| — | anti-debug (folded into `AntiManipulationPatcher`) | `antitamper-neutralization` | Partial. Debugger-probe sites are neutralized only where the value provably feeds a Reactor termination path. |
| — | `Helper/NativeUnpacker` + `QuickLZ` | `metadata-preflight` (`NativePackDetector`) | Deferred. Native-packed input is detected and reported unsupported with a specific diagnostic rather than mis-processed. Slayer unpacks it. |
| — | `Helper/CodeVirtualizationUtils` | `reactor-detection`, `virtualization-disassembly` | Beyond Slayer, short of lifting. Slayer detects virtualization by looking for a known runtime; detection here is by the shape of the seam every virtualizer has to leave — pack the arguments, pass a program number, call once, return — which holds for engines neither tool has seen, and it names the affected methods rather than only reporting a flag. Beyond detection, the engine's own decoder is run under the machine and the decoded program is read back off the heap, so nothing about the bytecode's framing or encryption has to be known. What the operations mean is then derived per sample — which is what the per-build opcode numbering makes necessary and what no static table could survive — two ways: by having the engine perform them on chosen values, and by watching what they do while the program really runs, which reaches the ones that refuse to be performed out of context and, by matching what they took and left against what the engine held elsewhere, identifies the loads and stores that isolated trials never could. That accounts for 26 of the 29 operations in each sample, 21 of them by name. Where they go comes from the same run, by recording which operation followed which, so branches are named and their targets given — the ones the run took as fact, the rest by a rule the run confirmed. Neither tool lifts the result to IL. |

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
but not yet represented by a real corpus sample. Payload recovery by
interpretation is proved on both payload-carrying samples, each of which hides
its unpacker behind a virtualized initializer that the machine runs rather than
lifts; the recovered stages are pinned by hash. The manifest schema and runner
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

Last full run: 9 passed, 0 failed, 0 missing, against 189 passing unit tests.

The three JIT-hook samples restore every protected body (199, 312, and 253),
fold their constant predicates, complete control flow, inline forwarders,
restore every string site, decrypt and reattach every resource stream their
bundle held, cut the loader calls Reactor injected into their type initializers,
and emit verified output that clears the structural oracle gate with every
preserved name intact.

What remains is surplus rather than failure, and it is measured per sample as a
ratchet in the manifest:

| Sample | Types emitted / oracle | Surplus in named types | Whole-module surplus | Unattributed dead methods |
| --- | --- | --- | --- | --- |
| `database` | 40 / 49 | 8 | -118 | 66 |
| `reason-pac` | 41 / 50 | 16 | -100 | 72 |
| `service-controller` | 37 / 44 | 4 | -110 | 61 |

The three clean oracle assemblies are the control: elision changes nothing in
any of them and cleanup removes nothing, which is the evidence that neither is
quietly tree-shaking the program.

Two surplus columns replace the one there used to be, because the single figure
stopped meaning what it says. De4dot renames Reactor's runtime type rather than
removing it, so the oracle for `database` carries a hundred and forty-four
methods of protector inside `Class1`; an output that deletes them scores a
negative whole-module surplus, and the same number would have appeared had the
output deleted program instead. The left column compares only types both sides
name — the ones Reactor never obfuscated — which separates the two: a surplus
there is Reactor's per-type helpers that cleanup cannot yet attribute, and a
deficit is program that went missing. The gate now fails on any deficit at all,
and all three samples have none.

`service-controller` used to be the outlier at a hundred and seventy-three, and
the reason was a single call. Its `ServiceUtils.GetServiceProcessID` loaded a type
handle through one of Reactor's token forwarders, which kept the resolver type
reachable and the shared cipher alive behind it; recovering that call closed a
hundred and forty methods in one step.

The surplus inside named types then fell from fifty-nine, seventy-nine, and
forty-four to five, twenty-eight, and fourteen, and that came from object
laundering. Reactor wraps ordinary framework calls in helpers that declare
everything they can as `System.Object` — `object f(object)` over
`FileVersionInfo.get_FileVersion` — and forwarder redirection was declining them
on two counts: the target sits outside the assembly, so it does not resolve to a
`MethodDef`, and the declared types do not match. Neither is a reason to decline,
because the body converts nothing: the values reach the target as the caller
pushed them either way. Admitting both took redirection from ninety-two sites to
six hundred and sixty on `service-controller`, and undoing the disguise leaves
the surviving code more strongly typed than it was, since a local already
declared `FileVersionInfo` now feeds a call that says so.

Removing the type initializers elision had hollowed out took the three the rest
of the way to eight, sixteen, and four. Reactor puts its loader call at the head
of every type's initializer, writing an initializer to hold it on types that had
none, so cutting the calls left twenty-two to thirty-five bodies per sample that
run and return. Those are removed on the strength of the body rather than of
reachability, which for an initializer answers the wrong question: nothing has
to call it, because the runtime starts it when the type is first used. What can
be said is that running it achieves nothing, and that holds whenever the runtime
chooses to. Emptiness also draws the line in the right place on its own, since a
type whose own initializer Reactor merely prepended to still has the program's
code in the body and so is never a candidate.

What is left is Reactor's per-type scaffolding: every type carries a static field
of its own type, a null-check predicate over it, and a getter. These are dead in
the input as well as the output — Reactor emits them and never calls them — so no
pass made them dead and nothing recovery did accounts for them. Attributing them
would need evidence of a different kind than the rule currently admits.

The oracle gate itself compares structure — type and method counts, the
preserved-name subset, per-type method counts inside named types, resource
names, and entry-point kind — because the oracle's own type names are `Class0`,
`Class1`, and `Class3/Delegate9`: it was produced by a de4dot-style renamer, not
built from original source. Requiring exact name equality would mean reproducing
another tool's arbitrary `ClassN` numbering, which is not a correctness property.
Names Reactor preserved, such as `Reason.rsServiceController.ServiceUtils`, do
appear verbatim in both, and those are what the preserved-name subset checks.

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
