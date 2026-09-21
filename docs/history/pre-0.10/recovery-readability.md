> Historical development snapshot. Claims and results may be superseded. Use the [current documentation](../../README.md) for 0.10.0.

# Recovery readability improvements

The September 2026 readability pass adds three changes:

- Track integer locals across basic blocks, preserving a constant only when all
  incoming paths agree. This exposes more redundant assignments and branches to
  the existing cleanup passes. It does not assume a value on conflicting paths.
- Attribute folded constant helpers after successful verification, and recheck
  dead protector types after orphaned methods have been removed. A removed
  method's signature or body can be the last reference retaining an entire type.
- Name generated array fields by element type and simple field-reader methods by
  the field they read. Public API and virtual/interop restrictions still apply;
  these are descriptive names, not recovered original identifiers.

## Measured results

Comparisons use ILSpy 11.0.0.9375 and the same recovery options before and after.
The Qbjuef chain uses `--generic-recovery --recover-embedded`.

| Assembly | Before | After |
| --- | ---: | ---: |
| Zebekeadu decompiled lines | 8,919 | 8,524 |
| Zebekeadu `goto` occurrences | 673 | 528 |
| Zebekeadu switches | 116 | 116 |
| Qbjuef decompiled lines | 5,208 | 4,949 |
| Qbjuef `goto` occurrences | 405 | 405 |
| Qbjuef switches | 17 | 17 |
| Qbjuef descriptively named symbols | 152 | 156 |
| Zebekeadu descriptively named symbols | 80 | 83 |

The final dead-type sweep also increases removed types from 13 to 34 in
Reason.PAC, 13 to 34 in rsDatabase, and 11 to 33 in rsServiceController.
The corresponding removed-method totals rise from 510 to 538, 385 to 412, and
466 to 497. These samples continue to satisfy their corpus oracle gates.
Qbjuef's original extracted assembly hashes are unchanged.

These numbers measure readability and cleanup, not complete unflattening or
behavioral equivalence. In particular, the remaining switches have not all been
proven to be protection, and the reconstructed Qbjuef bodies still lack behavioral
validation. The new data-flow analysis defers methods with exception handlers and
locals whose addresses escape to the previous, more limited analysis.

## Validation

- 651 selected tests passed; the selection excludes tests already recorded as
  unavailable in the original local baseline.
- All 24 corpus gates passed: 13 Reactor 6, nine Reactor 7, two ConfuserEx.
  There were no missing corpus samples. Reactor 7 oracle inputs are reference
  material rather than additional scheduled recovery gates.
- Dradg, Kadzzsn, mc and Msfhjjpkive, which are outside those manifests, all emitted
  structurally verified assemblies with generic recovery and reconstruction off.
- The full Qbjuef chain emitted structurally verified parent and child outputs.
- All 27 cleaned assemblies produced across these runs decompiled successfully
  with ILSpy, including the reconstructed parent and both extracted children.

The corpus runner disables renaming and reconstruction to preserve comparable
oracle measurements. Renaming is exercised by the focused tests, the four extra
sample runs, and the full Qbjuef chain; reconstruction is exercised by that chain.
Samples are statically interpreted and decompiled, never executed.

## Further unflattening

The next pass recovers integer table reads and pure integer helper calls before
control-flow cleanup. It also recognizes arithmetic/bitwise switch selectors,
follows known states through intermediate update blocks, and folds newly exposed
constant arithmetic. Redirects preserve the final state local; unknown values,
calls and exception-region transitions stop path tracing.

Table recovery requires private storage with no observed array escape, initialization
confined to its proven closure, and no external initialization effects. Two
independent bounded interpretations query indexes in opposite orders. Both use
strict mode with an empty host profile, preventing assumed clock, environment or
other host values from becoming output constants. This follows the actually
interpreted initialization path; an unused alternative cipher implementation does
not itself disqualify a deterministic resource decoder.

The complete Qbjuef chain now produces these ILSpy measurements, compared with the
previous readability output above:

| Zebekeadu payload | Previous | Current |
| --- | ---: | ---: |
| Decompiled lines | 8,524 | 5,430 |
| Switch statements | 116 | 9 |
| `goto` occurrences | 528 | 5 |

This run recovers 458 table constants and 53 pure helper calls, then redirects
343 dispatcher paths. The separately recovered payload and the child recovered
through Qbjuef produce identical cleaned assembly hashes. Qbjuef itself remains
at 4,949 lines, 17 switches and 405 `goto` occurrences; these improvements do not
resolve the remaining limitations of its reconstructed virtualized methods.

Inspection of the nine remaining payload switches finds data-field parsers,
wire-type handling, resource-array deserialization and decompression codes.
Their presence is not evidence of remaining flattening. The five remaining
`goto` occurrences also do not establish a protection failure. These are source
readability measurements, not a proof of behavioral equivalence or universal
unflattening support.

The final static trials are stored under
`C:/cilantro-verify/review-trials/unflattening-verified`.

Final validation: all 664 selected tests passed; all 24 corpus gates passed with
no missing samples (13 Reactor 6, nine Reactor 7, two ConfuserEx). The full Qbjuef
chain and all four extra samples emitted verified output. ILSpy successfully
decompiled all 28 emitted assemblies, including the separate Zebekeadu trial
(which duplicates the child from the full chain). No sample was executed.

## Reactor and ConfuserEx payload follow-up

ConfuserEx conditional arms can merge before finishing their state arithmetic.
The new dispatcher-tail separation pass copies only the short integer computation
onto the incoming branch, allowing the existing solver to prove each arm
separately. It preserves the original operations, bounds code expansion, excludes
exception-handler methods and rolls back a body that fails stack verification.
Synthetic tests compare the results of both conditional outcomes before and after
rewriting, as well as refusing an effectful shared computation.

Reactor numeric recovery is retried after proven loader calls have been removed.
The Qafcakg payload now yields 449 table constants plus 60 pure integer helper
calls, enabling 343 direct dispatcher paths. An initializer consisting solely of
`nop`/`ret` no longer blocks a pure helper; remaining initializer work still does.
The rrdsk table remains refused because its initialization writes state outside
the permitted initializer-owned fields. No host assumptions or effect checks were
relaxed to force a result.

The renamed analyst outputs are under
`C:/cilantro-verify/review-trials/protector-readability-final/analyst`.
The existing renamer provides 328 and 430 readable symbol names in the two
ConfuserEx outputs and 263 in Qafcakg. These are generated names, not restored
original source identifiers. The larger Mlfhntkcvb payload and rrdsk still retain
substantial control-flow/runtime code; this follow-up does not claim equivalent
recovery quality for every Reactor variant.

The few remaining ConfuserEx switches are not all ordinary program switches:
inspection of `06b9d08b` finds one section-processing switch and one surviving
flattened method with exception handling. The preparatory path separation
deliberately excludes those methods. Thus the large reduction is not a claim
of complete ConfuserEx unflattening.

Matched corpus settings (renaming and reconstruction off) give:

| Assembly | Lines before / after | Switches before / after | `goto`s before / after |
| --- | ---: | ---: | ---: |
| ConfuserEx 06b9d08b | 44,731 / 10,766 | 145 / 2 | 6,429 / 17 |
| ConfuserEx 61e31544 | 60,139 / 15,544 | 185 / 5 | 8,381 / 39 |
| Reactor Qafcakg payload | 8,742 / 5,665 | 114 / 9 | 528 / 5 |

The other matched outputs have unchanged switch and `goto` counts. Renamed
analyst copies have the same switch/`goto` counts but slightly different line
counts (10,773, 15,551 and 5,703 respectively). Validation passed all 669 selected
tests and all 24 corpus gates, with no missing samples. All five renamed payload
trials, four extra samples and the complete Qbjuef chain emitted verified output;
all 32 emitted assemblies decompiled successfully. Samples were statically
interpreted and decompiled, never executed.

## Six follow-ups: validation, types, reconstruction and residual cleanup

1. **Rebuilt-body validation.** The comparison now installs the lifted helper as
   well as stub bodies and stops preparation before loader-call elision can remove
   the path under test. Qbjuef enters the lifted helper and extracts the same
   payload bytes, raising observed coverage from 0/2 to 1/2. Its other rebuilt
   body is not entered, so the overall verdict remains `notMade`. Neither matching
   payloads nor successful decompilation are reported as full equivalence.
2. **Reference types.** Closed reference types from arguments, fields, calls,
   constructor results and strings can remain typed through stack/slot analysis.
   Unlike-type joins retain object, and conversion back to object does not box
   reference types. Synthetic string-return and object-return cases are interpreted
   and checked for the original value; open generic and non-object-compatible
   types remain excluded.
3. **Mlfhntkcvb reconstruction.** Running with reconstruction enabled produces a
   marked CIL body from 4,854 virtual operations, with 27/44 slots typed and four
   exception regions reconstructed. Eight unreached operations remain explicit
   throw placeholders. The sample offers no usable payload-comparison path, so
   this remains an unvalidated reading. The previous payload readability trial
   used `--no-devirtualize`; its lack of a rebuilt body was not a reconstruction
   refusal. This follow-up establishes that distinction rather than inventing
   semantics for an unknown operation.
4. **Exception-aware unflattening.** Shared tails can be copied within identical
   exception regions without moving clause boundaries. This removes the last
   artificial ConfuserEx dispatchers in the two tested samples: both analyst
   outputs now contain one switch (section processing) and zero `goto`s, down
   from 2/17 and 5/39 respectively. This is corpus evidence, not universal
   support for every handler/dispatcher arrangement.
5. **Initialization-preserving constants.** Where a closed table is independent
   of mutable external static inputs, constant replacement can retain the
   required initializer using `RunClassConstructor`. Regression tests cover
   retaining its write and refusing a table read from mutable external state.
   rrdsk still fails this proof and remains unchanged; its initialization is not
   silently discarded to recover more constants.
6. **Reflection-aware cleanup.** A type token carried through uniquely assigned
   locals no longer triggers module-wide virtual retention. Reassignment, escaped
   addresses, alternate entries into the producing expression and unknown type
   sources still refuse narrowing. The current corpus does not show additional
   runtime deletion from this rule: its unresolved reflective targets remain
   unresolved.

Outputs for this round are in
`C:/cilantro-verify/review-trials/recovery-next-final`. Analyst payload runs enable
reconstruction; the corpus retains its established gate settings. Mlfhntkcvb's
source grows because it now includes the reconstructed body, so a raw line-count
comparison against its earlier stub-only output would be misleading.

Final validation for these follow-ups: 677 selected tests passed, all 24 corpus
gates passed with no missing samples, and all 32 emitted assemblies decompiled
successfully. The final file hashes were checked against the decompiler audit
after every run completed. All five analyst payload trials, four extra samples
and the full Qbjuef chain emitted structurally verified output. One MCP process
startup test hit its known timeout on an initial suite run and passed on rerun.
No malware sample was executed.

## Five further checks: controlled trials, graph gaps and dependency proofs

The next round implements all five follow-ups, with explicit limits on what the
sample trials establish.

1. **Direct method comparison.** `RebuiltMethodTrial` interprets the prepared
   original VM stub and its rebuilt body in fresh machines, using matching
   zero/null, one/empty and negative/test-data fixtures for supported signatures.
   Each interpretation has a four-million-step limit; at most eight methods and
   three fixtures per method are attempted. The original VM entry and the target
   body must actually execute instructions. Instances and generic receivers need
   a supplied fixture and remain inconclusive. Completed returns, thrown objects,
   argument mutations and static state are normalized with heap aliases preserved;
   opaque models, native-memory effects, unknown values and budget exhaustion do
   not count as agreement. Exceptions include their modeled fields and messages.
   Direct differences prevent an overall agreeing reconstruction verdict; matching
   fixtures never validate other inputs or turn incomplete payload coverage into
   full coverage. The individual findings are recorded as
   `reconstruction-method-trial` evidence and summarized by the rebuild pass.
2. **Unreached operations and exception entries.** Known paired regions now seed
   the exact handler start, with depth one for catches and zero for finally/fault
   handlers. Their end positions and kind flags are no longer tried as additional
   handler entries. Unpaired regions retain the conservative fallback. The six
   Qbjuef positions (52–53, 566–567, 655–656) and eight Mlfhntkcvb positions
   (2590–2595, 2794–2795) follow unconditional jumps and have no incoming edge in
   the recovered graph. They remain fail-fast placeholders: this is evidence of
   redundant dispatcher tails in the recovered graph, not independent proof of
   the engine's branch semantics. Listings and build notes now state that limit.
3. **Initializer dependencies.** Numeric recovery can separate a final, uniquely
   assigned, freshly constructed holder from unrelated earlier initialization
   effects. The proof follows unconditional jump chains, refuses conditional or
   cyclic initialization paths, and checks the constructor's data dependencies.
   Closed literal lookup-field initializers can be checked separately from their
   initializer's other work; escaping or externally mutable arrays refuse that
   refinement. Required effects remain: the rewritten site retains the original
   holder-field read, preserving its initialization trigger, including
   `beforefieldinit` timing. A distinct non-beforefieldinit getter type retains an
   explicit initializer call in the original order. The interpreter now models
   that explicit trigger with the existing once-only/failed-initializer state and
   shared budget. rrdsk still reaches a mutable RSA-provider field
   (`EMTEaVkDss` in `E9ynFskYqf`) through its loader dependencies. Its constants are
   not replaced; the report now names the specific dependency instead of only
   listing all initializer writes.
4. **Remaining runtime and dispatcher cleanup.** Reflection through a local whose
   assignments all name type tokens or null can use the finite set of named
   types; an unknown assignment, address escape, cycle or alternate expression
   entry still refuses narrowing. Instance-aware reachability checks unknown
   construction at its reachable fixed point, so an uninstantiated virtual
   method cannot keep its own runtime alive merely by containing reflection.
   Reachable unknown construction still falls back to broad retention. Rebuilt
   bodies also receive the existing dispatcher-edge and known-state-path
   rewrites, with their normal transactions and verification. Mlfhntkcvb's
   reflective construction remains reachable, so that runtime is still retained.
5. **Verified semantic names.** Private generated field setters gain `Write_...`
   names, and bounded, acyclic chains of pure forwarders can be named for the
   external API they ultimately call. Multi-action bodies, cycles, public and
   virtual contracts remain outside these naming rules. These are generated
   descriptions of observed structure, never guesses at a malware role or
   claims to recover original source identifiers.

The synthetic checks cover changed static effects with identical returns,
exception-message differences, unsupported comparisons, finally stack depth,
mutable initializer inputs, preserved initializer effects, lookup-array escapes,
explicit once-only initialization, reachable versus uninstantiated reflective
constructors, setters and cyclic forwarders. All sample work uses static
interpretation and decompilation; no sample is launched.

The final trial artifacts are under
`C:/cilantro-verify/review-trials/recovery-completeness-final`.

The final direct trials are inconclusive for all three fixtures on each of
Qbjuef and Mlfhntkcvb. Qbjuef's original and rebuilt paths both reach a
`BinaryReader` without a modeled stream. Mlfhntkcvb's original path also needs a
debugger-state fact absent from the deliberately empty host profile. These are
interpreter/fixture limits, not successful comparisons or demonstrated semantic
mismatches. Qbjuef's separate payload comparison still covers 1/2 rebuilt bodies
and extracts identical payload bytes.

The five analyst payloads gain five additional descriptive method names: two in
Mlfhntkcvb, two in rrdsk and one in Qafcakg. The two ConfuserEx payloads retain their
existing semantic-name counts. The matched corpus recovery-pass counts remain
unchanged; this round does not claim additional constants, runtime deletions or
unflattened branches on these samples. Its main gains are stronger comparison and
initialization machinery, correct paired-handler stack entries and more precise
limits on the remaining readings.

Validation: 694 selected tests passed. All 24 corpus gates passed, with no missing
samples. All five analyst payloads, four extra samples and the Qbjuef embedded
chain emitted structurally verified output. All 32 emitted assemblies decompiled successfully with ILSpy, and their final
hashes match the audit. Structural validity and successful decompilation do not
imply full behavioral equivalence.


## Further evidence: streams, dependency paths and ground truth

This round addresses the next five investigations, with separate implementation
and sample outcomes:

1. **VM fixtures.** Direct comparisons now include 32-byte writable modeled
   streams for object/stream arguments, with debugger attachment explicitly
   simulated both off and on. Other host facts remain unanswered. These are
   valid stream objects, not a claim that arbitrary zero bytes satisfy every
   sample's format. Qbjuef and Mlfhntkcvb both reach completion with debugger
   attachment off. Full-state comparison still refuses opaque dictionaries and
   hashtables, and now names the first opaque root. With debugger attachment on,
   Mlfhntkcvb's original path throws `System.Exception` while its rebuilt path
   completes. The comparison now reports this terminal difference even when
   static state is opaque, and the overall reconstruction verdict is `disagreed`.
   This demonstrates different behavior under that simulated host condition;
   it does not establish incorrect payload bytes or identify the precise missing
   protection check. No native sample execution was used.
2. **rrdsk dependencies.** Refusals now include a bounded constructor/call/field
   initializer path. The observed chain goes from the numeric holder through
   stream decompression (`mVunBV9UFV`, `qoh7q1oIT9`, `SwN7MheF5j`, `v1Q7irMnOm`,
   `mma7NCoOf0`) to the lookup-table initializer `HeL89NTmN1QTQxf8SPN::.cctor`,
   which calls `E9ynFskYqf` and reaches the RSA field. That initializer contains
   literal arrays and a loop-built array. A new bounded proof accepts a fresh
   readonly array published before literal element stores, provided it never
   escapes and no subsequent call or foreign initializer can observe it during
   construction. Escapes and post-publication calls have negative tests. The
   current rrdsk initializer still exceeds this straight-line proof; no constants
   are replaced merely because the earlier loader call appears incidental.
3. **Reflection.** Instance-aware reachability follows bounded, acyclic static
   helpers that return an exact type token, including pure forwarding chains.
   Unknown and cyclic helpers retain broad reachability. Mlfhntkcvb's retained
   VM engine still constructs types from dynamic VM state; its
   `uWtDWojBIi` handler remains a reachable unknown-construction site, so the
   sample does not qualify for further runtime deletion under this rule.
4. **Residual dispatchers.** Known-state path evaluation supports integer shifts,
   signed/unsigned comparisons, negation and complement. The binary operations
   were compared before/after rewriting over 280 boundary-value combinations,
   including negative and oversized shift counts. The offline residual audit
   uses `DispatcherAnalyzer` on emitted CIL, not decompiler text. In the preceding
   five analyst outputs, Mlfhntkcvb had 601 switch-bearing methods/1,132 CIL
   switches, rrdsk 49/121 and Qafcakg 10/10. The ConfuserEx pair had no remaining
   CIL switch instructions (ILSpy's one source switch is reconstructed syntax).
   Frequent Mlfhntkcvb refusal classes are noncanonical switch blocks, fewer than
   two state assignments, and assignments not ending in the required branch.
   These are proof limitations, not claims that every remaining switch is
   protector code; rrdsk also contains state locals read outside dispatch blocks.
5. **Ground truth.** `corpus/probes/Probe/RecoveryGroundTruth.cs` adds benign
   arithmetic/branch and catch/finally/mutable-array cases. The tests compile the
   same source and compare static interpretation after cleanup with actual .NET
   execution of those benign methods, including return values and changed bytes.
   The probe builds for net48, net8.0 and net10.0. No local Reactor installation
   was found, so newly protected versions of these extended probes have not been
   generated; the existing protected probe corpus is still used for regression
   gates. This is a remaining validation limitation, not new protector coverage.

The ground-truth check exposed an interpreter defect: integer division by zero
was reported as invalid IL instead of entering an applicable catch handler.
Integer division/remainder now model that exception. An intervening finally that
would require unsupported exception unwinding still returns `Unsupported`; it is
never silently skipped. The existing sticky-initializer test now expects the
first division failure to be a thrown outcome while retaining its failed-state
and no-retry assertions.

Artifacts for this round are under
`C:/cilantro-verify/review-trials/recovery-evidence-final`. Changes remain
uncommitted.

Final validation: **719 selected tests passed**, **24/24 corpus gates passed**,
and **32/32 emitted assemblies decompiled successfully**. All final assembly
hashes match the decompiler audit. All five analyst payloads, four extras and the
Qbjuef chain emitted structurally verified output. One earlier test-suite attempt
hit the known MCP process startup timeout; the final complete suite passed.

Matched corpus pass-change counts, residual-dispatcher classifications and analyst
source line/switch/goto counts remain unchanged from `recovery-completeness-final`.
This round's measured gains are stronger validation and interpreter fidelity;
it does not claim additional sample constants, runtime deletion or unflattening.
The new Mlfhntkcvb simulated-host disagreement is intentionally retained in its
report rather than hidden by incomplete state snapshots.


## Fresh Reactor 7.5 trial probes

The user-supplied `dotnet_reactor_setup_7_5_0_0.exe` was verified as signed by
Eziriz e.K. and installed at `C:/Program Files (x86)/Eziriz/.NET Reactor`.
This closes the earlier toolchain limitation. Nine fresh benign fixtures were
built from the extended probe source: net48/net8.0/net10.0, each with strings/CFF,
NecroBit-only and full protection. The existing corpus and pinned hashes remain
unchanged. The reproducible Windows runner is `corpus/probes/verify.ps1`, documented
in `corpus/probes/README.md`. All execution trials in this round use these benign
programs; malware samples receive static analysis and decompilation only.

The new cases exposed and drove three fixes:

- **Markerless NecroBit exception bodies.** Reactor can omit the usual seven-byte
  marker on a body whose exception region starts at zero. The decrypt-table
  reader had discarded `RecoveryGroundTruth.Mutate`, producing partial recovery
  on all three NecroBit-only builds. Unmarked bodies are now accepted only when
  mapped to a method with restored exception sections; clause offsets use the
  actual marker length. The zero-key sentinel is excluded, and native body reads
  explicitly exclude mapped-image pointers and refuse conflicting scratch-region
  candidates. The existing two-interpretation, address-mapping, parsing and
  transactional verification gates remain in force.
- **Runtime delegate constructors.** Method cleanup now retains runtime-provided
  methods of surviving types. Removing an apparently unused delegate constructor
  made the CLR reject a delegate instantiated through native marshaling, even
  though no managed `newobj` referred to that constructor.
- **Exception-boundary continuations.** An unreachable exclusive handler end was
  pinned while its continuation was deleted or folded to nops, leaving terminal
  fallthrough rejected by the Framework JIT. A proven unreachable terminal suffix
  can now be removed with exclusive EH ends retargeted to end-of-method. Nonterminal
  pinned boundaries retain their continuations. Entry/handler reachability and
  retained branches into a suffix prevent unsafe trimming. The net48 strings/CFF
  catch/finally probe now runs and matches its oracle.

Final native execution results (ten outputs per fixture: seven branch returns and
three catch/finally returns with final array bytes):

| Protection | net48 cleaned | net8.0 cleaned | net10.0 cleaned |
|---|---|---|---|
| Strings/CFF | matches | matches | matches |
| NecroBit-only | matches | matches | matches |
| Full | fails during loader initialization | fails resolving a metadata token | fails resolving a metadata token |

All **9/9 protected originals** match their unprotected oracles. **6/9 cleaned
builds** match. These are real remaining CILantro failures, not trial expiry or a
protector failure. The CoreCLR full builds retain loader code resolving numeric
method token `0x06000095`, which is invalid after metadata cleanup/renumbering.
The net48 full build still reports `InvalidProgramException` in a retained loader
helper (`generatedMethod_0060`). The runner deliberately exits nonzero for this
matrix and preserves each stdout/stderr log. Structural verification and successful
decompilation do not turn these failures into passing behavioral checks.

Validation: **725 selected tests pass**, including six new regression cases;
**24/24 existing corpus gates pass**. Runtime cleanup now removes fewer declarations
where delegate contracts must survive, and control-flow cleanup conservatively
retains some additional EH-boundary continuations. These are correctness tradeoffs,
not additional unflattening claims. The fresh probe artifacts are in
`C:/cilantro-verify/review-trials/reactor75-ground-truth`; the complete existing
sample regression is in `C:/cilantro-verify/review-trials/reactor75-regression-final`.
The trial reports a 14-day expiration for newly protected outputs, so regenerate
the fixtures for later execution tests. Changes are uncommitted.

Final decompiler audit: all **9 new cleaned probes** and **32 existing-sample outputs** decompiled successfully; every final file hash matches its audit. The three full-protection execution failures above remain failures.

## Numeric-token safety and loader reachability follow-up

Cleanup now retains declarations while reachable or reflectively exposed code
still calls the CLR numeric-token resolution APIs. A numeric token may originate
in a decrypted resource rather than an `ldtoken` instruction; ordinary reference
analysis cannot prove its target dead. Compacting metadata had caused the fresh
CoreCLR probes to fail resolving token `0x06000095`. The writer now also preserves
existing tokens when reconstruction appends methods and annotation types. A
serialization regression verifies that original method tokens still resolve to
the same methods after both kinds of additions.

Loader elision uses instance-aware reachability, matching runtime cleanup. A
virtual reader on an uninstantiated internal type no longer pins loader state
merely because its signature matches a surviving virtual call. Unknown reflective
construction retains the conservative fallback. Reconstructed methods are now
explicit roots of this check, so their required initialization cannot disappear.
Paired tests cover instantiated and uninstantiated readers and a reconstructed
reader with no ordinary caller.

This round prioritizes correctness over smaller output. Several corpus assemblies
now retain more protector declarations because a numeric-token consumer survives.
No measured corpus-wide reduction in source size is claimed. The safe loader
removal improvement is covered by focused fixtures; the nine fresh probes do not
show additional loader calls removed.

Validation: **731 selected tests**, **24/24 existing corpus gates**, and all ten
analyst/extra/recursive runs pass their structural checks. All nine protected
benign originals match the oracle; the six strings/CFF and NecroBit-only cleaned
outputs still match. The three full-protection outputs still fail execution:
.NET Framework reaches a surviving integrity check (`Probe is tampered`), and
CoreCLR reaches an `InvalidProgramException` in retained loader code after the
numeric-token failure is removed. Their remaining loader failures require further
investigation; decompilation and structural verification do not establish runtime
equivalence. Malware samples were processed statically only.

Fresh benign results: `artifacts/review-trials/reactor75-next`.
Full corpus results: `C:/cilantro-verify/review-trials/reactor75-next-regression`.

Final decompiler audit: **41/41 outputs** (9 fresh probes and 32 corpus outputs) decompiled successfully, with all recorded hashes matching the final assemblies.

## Implicit initializer removal

Loader-call elision now includes initialization entered implicitly by the CLR.
Previously, an interpreted type initializer could qualify as inert but remain
unchanged because there was no explicit call instruction to remove. The proof now
speculatively replaces eligible initializer bodies with `ret`, checks surviving
field readers, and restores the original body if any reader remains. The committed
edit uses the same transformation and a transaction covering complete bodies and
change records. Calls inside an initializer being replaced are not counted as
separate edits. The global module initializer remains excluded from candidates.

New paired regression cases exercise removal without an explicit call and exact
body restoration when a public method still reads the initialized field.
The fresh full-protection probes lose four inert initializers on .NET Framework
and two each on .NET 8 and .NET 10. This removes additional protector work, but
runtime results remain six of nine matching benign probes; the three full cases
still fail in retained loader or integrity code.

A separate diagnostic copy of the benign .NET 8 fixture showed that the helper
reported by `InvalidProgramException` executes valid IL when its initializers are
disabled: it reaches the expected `ArgumentNullException` for a null native pointer.
Disabling all initializers is not a recovery fix: the probe's main program then
fails with an uninitialized-state error. No such blanket change is in production.
The remaining proxy initialization resolves numeric tokens and still has observed
state readers, so its removal requires additional evidence.

Artifacts: `artifacts/review-trials/reactor75-implicit` and
`C:/cilantro-verify/review-trials/reactor75-implicit-regression`.

Validation for this change: **733 selected tests pass**, **24/24 corpus gates
pass**, and all ten analyst/extra/recursive runs emit structurally verified output.
The final fresh .NET 8 run fails with `BadImageFormatException: Bad class token`
in the same retained loader helper; .NET 10 still reports `InvalidProgramException`
and .NET Framework still reports `Probe is tampered`. None is counted as a
behavioral pass. The final CLI build succeeds without warnings.
ILSpy source-line counts for the nine fresh probes are unchanged. The removed initializer bodies are a CIL cleanup gain, not a measured source-size reduction.
Final static audit: all 41 cleaned outputs decompiled successfully and all recorded hashes match the final files. Changes remain uncommitted.

## Dynamic-method delegate dispatch

A proxy-initializer experiment exposed an interpreter gap: Reactor calls
`MethodInfo.CreateDelegate(Type)` on a modeled `DynamicMethod`. The emitted-body
model already handled `DynamicMethod.CreateDelegate`, but the base-class metadata
spelling was routed to the ordinary reflection model and refused. It now dispatches
to the existing emitted-body binder only when the modeled receiver is a dynamic
method and the argument count matches that overload. An undeclared body remains a
failure; no delegate or body is guessed.

Three regression cases cover both metadata-owner spellings and refusal without a
body. The successful cases execute the interpreted emitted method and compare its
result with a benign dynamic method invoked through the same API on the real CLR.

The experimental batch removal of proxy initializers was discarded. Shared warm
state can make later initializers look inert, and seeded proxy delegates can mask
initialization work. Extending removal requires independent state and a complete
account of each initializer, not merely two runs of the same warmed sequence.
The exploratory artifacts in `artifacts/review-trials/proxy-init-probe` are not the
trusted final outputs. This change does not add a proxy-initializer removal rule.

Final-check roots: `artifacts/review-trials/reactor75-methodinfo` and
`C:/cilantro-verify/review-trials/reactor75-methodinfo-regression`.

Validation: **736 selected tests pass**, including the three new cases; **24/24
corpus gates pass**. The pinned .NET 8 and .NET 10 full-protection corpus fixtures
each now have four inert initializers emptied instead of two. Their additional
interpretation reaches the existing removal proof without adding the discarded
batch-removal rule. The other 30 corpus output assemblies are byte-identical to
the previous round at this point. All ten analyst/extra/recursive runs succeeded.

All nine fresh benign protected originals still match their oracle, and the six
strings/CFF and NecroBit-only cleaned probes still match. The three fresh
full-protection cases remain runtime failures. No complete devirtualization or
runtime-equivalence claim is made for them. Changes remain uncommitted.
Final decompiler audit: all 41 outputs decompile, and all audit hashes match the final assemblies.

## Initialization proof boundaries

Initializer removal now evaluates additional guard and delegate-proxy candidates
from independent heaps without injecting recovered proxy delegates. Prepopulating
those delegates can make an initializer skip real writes, while reusing a heap
can make a later initializer appear inert because an earlier one warmed its cache.
Both interpretations must complete module initialization and the candidate itself;
a failed bootstrap or exhausted budget supplies no removal proof. Proxy discovery
has a shared bounded budget and stops at the first unsupported initializer.

Global predicate folding now retains reads that occur within the initialization
window which writes that particular field. A value captured after startup does
not describe intermediate startup values. Separately initialized fields can still
fold in another type's initializer. The write-once analysis also propagates ordinary
and externally visible callers through the whole helper chain, preventing a shared
startup helper from hiding a writer that can run again later.

Eight new regression cases cover independent caches, seeded delegates, incomplete
bootstrap execution, exhausted budgets, intermediate startup reads, separately
initialized state, and transitive ordinary callers. All **744 selected tests pass**.

Current validation roots: `artifacts/review-trials/reactor75-startup` and
`C:/cilantro-verify/review-trials/reactor75-startup-regression`.

All **24/24 corpus gates pass**, and all ten analyst/extra/recursive runs emit
structurally verified outputs. Some predicate folds are now deferred until the
later recheck rather than applied during live initialization. The pinned full
probes retain two guard calls that the previous seeded proof removed.

All nine benign protected originals match the oracle; six cleaned outputs match.
The three full-protection outputs still fail: .NET Framework reports tampering,
.NET 8 reports a bad image format in retained loader code, and .NET 10 reports an
invalid program in retained loader code. Independent bootstrap interpretation
also exhausts its budget on those loaders, so no additional proxy initializer is
claimed removable there. These are correctness safeguards, not a demonstrated
increase in behavioral recovery coverage. Malware corpus processing remains static.

Final decompiler audit: **41/41 outputs** decompile successfully, and every audit
hash matches the final assembly. Changes remain uncommitted.

## Cold-start interpretation budgets

Tracing the fresh .NET 8 full-protection probe through the passes showed that its
681-method NecroBit table takes about 18 million interpreter steps to initialize.
The old four-million-step guard proof and sixteen-million-step proxy scan could
not get that far. With a sufficient bound, startup completes after delegate-proxy
analysis identifies the modeled trial guards, and continues to complete after
the subsequent rewrites. The earlier budget exhaustion was not evidence that a
control-flow transformation had broken startup.

Cold initializer proofs now add the measured method-recovery bootstrap cost to
the ordinary four-million-step allowance, capped at 64 million steps. A recovery
attempt that decrypted the table before throwing still supplies useful cost
information; its failure never supplies a successful proof. Each candidate still
requires two independent completed executions and the same surviving-reader checks.
Proxy candidates retain a shared total scan budget.

Five regression cases cover completed, throwing, and exhausted bootstrap attempts,
negative input, and overflow-safe capping. All **749 selected tests pass**.
Validation roots: `artifacts/review-trials/reactor75-budget` and
`C:/cilantro-verify/review-trials/reactor75-budget-regression`.

All **24/24 corpus gates pass**. Each of the three fresh full-protection probes
now loses two additional guard calls under the cold proof, while retaining its
four previously emptied initializers. A proxy initializer can now be interpreted
fully, but its observed writes still prevent removal. Behavioral coverage remains
**6/9** cleaned probes matching the oracle; all nine protected originals match.
The three full-protection loader/integrity failures remain unresolved.

The largest static gain is `extras/mc.dll`: loader elision rises from zero to
**1,793 calls plus one implicit initializer**. That leaves 287 type initializers
and 602 helpers doing no work. All ten analyst/extra/recursive runs succeed with
structurally verified output. Of the compared corpus assemblies, only `mc.dll`
and the three pinned full-protection probes change; the remaining compared
assemblies are byte-identical to the prior round. Malware was not executed.

ILSpy output for `mc.dll` shrinks from **137,899 to 112,703 lines** (25,196 fewer,
about 18%). Final audit: **41/41 outputs decompile**, with every recorded hash
matching the final assembly. Changes remain uncommitted.

## Separate startup and query budgets

The shared recovery bootstrap now receives the same measured startup allowance as
the cold initializer proof. Previously, a VM reader's 750,000-step query allowance
also bounded module startup, even when method recovery had already measured about
18 million steps to decrypt the method table. The bootstrap can now finish before
the reader starts. Subsequent queries keep their original budgets; explicit run
budget declarations retain their existing semantics. The allowance calculation is
shared with loader elision rather than maintained twice.

A regression test runs an initializer longer than the query allowance, verifies
the initialized field, and confirms a later over-budget query still stops. All
**750 selected tests pass**.

Each fresh full-protection probe now has **two reconstructed bodies**, enabling
71 state folds on .NET Framework, 77 on .NET 8, and 71 on .NET 10. ILSpy output
shrinks by 540, 549, and 514 lines respectively. Each recovered VM body still has
one contradictory stack operation and several unreachable operations represented
by fail-fast placeholders; controlled method trials remain inconclusive. This is
partial recovery, not complete devirtualization or a behavioral-equivalence claim.
All nine protected originals match the benign oracle, and six cleaned outputs
match. The three full-protection loader/integrity failures remain.

Validation roots: `artifacts/review-trials/reactor75-bootstrap` and
`C:/cilantro-verify/review-trials/reactor75-bootstrap-regression`.

Final validation: **24/24 corpus gates pass**, all ten analyst/extra/recursive
runs succeed with structurally verified output, and **41/41 assemblies decompile**
with matching audit hashes. The first Reactor 7 run rejected `probe-net80-full`
because its two bootstrap interpretations disagreed. A profile rerun with unchanged
code passed and recovered all 677 bodies; the first report is retained at
`artifacts/review-trials/reactor75-bootstrap/reactor7-first-attempt.json`.
The intermittent disagreement remains unexplained. Malware processing was static,
and changes remain uncommitted.

## Preserve VM predicates when every observed jump was taken

The .NET 8 full probe's stack contradiction was operation 1901: it consumed two
values but was written as `br`, which consumes none. The observation merge had
overwritten its conditional classification because all five observed executions
took the jump. Repeating the same outcome is not evidence that the alternate edge
does not exist.

The merge now preserves measured predicates and operand consumption when combining
trial semantics with observed jump counts. It does not invent a missing condition.
Four regression cases cover always-taken observations, preserving an established
condition, and building a two-path conditional body with a valid stack. Remaining
stack contradictions now name up to four operation indices, mnemonics, incoming
depths, and pop/push counts in the diagnostics. All **754 selected tests pass**.

Validation roots: `artifacts/review-trials/reactor75-branch` and
`C:/cilantro-verify/review-trials/reactor75-branch-regression`.

The fresh .NET Framework, .NET 8, and .NET 10 full-protection probes each lose
their one reachable contradictory-operation placeholder. The established `bgt.un`
condition is preserved and emitted instead. The remaining 6, 11, and 11 operations
are unreachable in their recovered graphs and still retain fail-fast placeholders.
All **24/24 corpus gates pass on the first run**, and all ten analyst/extra/recursive
runs emit structurally verified output. All nine protected originals match their
benign oracle; runtime coverage remains **6/9** cleaned probes. The three full
cases still fail in retained loader/integrity code. Malware was processed statically.

Final audit: **41/41 outputs decompile**, with all audit hashes matching the final
assemblies. The corrected full-protection source is 71–72 lines longer because the
loop that the placeholder cut off is visible again. Changes remain uncommitted.

## Recheck loader dependencies after reconstruction

Loader elision now runs again after reconstructed bodies, predicate folding, and
stack normalization. The first pass still runs before reconstruction so that its
removed initializers can enable helper inlining. The later pass repeats the effects
and reachability checks against the final bodies; it does not treat reconstruction
as permission to remove initialization. Modules without reconstructed methods skip
the additional interpretation work.

The later invocation also exposed a token lookup failure: newly generated methods
share an unassigned metadata row ID until serialization. They are now excluded
from the original-bootstrap token lookup while remaining in the reachability graph.
Regression tests cover the collision, skipping modules without reconstruction,
retaining initialization with a surviving reconstructed reader, and removing it
after that reader has been folded. All **758 selected tests pass**.

The fresh full-protection probes lose another **79 loader calls on .NET Framework
and 68 each on .NET 8 and .NET 10**, plus two implicit initializers each. Their
decompiled source shrinks by **158, 136, and 134 lines**, respectively. The extra
pass took 8–14 seconds per full probe in this run. This is a modest cleanup gain;
the retained integrity/native-loader paths still prevent all three full-protection
outputs from matching the oracle. Runtime coverage remains **6/9 cleaned probes**,
with all nine protected originals matching.

Validation roots: `artifacts/review-trials/reactor75-late-loader` and
`C:/cilantro-verify/review-trials/reactor75-late-loader-regression`. All **24/24 corpus
gates pass on the first run**, all ten analyst/extra/recursive runs succeed with
structurally verified output, and **41/41 outputs decompile** with matching final
audit hashes. Malware processing remained static. Changes remain uncommitted.

The probe harness also no longer copies the oracle's `execution.json` into the
cleaned directory alongside runtime configuration. Recovery clears previous cleaned
execution results and aggregate outcomes, so an old success cannot appear to describe
a newly emitted assembly before verification. A separate benign fixture trial seeded
both stale files, confirmed their absence after recovery, and then regenerated a
successful execution result through verification. The full-set figures above come
from completed verification, not the copied intermediate files.

## Preserve type initialization while removing an inert loader body

A cold trace of the fresh .NET 8 full probe showed that the native loader's remaining
FIPS-cache writes occurred in its declaring type's initializer. The integrity routine
performed the later cache updates. Removing the native loader call would also remove
its initialization trigger, but keeping the call and emptying just the loader body
preserves that trigger.

The interpreter now records body writes separately from automatic declaring-type
initialization on method entry. Initializing another type from inside a method still
counts as a body effect. Evidence agreement includes the new attribution, and completed
invocations are tracked separately so an interrupted or throwing frame cannot supply
the new proof, even if a later invocation succeeds.

The late loader pass obtains fresh evidence from two complete cold starts after
reconstruction, without synthetic proxy seeding. Earlier method recovery can finish
decrypting bodies before its interpretation completes, so its old frame evidence is
insufficient for this removal. A module initializer requested as the proof target is
executed only once per fresh machine.

The pass can empty a completed, argument-free, internal static loader body
when no surviving code observes its body writes. It preserves every call and the
declaring type initializer, rejects `beforefieldinit` and generic types, and retains
methods with registrations or without the new evidence. Speculative body removal,
reachability, a shrinking candidate set, and transactional verification guard the edit.
The ordinary call-elision proof still uses the full effects including initialization.
Reconstructed methods remain available for analysis, and methods without assigned
metadata row IDs cannot be selected through a shared placeholder token.

Six regression cases exercise initializer preservation, observable body writes,
`beforefieldinit`, failed execution, initialization reached through a callee, and a
failure before any effect followed by a successful invocation. A seventh case checks
that the cold-start proof does not execute the module initializer twice, and an eighth
retains a reconstructed body even when its effects appear inert. All **766 selected tests
pass**. The exception-region propagation experiment was deferred; no change to that
analysis is included in this round.

Validation roots: `artifacts/review-trials/reactor75-loader-body` and
`C:/cilantro-verify/review-trials/reactor75-loader-body-regression`. Each fresh full
probe loses one native loader body. Compared with the preceding round, decompiled
source shrinks by **2,589 lines on .NET Framework, 3,292 on .NET 8, and 3,246 on
.NET 10** (9,127 total), with 2,354 fewer `goto` statements across the three outputs.
The final reconstructed-method/token exclusion was audited against every body removal:
all three target original methods with assigned tokens and no reconstruction marker.

All **24/24 corpus gates pass**, and all ten analyst/extra/recursive runs succeed with
structurally verified output. All nine protected originals match the benign oracle;
cleaned runtime coverage remains **6/9**. The .NET 8 and .NET 10 full probes now pass
the former native/JIT failure point and report the same remaining integrity rejection
as .NET Framework: `Probe is tampered.` That separate integrity routine still writes
live shared cache state and remains in place. Malware processing stayed static.

Final decompiler audit: **41/41 outputs decompile**, and every recorded hash matches
the final emitted assembly. Changes remain uncommitted.

## Native wrapper continuation

Native bootstrap extraction now automatically feeds the recovered managed assembly
through the ordinary recovery pipeline. The raw extracted bytes and the wrapper's
report remain separate from the cleaned child and its report. An explicit `--output`
selects the child's cleaned assembly; overwriting the wrapper or raw stage is refused.
`--analyze-only`, strictness, declared libraries, recovery settings and cancellation
carry through. Progress reflects the managed passes after extraction.

The existing bounded traversal owns the entire chain, including any native children:
depth, input-byte and artifact limits and content deduplication cannot reset through
recursive pipeline calls. Without `--recover-embedded`, continuation stops after the
managed stage has been processed and its embedded assemblies extracted. With the
flag, those assemblies are followed as well. Child failures and traversal limits
make the overall result incomplete and link to the child diagnostics.

Static trial: `C:/cilantro-verify/review-trials/native-continuation`.
`WindowsManagement.exe` now yields a structurally verified cleaned assembly after
restoring **28,725 bodies**, resolving **11,108/11,108 detected encrypted string
uses**, making **24,095 proxy calls** explicit and renaming **21,661 symbols**.
One virtualized method and one additional program helper were reconstructed.
The preserved raw stage still hashes to
`83ba5d833eba38f578eb8478f8961a0bddb63ff35016b40d8e0536b164ee1ed3`.
ILSpy successfully decompiles the cleaned assembly (1,303,860 lines).

This is not complete unprotection: 13,566 dispatcher-like patterns remain, the
general payload-extraction pass reports unsupported, and the reconstructed bodies
are not a proof of runtime equivalence. The malware was not executed. The separate
Reactor 7.5 full-protection probe integrity blocker is unchanged: its writes to live
crypto-cache fields still prevent removal of the entire integrity routine.

Regression tests cover continuation, failure propagation, option forwarding,
preservation of raw inputs and shared traversal limits. **770 selected tests pass**;
real-sample tests that depend on the unavailable checkout sample paths remain outside
that selection and are supplemented by static trials in the analysis directory.

Final corpus run: `C:/cilantro-verify/review-trials/native-continuation-regression`.
All **24/24 gates pass**, including the native-wrapper analysis and its automatically
processed managed child. All **10 additional analyst/extra/recursive runs** succeed
with structurally verified outputs. All **32 managed regression outputs** match the
previous validated outputs byte for byte, including their successful decompiler
audit hashes. The new native-wrapper cleaned output was decompiled independently.

## Preserving shared state during integrity recovery

The remaining Reactor 7.5 integrity routine initializes crypto-cache fields that
surviving methods read. Removing the whole routine would discard those writes.
The new `integrity-verdict` pass instead retains the routine, its callers and all
argument evaluation, replacing only a uniquely attributable passing signature
verdict with `true`.

This runs after the late loader recheck. Two complete, independent cold startups
must agree on successful signature verification against the original module file.
The target must be an original non-public, non-generic, argument-free static void
frame, with one direct supported `RSACryptoServiceProvider.VerifyHash` call. Shared
wrappers, multiple verification sites, failed or unknown verdicts, incomplete
interpretation, runtime registrations and image/scratch writes all prevent the
rewrite. File-existence probes alone are not evidence of reading the image.
Reconstructed bodies remain untouched. The edit is transactional and must pass
structural verification.

Early bootstrap evidence may end after decrypting method bodies, before signature
verification. The pass therefore obtains fresh proof after loader cleanup rather
than requiring that the earlier bootstrap already reached the check. Integrity
frame selection now excludes unassigned metadata tokens introduced by reconstruction;
they must not collide in a token-indexed dictionary.

Validation fixtures are under `artifacts/review-trials/reactor75-integrity-verdict`,
with corpus results under `C:/cilantro-verify/review-trials/integrity-verdict-regression`.
The **788 selected tests** include 18 focused checks for attribution, refusal cases,
token handling and retention of stateful argument evaluation. Malware testing is
static; executable comparisons use only the repository-built benign probes.

All **9/9 cleaned benign probes now match their oracle outputs**, up from 6/9.
All nine protected originals also match. Each full-protection target (.NET Framework,
.NET 8 and .NET 10) specializes exactly one integrity verdict and exits successfully;
none times out. The six string/CFF-only and NecroBit-only targets need no such edit.
This establishes the exercised probe behavior, not equivalence of every reconstructed
method or complete removal of protector code.

An unproven verdict is an optional refusal: the routine remains intact and otherwise
valid output can still be emitted. Explicit `FailOnPartial` continues to withhold it.
The Qafcakg payload trial caught this distinction and the pipeline integration tests
now exercise both policies.

Final validation: **24/24 corpus gates pass** and all **10 additional analyst,
extra and recursive runs** succeed with structurally verified output. **41/41
assemblies decompile**, with the audit hashes checked against the final files.
The Reactor 6 profile was rerun after correcting the optional-emission policy.
The native-wrapper child still declines verdict specialization when its bounded
startup proof cannot complete; its extracted/recovered artifacts remain available.
Changes remain uncommitted.
