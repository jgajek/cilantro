> Historical development snapshot. Claims and results may be superseded. Use the [current documentation](../../README.md) for 0.10.0.

# Code organization

`Cilantro.Core` separates the run coordinator from the data and passes it uses:

| Location | Responsibility |
| --- | --- |
| `CilantroPipeline.cs` | Default pass order, run orchestration, reporting and emission |
| `ArtifactContext.cs` | Loaded assembly, trusted libraries, facts, evidence and change records |
| `Pipeline/` | Pass contract, options/results and execution planning |
| `Reporting/ReportModels.cs` | Public report records |
| `Passes/`, `Recovery/`, `Strings/`, `Payload/`, `Proxy/` | Detection and recovery stages |
| `Verification/` | Assembly validation, identity/structure checks and mutation rollback |
| `Analysis/`, `Codec/` | Analysis and decoding helpers |

Types extracted from `CilantroPipeline.cs` retain their `Cilantro.Core` namespace and public
signatures. File placement does not require callers to change imports. Pass ordering remains in
`CilantroPipeline.CreateDefaultPasses`; dependencies and planner decisions still control execution.

## Mutation ownership

Use `InstructionMutationTransaction` for opcode/operand edits, `BodyMutationTransaction` for one
complete method body, and `BodyMutationBatch` for a rewrite spanning multiple bodies. Capture before
editing. A batch captures each method once, even when several call sites belong to that method.
Keep the batch in a `using` scope so an exception or early return restores every uncommitted body.

Verify the rewrite before calling `Commit`. Change records queued through `RecordChange` become
visible only on commit; rollback discards them. A batch owns body snapshots and pending records,
not changes to fields, resources or type declarations. Those need their own rollback handling.

Tests exercise commit, rollback, repeated capture, exception unwinding and the recovery passes
that use these transactions. Corpus gates and emitted output hashes check that structural
refactoring preserves sample results.

`Reporting/AnalystSummary.cs` builds the shared console and HTML summary.
`Reporting/AnalystArtifact.cs` combines extraction provenance with child-run
results to prioritize artifacts. `Reporting/AnalystReport.cs` renders the offline
HTML report with expandable technical details. The CLI adds optional diagnostic detail to that summary;
the pipeline writes the HTML for managed and native-wrapper runs alike.

`Pipeline/EmbeddedAssemblyRecovery.cs` follows extracted assemblies with shared
hash deduplication and depth/count/byte limits. Child runs reuse the pipeline with
recursive traversal disabled and isolated output paths. `DevirtualizedRun`
requires coverage of every reconstructed body before accepting its limited
payload-comparison check; lifted helpers currently remain outside that check.

## Readability after recovery

`Analysis/LocalConstantPropagation.cs` tracks Int32/UInt32 locals across normal
control-flow edges. Joins keep only values agreed on by every incoming path;
loops converge before any instruction changes. Unknown operations discard stack
knowledge, address-taken locals are excluded, and methods with exception handlers
retain the existing cleanup analysis. A bounded analysis that cannot converge
makes no edits. The caller's body transaction checks and rolls back rewrites.

Constant-helper folding records the helpers whose calls were removed only after
verification commits. Runtime cleanup applies its reachability and reference
checks to those candidates, then rechecks dead types after orphaned methods are
removed: a removed signature may have been a type's last reference.

Symbol renaming recognizes array element types and simple field-reader methods.
These names describe observed structure rather than assigning a malware role;
the existing public API, virtual dispatch, interop and serialization restrictions
remain in force. Renaming maps preserve the original identities.

Numeric recovery uses `Recovery/NumericTableRecoveryPass.cs` for private,
initializer-owned integer arrays and `Recovery/IntegerHelperRecoveryPass.cs` for
bounded, pure integer helpers. Table interpretation uses an empty host profile
in strict mode, so host assumptions cannot become constants in the output.
Array alias checks and initializer-effect checks precede any replacement; two
independent machines query indexes in opposite orders. Rewrites commit only
after module verification, then become candidates for ordinary orphan cleanup.

`Passes/DispatcherPathPass.cs` follows known state through bounded, pure integer
update blocks and redirects it to a switch destination. It retains the final
state assignment and respects exception-region boundaries. Each verified rewrite
is applied separately before recomputing the graph, since two candidate paths
can depend on each other's original state updates. Unknown values and calls stop
the proof. `DispatcherAnalysis` also recognizes constant selector chains, while
`ControlFlowCompletionPass` folds exposed nonthrowing integer arithmetic.

`Passes/DispatcherTailSeparationPass.cs` runs before dispatcher solving. For a
recognized ConfuserEx dispatcher, it copies a short, shared integer computation
onto each incoming unconditional branch. Conditional arms then have separate
instructions at which the solver can observe their states. The copies preserve
operations and operands exactly; they do not guess a state or bypass a call.
Methods with exception handlers are excluded. Per-tail and per-method expansion
limits bound code growth, and a body transaction verifies the resulting stack.

Numeric table and pure integer helper recovery run again after loader-call
elision and wrapper redirection. A table that initially depended on loader setup
can then be read without host assumptions. Pure helpers may also be folded when
their type initializer contains only `nop` and `ret`; an initializer with remaining
work still prevents folding. Both retry passes contribute to the numeric recovery
count in the analyst summary.

## Reconstruction and conservative follow-ups

`DevirtualizedRun` prepares its comparison copy only up to loader-call elision,
so preparation cannot delete the path it is supposed to test. Successfully lifted
programs keep a recovery recipe; `VirtualizationRebuildPass.InstallLiftedCopies`
remaps those recipes to the comparison module, rebuilds the same helpers and
redirects the matching engine calls. Comparison-only helpers receive unique row
identities for entry tracking. Emitted helpers retain the existing added-method
accounting. Matching payloads still do not validate any body that was not entered.

`VirtualLift.Types` now carries exact closed reference types from parameters,
fields, calls, constructors and string literals, as well as value types. Joins
of unlike types fall back to object. `VirtualBody` only boxes value types when
adapting a settled value back to object, and can avoid redundant reference casts.
Open generic, pointer and by-reference types remain untyped here.

Dispatcher-tail separation can now work inside exception regions when the branch,
every copied instruction and the dispatcher destination have identical region
membership. Existing instruction objects preserve boundary identity; the pass
inserts copies locally and verifies under a body transaction.

Numeric-table recovery can retain an effectful type initializer with an explicit
`RuntimeHelpers.RunClassConstructor` before the recovered constant. This only
applies to a closed, non-generic owner with precise initialization semantics and
no mutable external static inputs found through its initializer call graph.
Host-independent interpretation and private-array checks still apply. Calls from
inside that same owner are excluded from this effect-preserving rewrite.

Instance-sensitive cleanup recognizes a type token carried through uniquely
assigned locals. Such a token already exposes its exact type to the ordinary
reachability walk. Reassignment, an escaped local address or an unknown origin
retains the wider conservative reachability result.

### Controlled reconstruction trials and initializer dependencies

`RebuiltMethodTrial` compares the prepared original VM stub with rebuilt CIL on
bounded fixtures in fresh strict interpreter states. Its heap snapshots preserve
aliases and normalize supported objects, arrays, strings and boxed values.
Unsupported or incomplete interpretation is inconclusive; it never constitutes
agreement. `DevirtualizedRun` records these observations independently of payload
coverage, and a direct discrepancy prevents an overall agreeing verdict.

`VirtualLift` uses recovered paired handler boundaries before trying the fallback
for unpaired regions. Catch entries receive an exception; finally/fault entries
receive an empty stack. Unreached-operation diagnostics refer explicitly to the
recovered graph, and `VirtualBody` retains fail-fast placeholders.

Numeric-table initialization proofs distinguish dependencies of a final fresh
holder and closed literal lookup assignments from earlier initialization effects.
Preserved effects use the original static-field access. When a separate getter
type requires an explicit initializer trigger, the interpreter uses its existing
initialization state machine and work budget. Unknown mutable dependencies and
array escapes still refuse replacement.

Instance-aware reachability checks reflection at the reachable fixed point before
falling back to broad retention. Finite local assignments of known type tokens do
not count as unknown construction. Rebuilt-body cleanup also invokes the existing
verified dispatcher solvers. Semantic naming follows bounded acyclic forwarder
chains and identifies simple field setters without guessing application purpose.


The additional stream fixtures use explicitly simulated debugger states, with no
inherited workstation facts. A completed-versus-thrown discrepancy remains a
discrepancy even when an opaque static object prevents full snapshot comparison.
Snapshots name the first unsupported root. Numeric dependency refusals include a
bounded call/initializer path and distinguish conservative reachability from a
proven data dependence. Literal array proofs also cover publication followed by
closed literal stores; calls after publication and escaping references refuse it.

Fixed type-token helper chains can narrow reflective construction. Dispatcher
path evaluation handles CIL integer shift masks and signed/unsigned comparisons;
the boundary-value tests compare interpreter outcomes before and after rewriting.
The benign `RecoveryGroundTruth` source is shared by the three-target probe and
test project, allowing cleanup/interpreter checks against real .NET returns and
array mutations. Integer division-by-zero reaches a modeled catch; implicit
exception transfers requiring unimplemented finally unwinding remain unsupported.


Fresh Reactor trials also cover markerless NecroBit bodies with EH regions at
zero. Their offsets are interpreted with the actual marker length, and native
record pointers must name scratch storage rather than the mapped stub image.
Runtime-provided delegate methods are retained on surviving types. Control-flow
cleanup removes only proven unreachable terminal suffixes, mapping exclusive EH
ends there to end-of-method; other pinned boundaries keep their continuations.
The executable benign probe runner checks restored returns and array mutations
separately from structural verification and records remaining loader failures.

`IntegrityVerdictPass` follows the late loader recheck. When an integrity routine
must remain to initialize shared state, two complete agreeing cold startups can
justify specializing one uniquely attributed original-file signature verdict.
The routine and its argument evaluation remain; reconstructed and shared verification
helpers are not rewritten. This proof is distinct from removing an effect-free
integrity frame in `AntiTamperNeutralizationPass`.
