# Virtualized methods

For routine use, enable reconstruction (the ordinary CLI default), open the cleaned application and read its validation. The [current status](status-report.md) verifies physical VM removal across all 14 intact virtualized identities in the frozen corpus. This technical reference also retains earlier diagnostic checkpoints; their unresolved observations are not the current corpus verdict.

Reactor can replace a method with bytecode for a custom interpreter embedded in the assembly. Decrypting ordinary method bodies does not restore that method: the program now exists in a different instruction set.

CILantro decodes supported VM programs, investigates their operations, and reconstructs supported programs as CIL. The resulting assembly can be opened in a .NET decompiler. These bodies are interpretations of VM behavior, not recovered original source.

Resource-resolution callbacks raised by assembly resource lookups receive the requesting assembly through `ResolveEventArgs.RequestingAssembly`. Where a resource-manager path has not established that identity, reading it remains unsupported rather than returning an invented assembly.

## What is written

- A `.vmprogram.txt` listing records decoded operations, operands, observations, and unresolved semantics.
- A `.lifted.il` listing shows the inferred CIL-level operations and graph information.
- With reconstruction enabled, supported methods are emitted into the cleaned assembly with `[RebuiltFromReading]` markers. Additional interpreter programs can become helper methods.
- The report records reconstructed counts, coverage, comparisons, and remaining issues.

Ordinary CLI runs enable reconstruction. `--no-devirtualize` disables rebuilding while still allowing disassembly. Strict CLI runs require explicit `--devirtualize`. MCP defaults reconstruction off; set `devirtualize: true` explicitly.

## How the reading is established

The tool interprets the sample's decoder to recover programs, observes handlers with controlled values and in program context, resolves metadata operands, and checks the inferred control-flow graph and stack depths. Supported exception regions and local types are reconstructed where the evidence supports them. Cleanup then simplifies the rebuilt bodies.

A stack-consistent graph is useful evidence, not behavioral proof. An operation's stack effect alone does not establish its semantics. Operations that remain unresolved can prevent reconstruction; unreachable regions may retain fail-fast placeholders rather than invented implementations.

For otherwise inferred branches, additional trials calibrate the interpreter's position
field against two distinct observed destinations and check the particular instruction
with separating stack values. Conditional trials must exercise both outcomes. Switch
trials check every table entry plus negative and upper-bound selectors, even if one
destination was already observed. These measurements are recorded as
`vm-branch-target-trials` and `vm-switch-target-trials`; they do not establish behavior
for arbitrary engine state.

## How to judge the result

When the supplementary non-VM snapshot matches, trials also check whether the VM and non-VM root graphs share modeled heap objects or collection state within each machine. A successful bounded traversal can establish absence of such sharing in that captured state; unsupported or over-budget graphs cannot. This does not rule out reflection, unmodeled external state, or aliases created by later calls, so it does not change the full-state verdict.

Controlled-trial diagnostics distinguish differences confined to static roots owned by the original VM type hierarchy. A supplementary snapshot omits those roots and renumbers objects independently, preserving aliases among the remaining roots; otherwise discarded VM objects could shift numbering and make unchanged application objects appear different. The supplementary match requires return/exception, argument, other static-root, network-setting, and native-memory snapshots to match. It is a localization of observed differences, not an escape analysis: aliases between VM and application roots, reflection, or later calls could still expose VM state. The full snapshot and overall disagreement remain unchanged until those effects are justified.

AppDomain event modeling preserves the subscription order of supported single-target managed delegates. Removing an equivalent delegate removes its last subscription, and null handlers do not change the list. Resource resolution invokes a snapshot of that list with the application domain as sender, stopping at the first returned assembly. This improves resource recovery when loaders register more than one handler. Subscription lists are bounded to 4,096 entries; unsupported delegate forms stop interpretation. These modeled subscriptions do not yet establish equivalent external registration effects in controlled trials.

Modeled `ServicePointManager` settings are also captured in controlled comparisons. They belong to each interpreter machine, so sharing an intrinsic cannot carry settings between trials. A difference in settings such as `SecurityProtocol` is reported even when return values and managed statics match. This checks stored settings, not network behavior; callback registrations and `SetTcpKeepAlive` effects remain inconclusive.

Read **Validation** and **Needs review** before treating a reconstructed body as reliable. The detailed evidence distinguishes two forms of comparison:

| Comparison | What it checks | What it does not prove |
| --- | --- | --- |
| Payload comparison | Original and reconstructed paths produce the same extracted bytes in bounded interpretation | Every VM method was exercised or all application behavior agrees |
| Controlled method trials | Selected input/state combinations have matching observable outcomes | All inputs, complete external state, or native runtime behavior |
| Repeat-call trial | After one original call on each independent machine, a second original call and a rebuilt call match on fresh controlled arguments and captured state | Cold-start equivalence, safe removal of initializer effects, or other inputs |
| Independent repeat-call trial | Each side evolves through its own first call; the second call also compares retained first-call arguments/results and aliases | Arbitrary call sequences or external callbacks |
| Coupled-startup trial | Original bodies initialize one machine; all reconstructed bodies/callers are installed before the other machine initializes | Every startup input, final cleanup effects or native runtime execution |
| Resolver-callback trial | Ordered requests for declared assembly/resource names and a missing name, with null/home requesters and a closed home/observed-load inventory; captures state before callbacks and at each response | Arbitrary requested names, external requesters, other preloaded assemblies or unsupported callback paths |
| Application-contract assessment | Completed trials preserve captured application state while allowing confirmed protector-metadata removal; checks VM sharing, escaped handles and final field removal | Full-state equality, inconclusive fixtures or untested paths |
| Modeled native-memory comparison | Captured region bytes, addresses, pointer offsets and aliases, ordered writes, and image-protection records match | Native execution, unmodeled external effects, or equivalence after relocating raw pointer bytes |

An `agreed` verdict is limited to the checks and coverage described. `notMade` includes inconclusive comparisons, such as unsupported state or unexercised bodies. `disagreed` requires investigation even if structural verification and the overall run succeeded.

Keep artificial cold-state fixtures separate from application startup. A trial that calls
a method while skipping the module initializer deliberately examines a state that normal
CLR execution cannot enter from outside that initializer. The [.NET module-initialization
guarantees](https://github.com/dotnet/runtime/blob/main/docs/design/specs/Ecma-335-Augments.md#module-initialization-guarantees)
require initialization before ordinary method execution or static-field access. Such a
fixture can expose a dependency, but a startup conclusion requires the coupled-startup
trial, including effects of reconstructed methods called during initialization. Neither
kind of trial replaces validation of the final emitted assembly.

Controlled trials include bounded snapshots of modeled lists, dictionaries, and hashtables, preserving collection order, contents, aliases, and cycles. Raw byte and integer arrays carried by framework models are also compared in full, including loaded assembly images, symbols and version components; their aliases are retained and their bytes count against the binary budget. Metadata handles are compared using shared identities within the loaded module context, rather than names or heap allocation numbers. Snapshots allow up to 65,536 nodes, retain depth and text limits, and distinguish node exhaustion from depth exhaustion. Unsupported state and exhausted budgets still make a comparison inconclusive. State mismatches identify the first differing root and say when the return/exception and argument snapshots matched; thrown outcomes retain their diagnostic location.

Native snapshots include all modeled regions, even those no longer referenced by managed objects, and the ordered write history. Matching final bytes alone does not hide different writes. Absolute addresses remain part of the comparison; heap allocation IDs are normalized, but bytes that might contain pointers are not rewritten. Native regions, write records, and managed byte arrays share a 32 MiB byte allowance; native snapshots also limit work to 4,096 regions and 262,144 writes. Byte arrays are compared in full by content hash, retaining their identity without spending a graph node per byte. Potentially truncated image-protection histories remain inconclusive. Registrations recorded only as descriptions also remain inconclusive: identical descriptions do not establish identical handlers, arguments, or external effects.

For example, tracing the Mlfhntkcvb debugger-present trial identifies an original protector initializer calling `nHl4SRTNAC` (`060002B7`), which throws `System.Exception("Debugger Detected")` at `IL_0014` before VM dispatch. The rebuilt path bypasses that initializer and completes. With the debugger absent, both paths complete and their return/argument snapshots match, but VM-engine static state differs. Qbjuef also has this static-state difference. Both pass the repeat-call trial on the 32-byte zero-stream fixture after identical original setup, including captured static state. This narrows the observed discrepancy; it does not establish equivalence for other inputs or justify discarding startup effects. Cold-start differences retain the overall `disagreed` verdict even when a repeat-call trial agrees.

The repeat-call trial requires a completed original prelude on both sides and uses fresh measured arguments. Warm-up and measurement share a budget per machine: four million steps by default, raised by a larger `budgets.steps` declaration. Trial evidence records the effective limit. VM-entry coverage is measured after warm-up, so a prelude that enters the engine cannot make an unexercised second call appear validated.

Additional cold-start and repeat-call trials use the run's configured host profile with the same controlled zero-stream fixture. Their evidence names the profile and its SHA-256 so analysts can distinguish these assumptions from the minimal debugger-only trials. Each side gets an independent, strict interpreter: configured host facts are available, but permissive execution settings and declared call outcomes are not imported. Missing facts and unsupported calls still leave the comparison inconclusive. Agreement under a configured profile neither overrides an observed disagreement nor establishes behavior on other hosts.

Reflection over constructed generic methods preserves the supplied method and declaring-type arguments when answering parameter and return-type queries. For example, the parameter of `Array.Reverse<byte>` is reported as `byte[]`, rather than an unresolved generic parameter. Method flags such as `IsVirtual` come from the underlying declaration; framework overload selection distinguishes generic arity and static/instance signatures. These queries read metadata and do not execute the sample through CLR reflection.

## Remaining limits

### Diagnosed cold-start differences

The initial September 2026 audit of Qbjuef and Mlfhntkcvb.payload.Lqcuzgc separated a full-state mismatch from a mismatch in recovered application work. Before the additional helper comparisons described below, a 32-million-step budget and controlled 32-byte zero streams produced these results:

| Sample | Captured non-VM state | Other evidence |
| --- | --- | --- |
| Qbjuef | Matched in all three differing cold-start trials; no modeled objects shared across the VM/non-VM boundary | Both repeat-call trials agreed. Payload bytes matched, but extraction exercised only one of two reconstructed bodies. |
| Mlfhntkcvb.payload.Lqcuzgc | Matched in two of three differing cold-start trials; no modeled objects shared across the boundary in those two | The debugger-present trial still differs: the original protector throws and the rebuilt method completes. Both repeat-call trials agreed. |

The original VM initializes caches and interpreter support state that the rebuilt method does not need. This accounts for the localized static-state differences on these fixtures; it does not establish equivalence on other inputs. Three additional trials per sample remained inconclusive. Both cleaned assemblies passed structural verification.

The initial cleanup obstacle was numeric metadata-token resolution. Follow-up work found that resource-based recovery skipped independent initializer proofs when bootstrap evidence was absent, and that `typeof(T).Assembly` incorrectly exposed all members of `T` to reflection in reachability analysis. Independent proofs now run without bootstrap evidence. Assembly-only type-handle use, including intervening no-ops and a redundant `System.Type` cast, no longer implies reflective access to the type's members. A local spill is accepted only when every read is an assembly lookup and the local's address never escapes. Other uses and control-flow entries into those sequences remain conservative. Cleanup still requires attribution, deadness and absence of surviving references; the captured-state comparison alone never authorizes deletion.

VM invocation discovery also tolerates no-ops between simple argument loads, while rejecting branch or exception-region entries into the argument sequence. This finds Mlfhntkcvb's additional 832-operation initialization program. Helper substitution removes the complete proven argument sequence rather than assuming a fixed number of adjacent instructions. Indirect calls and computed program identifiers can still conceal programs.

Lifted initialization helpers now receive separate cold-start and repeat-call comparisons through their parameterless callers, using those callers' actual argument-building code. Both the original VM entry and the rebuilt helper must be exercised. These trials run even when the module extracts no payload, preserve independent machine state, and use the configured host profile under strict interpretation. They complement payload coverage rather than silently counting as coverage of the unpacking path.

Cold initializer proofs honor declared step budgets, including their shared proxy-initializer allowance. Large proxy sets can exhaust that allowance; retained initializers are reported rather than treated as proven inert. Raising the analysis budget permits more proofs without weakening their requirements. Protector guard removal remains distinguishable from an accidental behavior change, and full-state disagreement is not converted to `agreed` by cleanup.

The final cleanup trials removed 200 protector support types and 1,444 methods from Qbjuef, and 564 types and 2,930 methods from Mlfhntkcvb.payload.Lqcuzgc. Method totals include methods belonging to removed types. Mlfhntkcvb required a 192-million-step declaration to independently prove all 514 proxy initializers inert. Its newly discovered initialization program rebuilt into 1,163 CIL instructions. Both samples' additional helper trials matched captured non-VM state on cold start, with no shared modeled objects across the boundary, and matched full captured state on repeat calls. Both cleaned assemblies passed structural verification and ILSpy decompilation; Qbjuef's two extracted payload hashes were unchanged.

Validation passed all 24 runnable corpus gates, 859 selected regression tests, and ten runtime comparisons against a source-built benign Reactor 7.5 fixture. Malware corpus trials remained static. Separate [reconstruction cleanup gates](corpus.md#reconstruction-cleanup-gates) enforce the removal counts and helper comparison evidence while requiring the full-state disagreement to remain visible. These results establish the stated checks, not equivalence for every input or complete unprotection of the corpus.

Reports now summarize the localized trials separately from other disagreements, using `reconstruction-state-boundary` evidence in the analysis JSON and the Validation section of analyst output. These findings close the diagnosis of the observed warning; they do not claim complete unprotection or whole-corpus equivalence.

VM removal is checked separately from reconstruction agreement. Cleanup can remove a
positively identified, replaced engine and its nested types when surviving declarations
no longer reference them, even when unrelated application reflection prevents precise
general reachability. Recognized, fully recovered delegate-proxy types receive the same
reference check. Reconstructed application methods remain roots. Opaque numeric metadata
lookups still prevent row deletion; a proved lookup using the same live member's `Module`
and `MetadataToken` can tolerate row compaction.

Cleanup also removes embedded VM data referenced exclusively by the removed engine,
excluding resources identified as application payloads or restored application resources.
Removal records retain resource hashes, and the original input retains the bytes. The
`vm-machinery-removal` evidence counts declarations actually removed or retained. Neither
successful reconstruction trials nor successful emission mean the VM is gone: use the
[emitted-metadata removal gate](corpus.md#reconstruction-cleanup-gates), inspect the cleaned
CIL, and separately check application behavior and payload preservation. A previously
rewritten assembly with stale VM tokens can still require its intact original.

Complex exception paths, reflection, unknown state, and sample-specific handlers can prevent complete lifting or validation. “No direct callers” does not exclude reflective calls. A remaining dispatcher is not necessarily a protection artifact, and a decompiler's readable C# is not the original source.

Use the [output guide](reading-the-output.md) to locate evidence, [compatibility](compatibility.md) for release boundaries, and [historical research](history/pre-0.10/devirtualization.md) for earlier implementation experiments.
