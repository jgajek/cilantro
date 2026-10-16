# VM validation reference

For contributors and analysts investigating a particular reconstruction difference. Use this reference to establish which initialization, inputs, and captured state a comparison actually covers. For normal case work, start with [VM reconstruction](../devirtualization.md).

For routine use, enable reconstruction (the ordinary CLI default), open the cleaned application and read its validation. The [current status](../status-report.md) verifies physical VM removal across all 14 intact virtualized identities in the frozen corpus. This reference explains reconstruction evidence and its limits.

Reactor can replace a method with bytecode for a custom interpreter embedded in the assembly. Decrypting ordinary method bodies does not restore that method: the program now exists in a different instruction set.

CILantro decodes supported VM programs, investigates their operations, and reconstructs supported programs as CIL. The resulting assembly can be opened in a .NET decompiler. These bodies are interpretations of VM behavior, not recovered original source.

Resource-resolution callbacks raised by assembly resource lookups receive the requesting assembly through `ResolveEventArgs.RequestingAssembly`. Where a resource-manager path has not established that identity, reading it remains unsupported rather than returning an invented assembly.

## What is written

- A `.vmprogram.txt` listing records decoded operations, operands, observations, and unresolved semantics.
- A `.lifted.il` listing shows the inferred CIL-level operations and graph information.
- With reconstruction enabled, supported methods are emitted into the cleaned assembly with `[RebuiltFromReading]` markers. Additional interpreter programs can become helper methods.
- The report records reconstructed counts, coverage, comparisons, and remaining issues.

Ordinary CLI runs enable reconstruction. `--no-devirtualize` disables rebuilding while still allowing disassembly. Strict CLI runs leave VM stubs unchanged; compare a separate ordinary run when reconstruction is wanted. MCP defaults reconstruction off; set `devirtualize: true` explicitly.

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

An additional independently evolved repeat trial warms the original and rebuilt paths separately. In the pinned reconstruction checks, it retains a full-state disagreement even when the separate captured non-VM state matches without shared objects. Agreement after original warm-up does not override that result.

Additional cold-start and repeat-call trials use the run's configured host profile with the same controlled zero-stream fixture. Their evidence names the profile and its SHA-256 so analysts can distinguish these assumptions from the minimal debugger-only trials. Each side gets an independent, strict interpreter: configured host facts are available, but permissive execution settings and declared call outcomes are not imported. Missing facts and unsupported calls still leave the comparison inconclusive. Agreement under a configured profile neither overrides an observed disagreement nor establishes behavior on other hosts.

Reflection over constructed generic methods preserves the supplied method and declaring-type arguments when answering parameter and return-type queries. For example, the parameter of `Array.Reverse<byte>` is reported as `byte[]`, rather than an unresolved generic parameter. Method flags such as `IsVirtual` come from the underlying declaration; framework overload selection distinguishes generic arity and static/instance signatures. These queries read metadata and do not execute the sample through CLR reflection.

## Remaining limits

- The original VM can initialize caches and support state that reconstructed methods do not need. Cold-start full-state comparisons can therefore differ even when the separately captured non-VM state matches. Review the actual comparison coverage and application effects; this does not establish equivalence on another input.
- Unknown values, exhausted budgets, unsupported native effects and incomplete snapshots remain inconclusive. A matched repeat call cannot establish a cold-start result.
- VM invocation discovery accepts simple argument-building sequences and intervening no-ops but rejects branch or exception-region entries into them. Indirect calls and computed program identifiers can conceal programs.
- Lifted initialization helpers receive separate cold-start and repeat-call comparisons through parameterless callers. Those callers' actual argument-building code must be available to interpret.
- Resource-based recovery requires independent initializer proofs. Numeric metadata-token resolution and unresolved reflection can limit safe cleanup.
- Assembly-only type-handle uses are distinguished from reflective member access. A spilled local qualifies only when every read is an assembly lookup and its address never escapes. Other uses remain conservative.
- Protector retirement requires attribution, deadness and absence of surviving references. Matching captured state alone never authorizes deletion of application code.

Use the [output guide](../reading-the-output.md) to locate evidence and [compatibility](../compatibility.md) for support boundaries.
