# Compatibility and provenance

## Corpus and support contract

The manifest at `corpus/reactor-6-nonvirt.manifest.json` contains nine
SHA-256-pinned entries:

- two `profiled` full-recovery fixtures;
- three `detected` JIT-hook/method-stub samples;
- one `exploratory` control-flow/proxy sample; and
- three deobfuscated validation oracles used as negative controls.

The three oracle assemblies are never implementation inputs. After recovery,
they are compared by assembly identity, entry-point kind, normalized method
signatures, public API sets, and resource sets. Binaries remain ignored under
`samples/`.

The batch runner verifies each input hash before analysis. `profiled` and
`detected` entries must emit deterministic verified output; `exploratory`
entries remain analysis-only; negative controls must receive no destructive
edits. Recovery expectations include restored-body counts, remaining-stub
limits, string-site coverage, mutation limits, and optional oracle parity, plus
gates for recovered booleans, restored tokens, restored resources, maximum
remaining switch dispatchers, maximum unreachable instructions, and an expected
unsupported diagnostic for native-packed inputs.

```bash
dotnet run --project src/ReactorUnpack.Cli -- corpus run
```

The full-recovery profile was derived independently from:

- `ad0c3182b18b5d7ba8771d830f4d51b4ada7e26f8d05223f4379e6312aba65fa`
- `c405398fc582e33bbbd37222b7360a6cfdc526146622141503de1ccf9de6174a`

Both are x86 .NET Framework 4 assemblies protected by the same .NET Reactor 6
runtime generation. Detection uses structural evidence rather than randomized
names:

- 279 `MulticastDelegate` proxy types;
- 1,341 methods with a branch over an unreachable invalid call;
- a resource-backed method-token resolver;
- dynamic-method and delegate-construction APIs; and
- malformed decoy metadata references.

## Implemented formats

### Recovery trust boundary

The pipeline is divided into preflight, analysis, original-byte recovery,
IL-transform, and verify/emit phases. A JIT-hook artifact cannot enter any
downstream mutating pass until complete method restoration is proven.
`PeImageView` validates PE32/PE32+ sections, maps RVAs without treating virtual
zero-fill as file data, and constructs a bounded loader-style image.

The bounded CIL machine models concrete values, objects, arrays, managed and
synthetic native pointers, static/instance fields, branches, switches, and
single-level deterministic finally flow. Framework calls are deny-by-default.
Allowlisted models cover resources, streams/readers, encoding, hashing,
decompression, symmetric crypto, synthetic module/process metadata, Marshal
operations, and virtual memory writes. Unknown branches, unmodeled calls,
symbolic writes, malformed ranges, and exhausted budgets stop recovery.

Every method mutation has a full-body transaction. Instructions, branch
operands, locals, max-stack settings, and exception handlers are restored
together on rollback.

### Dispatcher recovery

An EH-aware basic-block graph distinguishes raw switches from qualified Reactor
dispatchers. Rewrites require a unique state local, complete incoming-edge
accounting, concrete transitions, legal EH-region edges, and valid stack
analysis before and after mutation. Ambiguous methods are preserved.

### Invalid-call prefix

The normalizer recognizes only the proven entry sequence
`branch instruction[2]; call unreachable; instruction[2]`. Both instructions
are replaced with `nop`, preserving branch and exception-handler references.
Operand validation is performed on reachable instructions.

### Proxy map generation R6-2026-A

The 2,232-byte resource is decoded as a stateful little-endian UInt32 stream.
The result must match its profile hash and contain exactly 279 eight-byte
records:

```text
uint32 fieldToken
uint32 encodedTarget

targetToken = encodedTarget & 0x3fffffff
callvirt    = (encodedTarget & 0x40000000) != 0
```

Every field and target token is resolved before any edit. A valid use site is
the adjacent pair `ldsfld mappedField; call staticAdapter`. It is rewritten to
`nop; call|callvirt target`, preserving stack behavior and instruction
identity. Each fixture has 2,643 validated sites, and all of them are rewritten:
proxy restoration runs before forwarder redirection, so no site has already been
turned into a direct call by the time it looks.

The generic strategy locates a resource whose length equals eight bytes per
proxy field, extracts candidate stream constants from the token-resolver IL,
and accepts a pair only when every decoded field and method token resolves and
the mapping is bijective. This derives Qbjuef's 146-record generation
(`A=0x64875CD0`, `D=0x7511923A`) without its input hash. Known hashes remain only
as regression fallbacks.

### Embedded resource assembly

The protected host's `ResourceResolve` path consumes the large, high-entropy
resource and eventually passes decompressed bytes to `Assembly.Load(byte[])`.
ReactorUnpack models that load as a capture sink and never invokes it.

The general route is to interpret the module's own unpacker and take the bytes
as they reach that sink, which needs to know nothing about the cipher or the
number of stages. It is tried first, and it is what recovers payloads from
crypters the tool has never seen.

It reaches both stages of both fixtures, which is worth stating because of what
stands between the entry point and the payload. Underneath Reactor these samples
carry a second protector that virtualizes the crypter's module initializer: the
initializer's work is carried out by a bytecode dispatcher rather than by IL,
and the fields it sets are read both by the chain's flattened control flow and
by the string-table indices that supply the driver its resource name and key.
Nothing lifts that bytecode back to IL. The machine instead runs the dispatcher
as the ordinary IL it is, and the chain's own behaviour follows: the string
table decrypts, the protector's resource-resolve handler is raised the way the
runtime would raise it, the satellite it returns is read for the encrypted
stage, and the stage decrypts to an assembly. Running the virtual machine rather
than defeating it costs a great deal of interpretation — roughly a minute for
these samples — which is why the step allowance is raised only for a chain that
has already shown it ran out of the ordinary one.

There is no longer a second route. Until the machine could run the virtualized
initializer, these two fixtures were extracted by a table of their input hashes
that carried the cipher, the keys, and the expected outputs; the generic route
now reproduces every one of those hashes, so the table is gone. What each stage
must satisfy has not changed: a buffer is believed only when it parses as
managed metadata, and only when two independent interpretations produce the same
bytes.

Recovered resource-only assemblies:

- `f94b00a2-0086-4424-b9df-e76ba48d2dee.dll`, 485,376 bytes,
  SHA-256 `7fa1a9d74dad14fd686ad7b2e794111d1093de3fefe97c51d1908e44586d04de`;
- `cf07e290-4799-450f-969c-80255a1a4f0c.dll`, 86,528 bytes,
  SHA-256 `1db4e9c40d83bb790b89963888fd9a112b1d2467f7194dc55b6c35e14e443429`.

Each resource assembly contains one terminal `.resources` v2 ByteArray record
holding the second stage. The tool does not decode that record itself; the
crypter's own driver does, under interpretation, and the bytes are taken where
it hands them to `Assembly.Load`. That the stage happens to be TripleDES-CBC
under a GZip stream is something the run reveals rather than something the tool
knows. The final load and the reflective entry-point call are never performed.

Final managed payloads:

- `Lqcuzgc.dll`, 858,112 bytes, SHA-256
  `81cf796c987dbffeb950e38d7e4bc01e85bec2ef4b5a9750d9642843f8460c2a`;
- `Ptnifif.dll`, 154,112 bytes, SHA-256
  `e4e746f968a3ec89027484ab233d3d38c7778458a898d30f31bb74a2c97059d2`.

### Virtualized methods

Three fixtures carry a code virtualizer under Reactor. It is detected by the
shape of what it must leave behind rather than by recognizing the engine: a stub
that packs every one of its arguments into an object array in order, passes a
constant identifying which program to run, calls once, and returns. Nothing in
that shape depends on the engine's names, its bytecode framing, or its version,
and it holds across all three fixtures, whose engines share no names at all. It
fires on none of the five fixtures that are not virtualized.

Beyond naming the affected methods, the program behind each one is recovered by
running the engine's own decoder under the machine and reading the decoded
operations back off the heap. Writing a parser for the bytecode would mean
writing one per engine; the module already contains one that is exactly right.
What comes back is the whole program and not a trace of one run, because the
engine decodes all of it before executing any of it, and the list is taken at
the moment the first operation executes. The stub is entered with empty
arguments and the run is then allowed to fail however it likes, so as little of
the hidden code runs as possible.

| Fixture | Virtualized methods | Operations | Distinct operations |
| --- | --- | --- | --- |
| `embedded_dotnet_Qafcakg.exe` | 1 | 2,935 | 29 |
| `embedded_dotnet_Mlfhntkcvb.exe` | 1 | 2,952 | 29 |
| `Qbjuef.exe` | 1 | 3,007 | 29 |

Each program uses exactly 29 distinct operations, numbered sparsely below 175,
and the three prologues are the same sequence under a renaming — the first
eleven positions agree in shape across all three, sixteen between `Qafcakg` and
`Qbjuef` — while no two of them agree on a single number. The opcode sets
themselves overlap only four to six values out of 29. So the numbering is
assigned per build, and a table of meanings learned from one sample would not
merely fail on the next, it would misread it.

The listing therefore reports the operation numbers, their operands, and —
because an operand that is a metadata token resolves against this module — the
methods, fields, and types the hidden code reaches for. For `Qafcakg` that is 29
distinct named references, 28 of them into the module itself. Among them are a
`CryptoStream` constructor, a method taking a `CipherMode`, and the crypter's
own stream reader, which between them say what the method is for even before any
of its operations are understood.

### What the operations mean

Meanings are derived per sample, from the engine in front of us. Its handlers
belong to the engine rather than to any one program, so an operation can be
performed on its own: the engine's live state is captured, its stack is seeded
with values we chose, it is handed a single operation, and the stack it leaves
is read back. The operation given to it is one the program really contains,
taken from the decoded program, because an invented operand is what makes an
operation that indexes a table fault instead of answering.

Every conclusion rests on four trials with different values, and a name is given
only where exactly one candidate survives all four. One trial is not enough: on
7 and 3 subtraction and exclusive-or agree, and only a second trial separates
them. The last trial repeats its top pair, because a conditional jump never
fires when every value differs and would otherwise be recorded as an operation
that merely consumes two values.

An operation that refuses a stack of numbers does not say what it wanted, so the
arrangements it might have wanted are offered in turn — an array beneath an
index, an array on top, an array beneath an index and a value — and the one it
accepts is reported alongside the effect, because an operation that will only
run with an array beneath an index is indexing an array whatever else remains
unknown about it. The arrays offered are a different length in every trial and
filled with values that depend on where they sit, which is what separates an
operation that reports a length from one that returns a constant, and one that
reads an element from one that returns the index.

Nine meanings come out of the trials, and the same nine out of all three
engines, under numbering they do not share:

| Meaning | `Qafcakg` | `Mlfhntkcvb` | `Qbjuef` |
| --- | --- | --- | --- |
| exclusive-or | 57 | 17 | 58 |
| add | 87 | 58 | 68 |
| subtract | 109 | 107 | 60 |
| duplicate top | 48 | 42 | 157 |
| array length | 51 | 53 | 173 |
| writes an array element | 139 | 169 | 1 |
| widen a value | 22, 88, 112 | 87, 102, 168 | 127, 154, 172 |

Twenty of the 29 operations in each sample can be performed in isolation; the
other nine fault without the surrounding program, and the run reaches six of
those another way. Of the twenty, nine are named here and the other eleven are
reported as what was counted — how many values went in, how many came out, and
whether the engine's own state changed — until the run names most of them too.

Whether the engine's state changed is not decoration. What is watched is its
fields and
arrays, not just the numbers it holds directly, because an operation that stores
into a local writes an array element; and the state is put back between trials,
because an operation that writes the same value every time otherwise appears to
change something once and nothing afterwards. Both were real errors before they
were fixed, and both produced the same kind of wrong answer: an operation that
does something reported as doing nothing. That is worse than declining to name
it, since a reader told an operation is inert will take the code after it for
unreachable.

For the same reason nothing is named on the strength of the stack alone. An
operation that consumed a value and showed nothing else is reported as having
done exactly that, rather than as discarding it, because a write to somewhere
outside the walk — a static field, say — would look identical from here.

Why the nine were declined is reported as well, since it is what says where to
look next, and it is written into the listing under the operations. In every
sample they divide the same way: three index something the surrounding program
would have filled in, two want a value of a kind we do not know to offer, two
throw, and two the machine could not follow. Only the first group looks out of
reach by this method; the rest are gaps in what we know to put in front of the
engine, or in the machine itself.

### Where the operations go

None of the above finds a jump, and no amount of asking would. An operation
performed on its own cannot go anywhere: the engine's position is wherever the
last real run left it, so a handler that works out a target from it produces a
number nothing can check, and the operation is written down as having consumed
its values and done nothing. That reading is not merely incomplete but
misleading, since a reader told an operation is inert will take the code after
it for unreachable.

Several things that ought to have found it did not, and ruling them out is what
left watching as the answer. Nothing the engine can reach behaves like a
position: 79 integers across 121 places, eight levels out, were each set in turn
to the index of the operation being performed, and none of them changed what any
handler did. The one field that operations do write takes the same value every
time, whatever the operand and whatever is on the stack. Nor is the state the
problem. Entering the stub runs 6 of 2,935 operations, and both richer states
are worse: run to the end it characterizes 13 operations rather than 20, and
stopped halfway, 14.

So the engine is watched instead. It has to be run once anyway for it to exist,
and what is watched is not its state but the order it does things in: which
operation is performed after which. If that is not the next one along, the one
before it jumped, and it jumped somewhere that really is another operation of
the same program. This needs no view of where the position is kept, which may be
an offset, an index, or nowhere addressable at all.

For that to show anything the program has to actually run, and handed the
nothing that a stub is entered with, it stops at once — the method here is a
stream reader, and its seventh operation builds a reader over the stream it was
given. Its own caller has the real one. Entering there instead, the engine runs
3,500 operations, and

| | `Qafcakg` | `Mlfhntkcvb` | `Qbjuef` |
| --- | --- | --- | --- |
| operations watched | 3,500 | 3,484 | 3,400 |
| jumps watched | 345 | 361 | 349 |
| unconditional | 113 | 9 | 110 |
| conditional | 28, 135, 143, 156 | 28, 37, 119, 143 | 77, 97, 143, 156 |

An operation seen to be followed by something other than the next one every time
is called a jump; one that sometimes is and sometimes is not, a conditional
jump. Seen only once, it is called neither, because a jump that happened to be
taken and one that is always taken look the same from a single sighting. Two
operations per sample fall into that last group and are left unnamed.

One run takes one path, so most jumps are never watched. Every watched jump went
to the number the jumping operation carries — all 345 of them, in all three
samples — so the ones that were not watched are read the same way, and marked
`~>` in the listing against the `->` of a jump actually seen. The rule is
adopted per operation number, needs three sightings that agree, and is abandoned
if a single one disagrees. That resolves a further 141 to 171 jumps per sample.

Nothing here assumes the operand is a target. It is a rule the engine was
observed to follow, checked against where it really went, and reported as
separate from what was seen.

### What the operations do, from the run itself

Six of those nine are not out of reach after all, because the program performs
them perfectly well in the middle of a run. The same run that showed where the
operations go shows what they do, read off the engine's own stack either side of
each operation. Which values were left untouched underneath is settled by
identity rather than by depth, so an operation is measured by what it really
took and left rather than by the difference between two heights. That accounts
for 26 of the 29 operations in each sample, leaving three: two that threw and
one the machine could not follow, none of which the run reached either.

The two ways of asking answer different questions and are kept apart for it.
Trials choose values, so they can vary them freely and rule meanings out; a real
run cannot be made to try anything, and repeats itself. What the run has instead
is somewhere to put things. An operation performed in isolation has an engine
around it that holds nothing and is going nowhere, so the only meanings it can
demonstrate are the ones that begin and end on the stack — which is why the
trials find arithmetic and little else. In place, the same operation is seen
fetching and storing, and where it fetched from is as much of its meaning as
what it did.

So a value taken off the stack or left on it is matched against what the engine
had elsewhere at that moment: its own tables of values at the place the operand
names, the static field the operand names, the array sitting on the stack under
an index. A match is only believed where the operation was seen doing it more
than once, on more than one place, and carrying values that were not all alike —
except where the value is an object rather than a number, since an operation
caught carrying off the very object a field was holding is not a coincidence
that repetition could improve on. A write additionally has to have changed
something, a table that already held the value being indistinguishable from one
never written to.

That takes each sample from nine meanings named to 21, and the same 21 come out
of all three engines:

| Meaning | `Qafcakg` | `Mlfhntkcvb` | `Qbjuef` |
| --- | --- | --- | --- |
| loads what its operand indexes | 136 | 74 | 78 |
| stores where its operand indexes | 45 | 89 | 139 |
| reads the static field it names | 59 | 140 | 18 |
| reads an array element | 18 | 120 | 30 |
| pushes its operand | 43 | 57 | 79 |
| branch | 113 | 9 | 110 |
| branch if | 28, 31, 85, 135, 143, 156 | 28, 37, 119, 123, 124, 143 | 14, 77, 97, 143, 156, 165 |

An operation watched jumping only once is not called a jump on that alone, since
one that happened to be taken and one always taken look alike from a single
sighting. But an operation that also consumed values decided something with
them, and between the two readings available the one that leaves both ways out
of it open is the one that cannot mislead a reader into taking live code for
unreachable. Two operations per sample are named that way, and they are the last
two that had been left unnamed.

### What the handler works out

The readings above treat the engine as a black box, which invites the obvious
question: why not read its handlers instead? The answer is in what the
handlers are. In `Qafcakg` every one of them is inside a single method of 7,386
IL instructions with 1,133 distinct branch targets, control-flow flattened
behind a `switch` of 806 arms over a state variable. The opcode is read exactly
once, at `IL_5A97`, and the instruction after it assigns a state number and
jumps back to that switch; the opcode's own switch, 176 arms wide, sits far away
and is reachable only through the state machine, guarded by calls whose false
branch returns to it. So a handler is not a region that can be read but a chain
of fragments threaded through a thousand blocks.

Nor would reading them tell you what they call. Of 1,143 calls in that method,
18 go to the framework. 652 — more than half of all of them — go to one method,
the delegate proxy resolver, which picks its target at run time out of an
encrypted table. Statically those call sites say "call something". A further 156
go to a predicate whose only job is to send the state machine somewhere else.

None of that stands in the way of the machine, which resolves the proxies as it
goes, and by the time it is performing an operation it has already walked the
flattening. So while an operation is being performed, what the engine executes
is recorded: arithmetic, comparisons, conversions, and calls that leave the
assembly. Two filters make it readable, neither needing to know what the
plumbing is. An operation is credited only with what it did on every performance
watched, and then anything most operations also do is dropped — taking the top
of a stack, comparing two types, stepping a position. What is left is what one
operation does that its neighbours do not.

It arrives at the same answers by a different road, which is the point of
running it. The operation the trials called `xor` is watched executing `xor`;
`add`, `add`; `array length`, `Array::get_Length`. Where the two disagreed one
would be wrong, and they do not.

It also reaches past them. An operation the trials could only count — one value
in, one out — is watched calling `Module::ResolveType` and
`Array::CreateInstance`, which is `newarr` and nothing else. And a conditional
branch, which no measurement of the stack can see the condition of, is watched
computing `clt`. In all three samples:

| | `Qafcakg` | `Mlfhntkcvb` | `Qbjuef` |
| --- | --- | --- | --- |
| makes an array of a named type | 82 | 97 | 66 |
| branch on less-than | 28 | 28 | 97 |
| branch on a longer comparison | 135 | 119 | 77 |

Two of the three operations that nothing else reached have their working read
this way. Their effect on the stack is still unmeasured, and the listing says so
rather than reporting them as doing nothing.

No listing is acted on. The stubs are left exactly as they were, and the pass
does not gate emission, because a program that could not be read back says
nothing about whether the rest of the recovery is sound.

### Protected strings

The fixtures use a virtualized initializer for a UTF-16LE record table. The
resolver consumes an absolute byte offset and performs a caller check. The two
proven direct uses are restored statically with a stack-neutral
`pop; ldstr value` substitution:

- encrypted payload resource name; and
- `"Load "`, subsequently trimmed by the original code.

The resolver is never invoked.

This is the one place left where the tool recognizes a sample by its input hash.
Table capture reports ambiguous framing on these two, and the older strategy is
what keeps them producing output at all, so it is held behind a set of two
hashes in `LegacyStringStrategySamples` rather than deleted. The set exists to
be removed: the framing it works around is a virtual machine building the table,
and the machine can now run one.

For generic inputs, table capture and call-site rewriting are separate passes.
A table must be unique and strictly length-framed UTF-16, and every reachable
resolver use must have a proven offset. Replacements are atomic across the
assembly; one unresolved use causes zero string edits.

## Verification gates

Before emission, the tool checks:

- all branch and switch targets belong to their method;
- exception-region boundaries belong to their method;
- no reachable call has an invalid operand;
- public API, resource names, entry point, and strong-name state are preserved;
- every pass is complete (partial and unsupported recovery always block output);
- the emitted file reloads and passes the same structural verification.

The writer preserves metadata tokens and writes atomically. End-to-end tests
also assert deterministic binary output, entry-point preservation, fixture
hashes, pass counts, and independent dnlib reload.

## Fail-closed capability boundaries

- JIT-hook writes that do not deterministically target every catalogued stub;
- Reactor VM instructions or exception paths outside the bounded model;
- non-unique or incompletely referenced VM-backed string tables;
- code-virtualization lifting, which stops at a listing of the decoded program
  annotated with each operation's derived effect, rather than IL; and
- dynamic execution of protected assemblies.

Native-stub unpacking (NecroBit native / QuickLZ) is a deferred capability, not
a silent failure: `metadata-preflight` detects a native entry point, a managed
native header, or a non-IL-only image and reports the input as unsupported with
a specific diagnostic naming the deferred stage.

Destructive removal of runtime/proxy types and symbol renaming are no longer
permanently out of scope; they are opt-in and off by default (see below).

The JIT-hook generation is detected through duplicate raw metadata rows,
hundreds of `NoInlining` default-return stubs, high-entropy patch resources,
large switch dispatchers, `clrjit` references, and runtime-module pointer
access. The recovery pass repeats interpretation, validates write-log identity,
restricts writes to catalogued method-prefix windows, reparses restored bodies
by unchanged MethodDef token, and requires all stubs to pass branch/stack/EH
verification. Any unmet condition preserves every body and refuses output.

## Generic analysis components

- Raw `BSJB`/tables-stream preflight records duplicate Module/Assembly rows,
  invalid stream bounds, and zero sorted masks before mutation.
- Resource roles are inferred from consumers such as `ResolveMethod`,
  `GetManifestResourceStream`, `Assembly.Load`, and `string(int32)` resolvers.
- Encrypted resource bundles are recovered by running the module's own bundle
  reader, identified as a static method that names the bundle and reaches a
  manifest-resource read through however many laundering hops. Because the
  reader stores its result rather than returning it, the plaintext is taken from
  machine state and selected by parsing: the bundle is a satellite assembly, and
  the one buffer that loads as an assembly carrying resources is it. No cipher,
  key schedule, or container layout is hardcoded.
- Bounded integer evaluation handles constant arithmetic, shifts, and bitwise
  operations; constant array discovery recovers FieldRVA and IL-built material.
- Conservative CFG reachability, exception roots, dispatcher detection, and
  evaluation-stack analysis are bounded and diagnostic.
- Payload stage gates require strict terminal ByteArray framing, bounded
  decompression, `MZ`/CLR metadata, and independent managed parsing.
- Mutations have rollback support; destructive cleanup requires complete
  recovery, no remaining use sites, and at least 0.95 confidence.

Unsupported mechanisms remain intact and are reported. This is safer than
claiming broad Reactor 6/7 compatibility or emitting a partially damaged file.

## Scaffolding removal and renaming

`runtime-cleanup` runs by default and `--keep-runtime` turns it off. It deletes a
type or method only when five things hold: nothing reachable can transfer control
to it, it is invisible outside the assembly, no reachable code takes its handle,
no surviving declaration references it under a fixed-point scan, and recovery can
account for why it has no use left. That last condition is what keeps the pass
from tree-shaking the program: a pass that replaces a resolver call with its
string, redirects a call past a forwarder, or elides an inert loader call records
the declarations it made pointless, and only those are candidates. Unreachable
code that nothing accounts for is counted in the pass diagnostics and kept. The
whole pass is additionally gated by `RewritePolicy.CanRemoveRuntime` (recovery
complete, no surviving use site, confidence at least 0.95).

Cleanup and loader-call elision are the two places that model a type initializer
as running only when its type is used, which is what the runtime does and what
lets an abandoned island of protector code be recognized as dead. Every other
consumer of reachability keeps the conservative reading in which every
initializer runs.

`loader-call-elision` removes the calls Reactor injects at the head of type
initializers all over the assembly, which are what keep its runtime referenced
from application code. A call goes when the bounded interpretation gives a
complete account of what it does and nothing that survives can notice any of it.
The account is complete because the machine refuses every call it does not
model, so a frame that interprets to completion twice, in agreement, did nothing
outside the modeled surface, and that surface is read-only apart from handing the
runtime an event handler — which the effects record names explicitly, and which
disqualifies the call. That leaves the static fields it wrote as the only channel
out.

Whether those writes can be noticed is decided by making the edit, recomputing
reachability, and undoing it. Reactor reaches its own runtime mostly through
function pointers: the JIT callback and the resource handler are installed rather
than called, so they stop being reachable exactly when the loader does, and a
test run before the edit would report them as live readers and condemn every
candidate. Candidates that fail are dropped and the rest retried, since keeping
one keeps everything it reaches alive. Removing a call removes its writes, so a
reader that survives is disqualifying whether or not it is part of the protector;
only unreachability clears a field.

The pass runs after resource restoration and hook elision rather than early,
because whether loader state is still observable depends on the earlier
recoveries having replaced the code that read it. Reactor's resolve handler reads
four of the loader's fields, and while its subscription stands nothing can be
cleared.

`resource-hook-elision` is the one pass that removes a live subscription rather
than dead code, and it earns that by proving the subscription can no longer fire.
Reactor's handler answers `AppDomain.ResourceResolve` with a satellite assembly
decrypted from an embedded bundle, and the runtime raises that event only after
its own lookup fails; once restoration has put every one of the satellite's
streams on the module, the lookup succeeds and the handler is unreachable. The
edit is the five stack-neutral instructions that build the delegate and add it to
the event, replaced in place so that every branch target in the body still points
where it did. It declines if any bundle went unrecovered or a resource still
looks like an unextracted assembly payload, either of which would mean the hook
still serves something the module lacks.

`--rename` stays off by default. It runs `symbol-renaming`, which deterministically
renames only non-public members whose names are structurally proven
Reactor-generated, skipping virtual, P/Invoke, constructor, and
serialization-sensitive members, and writes an old-to-new map beside the JSON
reports.

Identity verification is policy-aware rather than bypassed: each pass declares
the exact removals, additions, and renames it made, and the snapshot comparison
still fails on any change outside that declared allowance.

A full stage-by-stage comparison against NETReactorSlayer's fifteen stages is in
[parity.md](parity.md).

## Clean-room boundary

Behavioral specifications came from the supplied binaries and independently
authored tests. No source or binaries from NETReactorSlayer or de4dot are used.
The project depends on dnlib under its MIT license.
