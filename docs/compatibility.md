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
single-level deterministic finally flow. Framework calls are answered from an
allowlist of models; a call outside it is stepped over by default and stops the
frame under `--strict`, as set out in [the two modes](#the-two-modes) below.
Allowlisted models cover resources, streams/readers, encoding, hashing,
decompression, symmetric crypto, synthetic module/process metadata, Marshal
operations, and virtual memory writes. They also cover the types a sample passes
through on the way there: `StringBuilder`, formatted number-to-text conversion,
`ToString` decided by the receiver rather than the call site, `TimeSpan` and
`DateTime` arithmetic, named mutexes, certificates held as the bytes they
were built from, format strings filled in, weak references that hold what they
were given, and URLs parsed by the framework's own parser. Unknown branches,
unknown indexes, lengths and counts, symbolic writes, malformed ranges, and
exhausted budgets stop recovery in either mode.

An `async` method is run by driving its state machine, which means the builder,
the task and the awaiter are modeled and `MoveNext` is interpreted like any other
body. Every awaiter reports finished, because nothing here runs on another thread
and so anything a task stands for has already happened; that is the path the
compiler wrote for a task which completed before it was awaited. A task this
machine did not produce is refused rather than read for a result, and an async
method that ended in an exception stops where its result is read.

The network is a boundary rather than a gap. What only arranges a connection is
modeled — TLS settings, request headers, timeouts, endpoints, address parsing,
socket options — and the request itself stops the interpretation, naming the host
and port it was about to reach. That name is usually the most useful thing a run
over a stager produces, so it is in the refusal rather than left implicit. A name
lookup is a question about the network the machine is on and may be stated in a
profile as `net:dns:<host>`.

Two families of framework answer are deliberately withheld rather than
approximated. A number written with a format that places group separators or a
decimal mark reads differently under different cultures, and nothing states which
culture the machine the sample expects is running under, so only the decimal and
hexadecimal families are answered. A certificate's subject, issuer, or public key
takes a full X.509 parse of attacker-supplied bytes, which this tool will not run
over its own input; the encoded bytes, their hash where they are a bare
certificate, and equality against another certificate are answered instead.

### The two modes

Two things differ between a default run and a `--strict` one, and nothing else
does. Declarations, trusted libraries, two-run agreement, verification, round-trip
and emission gating are identical in both.

| | Default (triage) | `--strict` |
| --- | --- | --- |
| Questions about the machine | answered by a built-in Windows 10 workstation profile, every answer marked assumed | answered by the fifteen-fact built-in profile, everything else refused |
| A call the machine cannot read | stepped over: nothing back if it returns nothing, otherwise a value marked not known | stops the frame, recorded as a blocker |

What holds in both:

- Nothing about the program is invented. No instruction is guessed at, no branch is
  taken on a value the sample did not produce, no byte is written down that
  decryption did not produce.
- An unknown may be carried but may not become a value. A branch condition, an array
  index, an array length, and a block-copy count each stop the run rather than
  taking a supposed value, and the stop names the earlier refusal that produced the
  unknown rather than offering a remedy that would not work.
- A question the profile does not answer is refused, and the refusal names the key.
  This is why the shipped portrait states machine-shaped things only — names, paths,
  identifiers, sizes, screen metrics — and never file contents or a registry value
  holding bytes. A wrong machine name costs a reader a plausible detail; invented
  key material would answer the only question they asked, and answer it falsely.
- A frame that stepped over a call is recorded as having handed something to the
  runtime, so no pass can prove such a frame does nothing and remove it. Assuming
  past a call can cost a removal that should have happened; it cannot cause one that
  should not have.
- A declaration beats an assumption. Declared call outcomes are consulted before the
  step-over, so what somebody stated a call does is what the run uses.

Both modes disclose what they leaned on. `HostProfile.Consulted` in the analysis
report marks each answer stated or assumed, values derived from an assumed answer
carry `Assumed` provenance rather than `Host`, and every call stepped over is listed
in `ContinuedPast` in `NAME.blockers.json` and in the summary. `Blockers` keeps its
meaning: things that stopped the run.

Measured on the eleven-sample corpus, the two modes agree on every expectation —
detection, capabilities, restored body counts, string-site coverage, remaining stubs,
mutation counts, oracle parity and preserved names: 2041 of 2057 reported fields are
identical, and the sixteen that differ are diagnostic text. What changes is where a
run that does not finish stops. On `qafcakg-payload`, `--strict` stops
payload-extraction at `native:user32!SetProcessDPIAware`, a call with no bearing on
the payload; the default steps over that and stops at
`registry:HKEY_CURRENT_USER\Software\A0A99EB4…`, which is where that sample keeps its
key material and is a fact an analyst can state. The gain is in what the run is able
to tell you to do next, rather than in the numbers.

### Declared host facts

Questions about the machine the sample believes it is running on are answered
from a host profile, and from nowhere else. Two profiles ship. The sparse one,
which `--strict` uses, states the clock, the identifier seed, the debugger
verdicts, the process id, the runtime module and version, the FIPS policy, and
that nothing else on the machine holds a named mutex — the last following from the
modeled world having one process, which is the same process every other probe is
answered about. The default one adds the rest of a plausible Windows 10
workstation and is the same file as
[profiles/windows-10-workstation.json](../profiles/windows-10-workstation.json),
carried inside the assembly so that a first look needs no file on disk; it is named
and hashed in the report like any other. `--host-profile` overlays
a JSON file of additional
facts keyed by family: `env:`, `time:`, `guid:`, `debugger:`, `process:`,
`runtime:`, `native:`, `wmi:`, `registry:`, `volume:`, `net:`. A key in no family
is rejected when the profile is read.

A fact is text, a whole number, `true`, `false`, `null` for "not there", or
`{ "base64": "..." }` for bytes. The last matters for a stager that keeps its
next stage in a binary registry value: an analyst who has that value has the
payload, and stating it is how the interpretation gets to it. The bytes are part
of what the profile's hash covers.

Support contract for a fact, whether stated or assumed:

- It is used like any other known value. It may be folded, may decide a branch, and
  may reach the emitted assembly.
- Which of the two it is is recorded per fact rather than per profile, because a
  supplied profile inherits everything it did not mention: stating a machine name
  does not make its author answerable for the clock reading 2020. The summary marks
  each answer, and values derived from one carry `Host` provenance when a person
  stated it and `Assumed` when the tool did.
- Every question asked is recorded with the answer given, and the report carries
  the profile's name and the SHA-256 of its contents alongside the input's hash.
  Recovery that depended on a profile is reproducible only with that profile.
- A question no profile answers is refused with the key that would answer it.
  Nothing is inferred from the analysis host, which is not Windows.
- `Environment.Default` encoding, unlisted platform invokes, and anything else
  whose answer is a machine's rather than a file's remain refused.

Facts can also be stated in the `facts` section of a declarations file, which is
the same parser and the same contract. See
[declarations.md](declarations.md).

### What else can be declared

`--declarations` takes one file covering the facts above, the libraries below,
the budgets, the passes to leave out, and — only with `--allow-declared-calls` —
what a call the interpreter cannot read does. Every run writes
`NAME.blockers.json`, which names each thing that stopped it, where, how often,
and the exact declaration that would get past it, or says that no declaration
will.

Support contract for a declared call outcome:

- It is consulted last, after a body in the module, a trusted library, a model
  and every other way of following the call, so it can never displace one.
- It states either what the call returns or that the call is inert; a call that
  returns a value cannot be declared inert.
- A returned value may be text, a whole number, a truth value, absent, or bytes.
  A call returning `float` or `double` is refused, since nothing here computes in
  fractions.
- Every value derived from one carries `Declared` provenance — deliberately
  distinct from `Host`, because this is an assertion about somebody else's code
  rather than about a computer.
- Every use is recorded as a `DeclaredCall` observation and printed in the
  summary, and an inert declaration also records a registration, so the pass that
  removes provably inert loader frames cannot conclude inertness from a
  declaration of it.
- The declarations' name and SHA-256 are in both reports. A run that used a
  declared call is reproducible only with that file.

Budgets are `steps`, `allocatedBytes` and `depth`, and replace the per-pass
figures wherever they are set. Skipping a pass leaves it recorded as incomplete,
so the emission gate still withholds the cleaned copy.

### What the output promises

The three files a run writes and the object `--json` prints have published
schemas in [`schema/`](../schema/), and the promise attached to them is that no
field is removed, renamed or given a new meaning while the major version in the
document stays where it is. Fields are added; a reader that refuses unknown ones
will break, and one that ignores them will not. A field that can be absent is
`null` rather than missing, and both `BlockerKind` and `PassStatus` may gain
members.

The schemas are held to the types by a test rather than by attention: every
property the serializer writes has to appear in the schema and the other way
about, so a field added without being written down fails the build. There is no
separate mode for a program driving the tool — the modes are about what may be
assumed, which is a different question from what the answer is shaped like. See
[agents.md](agents.md).

### Trusted third-party assemblies

`--library` supplies an assembly whose IL the interpreter may run. The assembly
must be referenced by the sample by name, or it is refused; its name, version,
public key token and SHA-256 are recorded as `trusted-library` evidence, and a
version that differs from the reference is reported rather than refused. Virtual
dispatch and type-ancestry queries search the sample and the supplied assemblies
together, so a call into a library's own abstract method resolves.

Measured on protobuf-net 2.4 driving a sample's payload path, a call to
`Serializer.Deserialize<T>` now runs to its result. Doing that meant modelling
what a serializer does rather than what a program does: reflection over the
sample's own contract types, custom attributes read off them, and
`Reflection.Emit` — the generated serializer is assembled into a real method body
and then interpreted. Generic arguments are carried into the machine's `Type`
model, so a library reflecting over its own `typeof(T)` sees the type the call
site supplied.

Known limits:

- Static-field and type-initialisation state is keyed by full name with no
  assembly component, so a library and a sample that both define a type of the
  same full name would share state.
- There is no per-library step budget; a library shares the run's budget.
- Emitted IL is assembled for the shapes the serializer generator uses. An emit
  the assembler cannot form into a runnable body is refused rather than
  approximated.

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
for 26 of the 29 operations in each sample.

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

### Operations with no fixed effect

Two operations per sample took a different number of values every time they ran,
which is why nothing above could measure them: there is no arity to establish.
That is itself the finding. An operation whose arity is decided by something
other than the operation is being told how many values to take, and both of them
carry an operand that names a method of the assembly — one of them always a
constructor. They are the call and the object construction, and they are named
from those two facts together, with what could not be measured said alongside
rather than papered over.

They are also the most informative operations in a listing. Between them they
account for around a thousand of `Qafcakg`'s 2,935 operations, each naming the
method it reaches for, which is what turns an unreadable method into a legible
account of what it does.

A call whose arity never varied is the same finding arrived at the other way. An
engine watched performing one has measured the method rather than the operation,
so where the run only ever reached one site the operation looks like an ordinary
fixed-arity operation, and reading its other sites that way reads them wrong. Two
things settle it: every operand the operation carries has to name a method of the
assembly, which an operation carrying local slots or constants fails, and what was
measured of the operation has to be exactly what one of those methods' signatures
says. The second is the test rather than the premise — an operation measured
taking one value and leaving one, whose operands name a property getter and a
four-argument method, is a call if the getter accounts for the measurement, and if
none of the methods it names does then it is something else and stays unread. The
payload sample `Lqcuzgc` has one such operation at 50 sites, and they are the
protector's own signature check: `TransformFinalBlock`, `ReadBytes`,
`set_Position`, `VerifyHash`. Read as the one-argument call the run happened to
watch, they left the walk contradicting itself at five places in the middle of
that check; read as the calls they are, the listing goes from 4,801 operations to
4,851 and the contradictions to none.

Three readings then come from putting the two sources together. An operation
that takes a value, leaves nothing, changes nothing the trials can see and never
writes a static field while the run watches it has nowhere left to have put what
it took, so it discarded it — 142 operations of `Qafcakg` alone. The jumps give
away where the engine keeps its position, being what they write; an operation
that writes that place a fixed number that is no place in the program has
stopped rather than gone anywhere, and the one that does so also hands back what
it took and raises a flag, which is a return. And an operation whose pushed
value cannot be read can still be looked inside, since the engine wraps what it
stacks and the wrapper can be seen through.

A fourth reading needs the listing below to have been written first, and is
folded back into the report once it has. Where nothing could perform an
operation and the run never reached one, the depths of the stack around it still
leave it one possible effect; and where that effect is to take a value and leave
nothing, and every instruction of that kind carries the token of a static field,
there is one thing left for the operation to be. It is the counterpart of the
operation the run watched reading a static field, and it is given the same name,
because it is the same claim. Neither half would do on its own: that an
operation consumes a value says nothing about where the value went, and that its
operand names a field says nothing about which direction it goes in.

With those, all 29 operations in each of the three samples are reported on and
all 29 are named. The last two names to become specific enough to be an IL
opcode were both the same error: reading a wrapper rather than what it held. A
wrapper with nothing in any of its places is the engine holding null, whatever
the tag beside the empty places says, so the operation that leaves one is
`ldnull` and not the number it was reported as. And a load from one of the
engine's tables is a load of an argument where the table is as long as the
method declares arguments and no index reaches past it — which needed the
tables sown with values first, since a cold engine's are empty and an operation
that fetches from one then has nothing to fetch, and needed a table's length
counted as its entries rather than as everything reachable through them.

### Reading the program back

What all of that comes to is written out separately, in the assembly's own
terms: each named operation as the IL it stands for, each token operand as what
it names, and everything unsettled as `??` beside its operand and what was
counted. Every operation in each of the three samples now comes out that way —
2,935, 2,952 and 3,007 of them, none left unread, and 4,854 of 4,854 in the
payload sample on the fourth engine. By default it is a report and stays one:
the stubs are left exactly as they were, nothing is written into the cleaned
copy, and the pass does not gate emission, because a program that could not be
read back says nothing about whether the rest of the recovery is sound.

Writing it out turned up something the listing had been hiding. The dispatcher's
jump carries a table of places rather than one, which is to say it is a switch —
355 arms in `Qafcakg` — and the working already read off its handler is the
bounds check that goes with one: `conv.i8`, `blt` twice, `bge`. Every operation
in a flattened program is reached through that table, so before it was read the
program was a dozen operations and a wall; after, it is blocks.

That is what makes the reading checkable. Stack depth is walked from the first
operation through every branch, adding what each leaves and subtracting what
each takes, and every place two paths arrive at has to agree on the depth or
some reading along the way is wrong. It is a demanding test in a program of this
shape, where hundreds of blocks converge on one dispatcher:

| | `Qafcakg` | `Mlfhntkcvb` | `Qbjuef` |
| --- | --- | --- | --- |
| operations walked | 2,921 of 2,935 | 2,948 of 2,952 | 3,001 of 3,007 |
| places two paths disagreed | 0 | 0 | 0 |
| operations no path arrives at | 14 | 4 | 6 |

The walk now stops nowhere, and that is what makes the last row a finding rather
than a gap: a walk never at a loss followed everything there was to follow, so
what it did not arrive at cannot be arrived at. Those operations sit after an
unconditional jump, in no arm of the dispatcher's table, and are code the
protector emitted and never uses. Nothing else in three programs of some three
thousand operations contradicts anything else.

That completeness is what settles the last two operations. With everything
around them known, the depth of the stack where each begins is fixed by the
paths in and the depth where the next begins by the paths out, and the
difference is the operation's effect whether anything measured it or not. In
`Qafcakg` the operation the machine could not follow is pinned at one value
taken and none left; in each sample two operations are settled this way. A
solved effect is used to solve the next but has to survive being carried through
the rest of the program, and is withdrawn if it contradicts a depth arrived at
another way. It gives an effect and not a reading, so nothing is named on the
strength of it.

### Building the program back into IL

A triage run writes the virtualized methods into the cleaned copy as IL instead
of a stub, each marked with an internal `ReactorUnpack.RebuiltFromReading`
attribute that decompilers show above the method; a strict run builds nothing
unless asked with `--devirtualize`. The attribute type and its constructor are
the only declarations the tool adds to an assembly, and both are declared to the
identity gate the way deletions are. The lowering
assumes nothing the reading did not establish: every value is carried as an
`object`, every slot is an `object` local, and a value is converted back only
where the assembly itself says what it must be. An operation whose meaning was
never established refuses the whole method rather than that instruction, and an
operation the stack walk never arrives at is emitted as a `throw`, there being no
stack for it to work on.

| | `Qafcakg` | `Mlfhntkcvb` | `Qbjuef` | `Lqcuzgc` |
| --- | --- | --- | --- | --- |
| operations built | 2,935 | 2,952 | 3,007 | 4,854 |
| instructions emitted | 8,997 | 8,886 | 9,290 | 15,270 |
| object slots | 13 | 12 | 13 | 44 |
| unreachable places emitted as `throw` | 14 | 4 | 6 | 8 |
| guarded regions emitted as catch clauses | 0 | 0 | 0 | 4 |
| `ilverify` errors in the built method | 0 | 0 | 0 | 0 |
| ran and unpacked what the original unpacked | yes | yes | not made | not made |

The files themselves are not error-free — Reactor's own code accounts for 17, 17,
14 and 77 `ilverify` complaints across them, and 22 in the cleaned copy of
`Qafcakg` — but a cleaned copy with the bodies in reports exactly the same set as
one built without them, so nothing emitted added one.

Verifiable IL can still be the wrong IL, so where the sample's own work can be
compared it is. A second copy of the input is prepared identically, the built
bodies replace the stubs, and the startup path is interpreted again; if the same
payload comes out, SHA-256 for SHA-256, the bodies did what the engine did.
`Qafcakg` and `Mlfhntkcvb` pass that way, each unpacking both of its payloads
with a built body entered on the path. The other two report that the check was
not made and why: `Qbjuef` unpacks the same payload either way without ever
entering a built body, and `Lqcuzgc` is itself an extracted payload with no
startup path to run. A check that could not be made is never reported as one that
passed.

### Guarded regions

The fourth engine, in the `Lqcuzgc` payload, is the only one here whose programs
use exception handling, and it keeps that outside the operations: a region is an
object holding a range of operations, a handler, and a caught type. Recovering
the numbers was not enough, because nothing in them says which range is which,
and a handler emitted over the wrong range runs the wrong code precisely when
something has already gone wrong. Following the objects that hold the clauses
settles it, giving all four regions of that program as a guarded span, a handler
span and a type — `22-31 guarded, handled at 32-33, catching System.Object` and
three more. Emission then requires what the runtime requires: a jump leaving a
guarded region becomes `leave` and must carry nothing on the stack, regions must
nest or be disjoint, and a try or handler block must end in a terminal
instruction. A conditional jump or a jump table crossing a region boundary has no
`leave` form and refuses the method rather than being approximated.

### Protected strings

The fixtures use a virtualized initializer for a UTF-16LE record table. The
resolver consumes an absolute byte offset and performs a caller check, and it is
never invoked: the table is built by running the protector's own virtual machine
under the numbering the semantics probe read off that build's engine, and each
use is restored with a stack-neutral `pop; ldstr value` substitution. Both
fixtures yield a 22-record table and all 23 uses.

The tool no longer recognizes any sample by its input hash. The last two entries
were removed once the machine could run the program that builds the table, and
with them went the older strategy they gated, which inferred a handful of values
from the shape of the method that asked for them rather than reading any.

Reading that program correctly turns on width. The engine's slots hold 32-bit
values, so a shift left that carries a bit past the top loses it, and evaluating
the same program in 64-bit arithmetic keeps it — a later shift right then brings
back a bit that never existed and the offset lands in the middle of no record.
The width is not assumed: it is what the probe measured each operation to leave,
and a result is cut to it exactly where the engine cuts it. An operation whose
width nothing measured keeps the wider arithmetic.

For generic inputs, table capture and call-site rewriting are separate passes.
A table must be unique and strictly length-framed UTF-16, and every reachable
resolver use must have a proven offset. Replacements are atomic across the
assembly; one unresolved use causes zero string edits.

#### Strings kept where no table can be framed

A sample is often protected twice — once by whoever wrote it and again by
whoever sold them Reactor — and the layer underneath does not have to keep its
strings anywhere a run of bytes describes. In the `Lqcuzgc` payload it decrypts
them once into a `Hashtable` parked in a slot of the application domain, and
every use is a call passing the number the string was filed under. There is no
table for the reading above to frame, so that reading finds nothing and, on its
own, reports the seventeen strings of Reactor's own layer as seventeen of
seventeen: true of the layer it read, wrong about the file.

So a second reading does not look for the table. It asks the method that fetches
the strings — the one thing that knows where they are — for each number that
reaches it, interpreting it in the same bounded machine as everything else, and
takes the answer. Its gate is what it can prove rather than what it recognizes:
the declaring type must be one the assembly does not show the outside world,
every call reaching the method must pass a number the slice can settle, and each
answer must be a string the machine holds concretely. Anything else leaves that
lookup entirely alone, because a lookup half restored leaves the rest of its
calls pointing at machinery the cleanup afterwards is entitled to delete.

The reading runs after Reactor's own strings are back, and the ordering is not a
preference. The inner layer reaches its own resource through a Reactor string, so
asking it anything earlier means asking through the virtual machine, and the
machine then has to interpret the protector's interpreter running the protector's
loader — which on this fixture walks as far as the payload's entry-point call
before stopping. Once the outer layer is off, the same question is ordinary code
and is answered in fourteen seconds. `Lqcuzgc` yields 155 strings this way for
172 across both layers, among them the sandbox, debugger and hypervisor names the
sample checks for and the base64 protobuf holding its reporting endpoint.

Uses that take the method's address for a delegate rather than calling it are
reported and not counted, because no rewrite of call sites could ever bring that
number down; uses that are calls and were not read are counted, so a run cannot
report every string a file has as recovered when a layer of them was untouched.

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
- code-virtualization recovery that could be called proof: what goes into the
  cleaned copy is IL built from a listing of the decoded program, marked as the
  tool's reading with an attribute on every method it wrote, and a method with an
  unread operation or an unemittable jump out of a guarded region is refused whole
  rather than approximated; and
- dynamic execution of protected assemblies.

Native-stub unpacking (NecroBit native / QuickLZ) is a deferred capability, not
a silent failure: `metadata-preflight` detects a native entry point, a managed
native header, or a non-IL-only image and reports the input as unsupported with
a specific diagnostic naming the deferred stage.

Destructive removal of runtime/proxy types and symbol renaming are no longer
permanently out of scope. Both are what a triage run does and neither is what a
strict run does, and each can be turned the other way by name (see below).

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

A method the run built a body into is a root regardless of what reaches it. A
virtualized method is typically one nothing calls by name, so the ordinary
reading has it dead; deleting it, and the helpers its new body calls, would
remove the thing the run was asked to produce.

Cleanup and loader-call elision are the two places that model a type initializer
as running only when its type is used, which is what the runtime does and what
lets an abandoned island of protector code be recognized as dead. Every other
consumer of reachability keeps the conservative reading in which every
initializer runs.

`loader-call-elision` removes the calls Reactor injects at the head of type
initializers all over the assembly, which are what keep its runtime referenced
from application code. A call goes when the bounded interpretation gives a
complete account of what it does and nothing that survives can notice any of it.
The account is complete because every call the machine did not read is written into
the effects record. A frame that interprets to completion twice, in agreement, did
nothing outside the modeled surface, and that surface is read-only apart from two
things the record names explicitly, each of which disqualifies the call: handing the
runtime an event handler, and — outside `--strict` — a call the machine could not
follow and stepped over. That leaves the static fields it wrote as the only channel
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

Renaming runs on a triage run and not on a strict one, and `--rename` and
`--keep-names` say which regardless. It runs `symbol-renaming`, which
deterministically renames only non-public members whose names are structurally
proven Reactor-generated, skipping virtual, P/Invoke, constructor, and
serialization-sensitive members, and writes an old-to-new map beside the JSON
reports. The corpus harness pins it off, along with building virtualized methods
back, so that an outcome measures recovery rather than presentation.

Identity verification is policy-aware rather than bypassed: each pass declares
the exact removals, additions, and renames it made, and the snapshot comparison
still fails on any change outside that declared allowance.

A comparison against the other Reactor tools — NETReactorSlayer stage by stage,
de4dotEx and Krypton by what each handles and whether it runs the sample — is in
[parity.md](parity.md).

## Clean-room boundary

Behavioral specifications came from the supplied binaries and independently
authored tests. No source or binaries from NETReactorSlayer, de4dot, de4dotEx,
or Krypton are used, and none of them is called at runtime. The project depends
on dnlib under its MIT license.
