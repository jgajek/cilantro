# How ReactorUnpack undoes it

This is the counterpart to [how-net-reactor-works.md](how-net-reactor-works.md).
It assumes you have read that, or already know what Reactor does.

## The central idea

Reactor's protections all share one weakness: **the decryption routine ships with
the file**. It has to. The program must be able to decrypt itself on the machine
it runs on, with no network and no key server, so everything needed to undo the
protection is present in the sample.

There are two ways to use that.

The obvious way is to load the assembly and call its decryption routines
yourself. This is what most .NET deobfuscators do, and it works well: you get
whatever the real routine produces, including for encryption schemes nobody has
studied. It is also, unavoidably, **running the malware**. The routine you call
is inside a hostile binary, its type initializers run before it, and Reactor's
caller checks mean the tool must actively defeat the sample's own defences to get
an answer. Tools that work this way tell you to only use them in a VM, and they
are right to.

ReactorUnpack takes the other way. It **interprets** the decryption routine in a
simulator it controls, instead of executing it on the CPU. The protector's own
code drives the recovery, so no cipher or key layout has to be hardcoded, but the
code never runs — it is data being traced through a model. Nothing the sample
contains can execute, allocate real memory, touch the filesystem, or open a
socket, because there is no mechanism by which it could.

The rest of this document is about how that is made to work, and what is given up
for it.

## The bounded machine

At the centre of the tool is an interpreter for IL. It models what it needs to
model, and says so wherever it is reading something it does not.

It handles integers, objects, arrays, fields, branches, switches, and enough
exception-handling flow to follow real loader code. Pointers are modelled
symbolically, so when Reactor's loader writes decrypted bytes into what it thinks
is executable memory, the write lands in a simulated buffer that the tool can
read afterwards.

Calls out to the .NET framework are answered from an allowlist of modelled
operations — reading embedded resources, streams, text encoding, hashing,
decompression, symmetric ciphers, a few `Marshal` operations, and synthetic stand-ins
for things like "which module am I in". A call that is not on that list cannot be
read, and what happens then is the one decision the two modes differ over. By
default the call is stepped over: one that hands nothing back costs the run
nothing, and one that returns something returns a value marked as not known, which
the frame carries on with. Under `--strict` such a call stops interpretation, as
this tool did everywhere until recently.

Neither mode guesses what the call returned. The difference is between stopping at
a call and continuing without its result, and it matters because most unreadable
calls are on the way to the part worth reading rather than in it: a thread is
constructed, a window title is fetched, a counter is bumped, and the payload comes
out of the same method either way. What an unknown may never do is become a value.
The moment one would have to be a branch condition, an array index, or a length,
the run stops in both modes — inventing it there would mean reading a path the
program does not take and presenting it as the program.

Much of that list is unglamorous by necessity. A sample rarely goes straight from
its entry point to the thing worth recovering: it builds a string a character at a
time, writes a byte as two hex digits, takes a mutex to see whether a copy of
itself is already running, times something. None of that is interesting to read and
all of it is on the way, so each has to be modelled or the path stops short of the
part that matters. Where the answer would depend on something nobody has stated —
the culture that decides whether a formatted number uses a comma or a full stop —
the call is refused instead, because a plausible string that then gets hashed or
compared is worse than stopping.

A few of the modelled answers are about the world rather than about the file, and
those come from a **host profile**: a list of things stated about the Windows
machine the sample believes it is running on. By default that list is the tool's
own portrait of a plausible workstation — a machine name, a user, a disk serial, a
screen size, a processor id — and every answer taken from it is marked in the
report as assumed rather than stated. Under `--strict` the profile shrinks to the
fifteen answers the tool has always given: the clock reads a fixed instant, no
debugger is attached, the process is number 1 and the only one, the runtime is
4.8, and nothing else is answered at all. Protected code asks the debugger
question inside the type initializer that builds its virtual machine, so refusing
to answer it does not leave the tool neutral; it loses the program, the string
table, and whatever is behind them. Every question is recorded when it is asked,
so a report says both what the sample wanted to know and what it was told.

Questions the profile does not answer are refused exactly as any unmodelled call
is, and the refusal names the fact that would answer it: `env:MachineName`,
`wmi:Win32_BIOS.SerialNumber`, `native:user32!GetForegroundWindow`. Passing
`--host-profile` with a file stating those turns the refusal into an answer. A
fact can be bytes, written as `{ "base64": "..." }`, because some of what a
machine holds is not text — a stager that keeps its next stage in a binary
registry value is recovered by stating that value, and then the payload comes out
of the profile the same way it would have come out of the registry.
A stated fact is used freely, and can end up folded into the emitted assembly,
which is why the report carries the profile's name and hash next to the input's.

What the tool will not invent is anything about the program. No instruction is
guessed at, no branch is taken on a value the sample did not produce, no key is
supposed and no decrypted byte is written down that decryption did not produce.
What it does assume, by default, is the machine: a name nobody stated reads as
`DESKTOP-N7QK2LP` rather than stopping the interpretation. Every such answer is
listed as assumed in the report, so a reading that depends on one can be seen to
depend on it, and `--strict` removes them all. The shipped portrait deliberately
describes only machine-shaped things — names, paths, identifiers, sizes — and
never file contents or a registry value holding bytes, because a wrong machine
name costs a reader a plausible detail while a wrong blob would answer the only
question they asked, and answer it falsely.

The same reasoning covers somebody else's library. A sample that unpacks itself
through a third-party assembly cannot be followed past the call unless that
assembly is available, and it is not inside the file. `--library` supplies one:
the tool checks that the sample actually references it, records its version and
hash, and then treats its IL as interpretable in the same way the sample's own is.
Nothing is executed, and a library the sample never mentions is refused.

One of those answers is about the file, and it has two right values. Protected
code hashes the assembly it is running in and compares the hash against a
signature it carries, and the assembly it is running in does not always have a
file: an assembly handed to `Assembly.Load` as bytes reports no location, and a
payload unpacked by another module is loaded exactly that way. The protector has
to keep working there, so its own check tests for the empty location before it
tries to open anything. The machine therefore interprets a module the way that
module was reached. A file on disk is a file on disk; but where a module read its
own file, hashed it, and rejected it, it is interpreted again as an assembly with
no file of its own, which is what a payload recovered from inside another file
actually is. That is the other half of the protector's own check rather than a way
around it, and both attempts are recorded, so the report says the module looked
and says what it concluded.

A call that leaves the runtime altogether is reported differently. A platform
invoke has no body to interpret and no model that could stand in for what the
operating system would do, so it is named as what it is — the boundary of the
runtime rather than a gap in the allowlist — and what would get past it is a
statement about the machine rather than a model somebody has yet to write. Like
any unreadable call it is stepped over by default and stops the frame under
`--strict`. Where the platform call only reports a fact about the machine, the
profile answers it outright and the interpretation continues with a real value.

The network is that same boundary, and it is worth reaching. A stager keeps its
next stage on a server, and everything it does before the connection —
configuring TLS, setting headers and timeouts, parsing the address, building the
endpoint — is arithmetic on objects and is modelled, so the interpretation gets
all the way to the connection. There it stops, and the refusal says where the
connection was going: `https://logs.example.invalid:8443/ping`, or a host and
port. For a sample whose payload is not in the file at all, that address is what
the run has to show, and it is a better answer than a stage that says only that
nothing was recovered.

Async is not a boundary, though it looks like one. A modern loader is
`async Task<byte[]>` all the way down, and the awaiting is a compiler-written
state machine whose steps are ordinary IL. The machine drives it: the builder and
the task are modelled, and every awaiter reports that what it waits for has
finished — which is true here, because nothing runs on another thread, so whatever
a task stands for either already happened or already refused. `MoveNext` is then
interpreted like any other body and the method runs to its result.

Knowing what a frame did is load-bearing for correctness, because several later
stages remove code on the strength of having proved it does nothing. Under
`--strict` that proof comes for free: a routine that interprets to completion made
no unmodelled call, so it had no channel for a hidden effect. Stepping over a call
would break the proof, since the call might have done anything, so a frame that
stepped over one is recorded as having handed something to the runtime — the same
note that a modelled `AppDomain` handler registration leaves. Every stage that
asks "does this frame do anything" reads that note, and so declines to remove a
frame whose calls nobody read. Assuming past a call therefore costs the run a
removal it might have made, and cannot cost it a removal it should not have made.

There are budgets on instructions, allocations, and memory. Running out is
treated as failure, not as a partial answer.

Finally, anything the machine produces is produced **twice** and compared. Two
independent interpretations that agree, instruction for instruction and write for
write, rule out the tool having been steered by uninitialised state or its own
ordering. A disagreement means the recovery is abandoned.

## The order things happen in

The protections are layered, so they have to come off in a specific order. Some
of the ordering is obvious, some of it is not.

**1. Look before touching.** The raw metadata is parsed by hand first — before
handing the file to a library that would normalise it — to record duplicate
table rows, malformed stream bounds, and native-packing markers. Reactor puts
deliberate anomalies here to break tools, and they are evidence rather than
errors. If the file is native-packed, this is where the tool stops.

**2. Identify the protection.** Which Reactor generation this is, and which
features are in use, is decided from structural evidence: the shape of the
metadata, the count and form of the method stubs, the entropy of the resources,
the presence of JIT-related references. Not from version strings or file hashes,
so the answer holds for samples nobody has seen.

**3. Get the method bodies back, before anything else.** Everything downstream
reads IL, so if the IL is encrypted there is nothing to work on. Reactor's
bootstrap is interpreted, and it decrypts every method exactly as it would at run
time, writing the plaintext into the simulated image. The tool then reads the
bodies out of that image and grafts them into the assembly.

This is the strictest stage in the tool. Writes are only accepted inside the
specific regions belonging to catalogued method stubs, the write log has to be
identical across the two interpretation runs, every restored body has to reparse
and pass structural verification, and each one goes back under its original
metadata token. If any stub is left unrecovered, nothing downstream is allowed to
run and no output is produced. A partially decrypted assembly is worse than no
output, because it looks like a result.

**4. Neutralise anti-tamper.** The integrity check is proven — the tool follows
the verification through the machine and confirms it is a signature or checksum
comparison — and only the proven check subtree and its failure paths are removed.
This has to happen before the file is modified, for the obvious reason.

**5. Simplify the logic.** A group of stages fold away the machinery that makes
control flow unreadable:

- *Constant predicates* — Reactor's helpers that always return the same value are
  interpreted, and their call sites replaced with the value.
- *Global state capture and folding* — the loader initialises a module-wide
  object of integer fields, which the obfuscated branches test against. The
  interpreter records what the loader put there, the tool proves those fields are
  written once and never again, and the reads collapse to constants.
- *Dispatcher deobfuscation* — the `switch` loops are turned back into ordinary
  control flow, but only where the state variable is unique, every incoming edge
  is accounted for, all transitions are concrete, and the result passes stack and
  exception-region validation. Anything ambiguous is left alone.
- *Dead-code removal* — with the predicates folded, the branches Reactor inserted
  are now provably one-way, so the junk behind them is unreachable and goes.

The order inside this group matters: folding the predicates is what makes the
branches constant, which is what makes the junk provably unreachable.

**6. Undo the indirections.** Proxy call tables are decoded and every call site
rewritten to the real target; the decode is only accepted if every entry resolves
and the mapping is one-to-one. Hidden metadata tokens are turned back into direct
references. Pass-through wrappers are bypassed so calls point at what they
actually reach.

**7. Decrypt the strings.** The string table is captured from the interpreted
loader, then every call site is rewritten with its literal. This is
all-or-nothing across the whole assembly: if one site's offset cannot be proven,
no string is replaced at all. A half-decrypted assembly would leave you unsure
which strings you can trust.

Not every hidden string is in the table. The samples also carry a decoder per
string: a method that takes a scrambled literal apart, alters each character, and
puts it back together. No table indexes those, so the step above never sees them,
and what is left in the listing is a call to a randomly named method where a
string should be. Each such method is interpreted twice and its calls replaced by
the string only where both runs complete, agree, and leave nothing behind — no
field written, no handler registered — since a call that also does something
cannot be replaced by what it returns. Where the protector calls the decoder
through a delegate field, and that field is written once with a delegate over a
null target, calling through it is calling that method, and the pair is folded
the same way. It matters beyond readability: a resource is attributed to a role
by finding its name in the code that reads it, and a module that spells its
resource names this way has no such literal anywhere until this step runs.

**8. Restore the resources and extract the payloads.** The module's own bundle
reader is interpreted, the decrypted satellite assembly is taken out of machine
state, and its resource streams are reattached to the module. Hidden payload
assemblies are pulled out and written to disk. The `Assembly.Load` call that the
sample would have made is a capture point — the bytes are taken and the load
never happens.

**9. Read back what was virtualized.** A method a virtualizer emptied is found
by the shape of the seam it had to leave: pack every argument into an array,
pass a number saying which program to run, call once, return. Rather than
parsing the engine's bytecode — which would mean a parser per engine — its own
decoder is run under the machine and the decoded program is read back off the
heap, whole, before any of it executes.

What the operations *mean* is then asked of the engine directly, because its
handlers belong to it rather than to any one program: seed its stack with chosen
values, hand it a single operation, read back the stack it leaves. Several
trials with different values are needed before anything is named, since one
trial cannot tell subtraction from exclusive-or.

Where it *goes* cannot be asked, only watched: an operation performed on its own
has no position to move. So the engine is run once more — entered at the stub's
call site, whose arguments are the real ones — and what is recorded is the order
it performs operations in. An operation followed by something other than the
next one along jumped, and jumped somewhere that is really another operation of
the same program. One run takes one path, so the jumps it did not take are read
off the operation itself, but only where every jump that was watched turned out
to have been decided that way.

That run answers the other question too. An operation that reaches for something
the surrounding program prepared cannot be performed on a stack we arranged, but
it runs perfectly well in place, so the engine's stack is read either side of
each operation as it goes — matched by identity, so that what was left untouched
underneath is not counted. What it took and left is then matched against what
the engine was holding elsewhere at that moment: its tables of values at the
place the operand names, the field the operand names, the array on the stack
under an index. An operation caught carrying off what one of them held has been
seen to load, and one whose value turns up in a place that did not hold it
before has been seen to store. Between asking and watching, each sample comes to
26 of 29 operations accounted for and 21 named, rather than 20 and nine — and
the last of them are reached below.

One more thing is taken from that run, and it is the closest to reading the
engine's own account of itself. Its handlers cannot be read out of the file:
they are one flattened method of several thousand instructions, and over half of
what they call goes through a proxy whose target is picked as it runs. But the
machine performing an operation has already resolved the proxies and walked the
flattening, so what it executes on the operation's behalf is recorded —
arithmetic, comparisons, conversions, and calls that leave the assembly. What
every operation does is then subtracted as housekeeping, leaving what one does
and its neighbours do not. That is what says a conditional branch compares for
less-than, or that an operation nothing else could name resolves a type and
makes an array of it.

Two operations in each sample never settle to an arity, and that is not a
failure to measure but the measurement: an operation told how many values to
take is being told by something, and theirs name a method of the assembly, one
of them always a constructor. Those are the call and the object construction —
between them a third of everything the method does — and each says which method
it reaches for.

Three more readings come from putting the two sources together, and each closes
something neither could close alone. The trials watch every place the engine can
reach and see nothing move; the run watches the handler execute and never sees
it write a static field, which is the one place outside the engine it could put
anything. An operation that takes a value, leaves nothing, and touches neither
has discarded it — a reading the trials refuse on their own, and rightly, since
on their own they cannot see everywhere. The jumps, meanwhile, give away where
the engine keeps its position, being the operations that write it; so an
operation that writes that same place a fixed number that is no part of the
program is not going anywhere in it, which is what returning looks like from
outside, and if it also puts what it took somewhere, that is the value it
returns. And an operation that pushes something unreadable can still be looked
inside: the engine wraps what it stacks, and the wrapper can be seen through to
what kind of thing was in it.

One reading needs the listing below to exist before it can be made, and is put
back into the report once it has been. An operation nothing could perform and
the run never reached still has to fit the depths of the stack around it, and
those can leave it one possible effect and no other; where that effect is to
take a value and leave nothing, and every instruction of that kind names a
static field, the operation is writing the field. It is the counterpart of the
operation the run watched reading one, and takes the same name. Neither half is
a reading alone: consuming a value says nothing about where the value went, and
naming a field says nothing about the direction.

That brings each sample to all 29 of its operations named, but two of the names
stopped short of an IL opcode, and both were the same mistake: looking at a
value and reporting the container instead of what was in it. The engine wraps
what it stacks, and a wrapper holding nothing still has a tag beside the empty
places saying what kind of nothing it is — read as that tag, an operation
pushing a null reference was reported as pushing a number. Looked at as a whole
rather than field by field, a wrapper with nothing in any of its places is the
engine holding null, and the operation that leaves one is `ldnull`.

The other was a load from one of the engine's tables. Which table it was is the
whole reading, since a method's arguments and its locals are kept the same way
and neither table says what it is for; but the arguments are as many as the
method declares and the locals are not, so the length tells them apart. Two
things had to be fixed before the length could be trusted. A cold engine's
tables are empty, so an operation that fetches from one has nothing to fetch and
cannot be performed at all: they are sown with numbers first, far from anything
the stack is seeded with, so that a value taken from a table is never mistaken
for one taken from the stack. And the places under a table run on into whatever
its values are made of, so counting those as entries made every table as long as
its contents were deep. Counted properly, the table is as long as the method has
arguments and every index into it is one of them, and the operation is `ldarg`
rather than `ldloc` — the difference between a listing that says where a value
came from and one that says only that it came from somewhere.

All of that is then written out a second time in the assembly's own terms: the
operations that were named as the IL they stand for, the operands that turned
out to be tokens as the methods, fields and types they name, and the ones
nothing settled as `??` beside its operand and what was counted about it. Every
operation in each of the three samples can now be written this way, and none is
left `??`.

Reading it back is also what checks it. The dispatcher of a flattened program
carries a table of places rather than a single one, and taking every arm of it
turns the program back into blocks; from the first operation onwards the depth
of the stack can then be walked through the whole thing, adding what each
operation leaves and subtracting what it takes. Every place two paths arrive at
has to agree about how deep the stack is, or one of the readings is wrong. In
the three samples the walk reaches every operation any path arrives at and finds
no disagreement anywhere — which is a far stronger statement about the readings
than any one of them could make alone. What no path arrives at is reported too,
and whether that is dead code or somewhere the reading cannot go is itself worth
saying. A walk that was never once at a loss followed everything there was to
follow, so what it did not arrive at cannot be arrived at. That is the case in
all three samples: four to fourteen operations each, sitting after an
unconditional jump with nothing pointing at them, code the protector emitted and
never uses.

The walk is also how the last unmeasured operations are settled. A program whose
every other operation is known is a system of equations with one unknown in it —
the depth where an operation begins is fixed by the paths in, the depth where the
next begins by the paths out, and the difference is its effect whether anything
watched it or not. Flattening helps here rather than hindering, since every block
ends by rejoining the dispatcher at a depth the dispatcher fixes, so the unknowns
are pinned from both sides. A solved effect is then used to solve the next, but it
has to answer for itself: if carrying it through contradicts a depth arrived at
another way, it is withdrawn and the program solved again without it. This says
an operation takes one more than it leaves; it does not say what it did with it,
and nothing is named on the strength of it.

A fourth sample, the assembly one of the others carries, has an engine put
together differently, and three of its differences were worth answering.

Its handlers do not read the operation they are performing. The loop around them
unpacks it first — reads the operand out of the operation and writes it to a
field of the engine — so a handler performed on its own reads a field nothing
filled in, and two dozen of them refused for the same reason. The unpacking is a
pair of instructions in the engine's own code, read a field of the operation and
write a field of the engine, and nothing else in the engine has that shape; read
back and repeated before each trial, it took the operations performed in
isolation from 19 to 38 of 43.

Its program mostly calls the framework rather than itself. An operation whose
arity is decided by its operand is calling the method the operand names, and the
name was being looked for as a definition in this assembly — which a call to
`SHA1.Create` does not have and never will. A reference is as much a name of a
method as a definition is, and it carries the signature, which is the whole of
what decides how many values the call takes. Reading the reference took the
listing from 4586 of 4854 operations written as IL to 4826.

Its operand also bounds what an operation can be. An operation whose operand
names a field is one of the six that name a field, and which six depends on
whether the field is static: a static one can be read, written or have its
address taken, leaving one more, one fewer or one more on the stack, while an
instance one takes the object as well. So a solver that concluded from the
depths around it that a write to a static field consumes two values had followed
a wrong depth in from somewhere, and saying so is better than letting the
conclusion spread. Where the bound leaves two possibilities and the depths
cannot choose, each is put to the program in turn and the one that contradicts
nothing is adopted — the same standard as the rest of the solving, and where
both survive, nothing is claimed.

Two readings of a jump had to be made harder to come by. An operation is watched
jumping when the operation performed after it is not the one after it in the
program, and that is also what a program entered twice looks like at the seam
between the two entries. One crossing is therefore not enough to overturn a
reading arrived at by performing the operation and watching what it did — a
store into the table its operand indexes, in the sample where this bit — though
it is still enough where nothing else was established. The other reading is of
an operation whose operand turns up in one of the engine's own fields, which is
how a jump nothing was watched taking is recognised; a value written at the
place its operand indexes is not that, and slots of a table are now told apart
from fields of the engine so that a store is not read as a branch.

Where a program's blocks are entered from a table, an operation nothing reaches
is either dead or reached a way the reading has not followed, and a handler is
the second sort: it is entered by a throw, with the exception on the stack, and
no ordinary path models that. The engine parses its guarded regions into objects
of its own, which are read back, but the numbers in them are not labelled and
which one is the handler is not stated. So each is tried: a place the walk
already arrives at is left alone, and one it does not is walked from with a
value on the stack and kept only where the depths still agree everywhere. In the
sample that carries four of them, the four handlers are found and twelve
operations join the walk; the eight that remain are blocks the dispatch table
never selects, which is a fact about the program.

What remains in that sample is three operations of the forty-three that nothing
asked and nothing watched. Each of them takes one more value than it leaves,
because the program around it leaves it no other choice, so the walk carries on
through them and the listing says of each that its effect was never established.

The result is a listing rather than a method body. Nothing is rewritten on the
strength of it, and nothing is emitted: a body that is nearly right is worse
than none, since an analyst told a method does something it does not will act on
it, where one told an operation is unknown will go and look.

**10. Remove the protector.** Covered in its own section below.

**11. Verify, then emit.** Covered in the section after that.

## Deleting Reactor's code without deleting the program's

Once recovery is done, Reactor's runtime is still sitting in the assembly. The
obvious way to remove it is to work out which types belong to the protector and
delete those. That is what recognition-based tools do, and it works until the
protector changes shape, at which point the tool deletes the wrong thing or
nothing at all.

ReactorUnpack uses a different rule, and it is the most distinctive thing about
the tool: **a declaration is deleted only when recovery can say why it has no use
left.**

Concretely, when a pass replaces a resolver call with the string it would have
returned, it has also destroyed the only reason that resolver existed. It records
that. When another pass redirects a call past a wrapper, it records the wrapper.
When the calls into Reactor's loader are proven inert and cut, the loader subtree
is recorded. Cleanup then removes only declarations that appear in those records
*and* are unreachable *and* are invisible outside the assembly *and* are not
referenced by anything that survives.

Unreachable code that no pass accounts for is counted, reported, and kept.

The trade-off is deliberate. It means a program's own unused internal helper
survives, so the output is slightly larger than a tool that tree-shakes would
produce. In exchange, the output is an unobfuscated version of the input rather
than a smaller program, and the rule does not depend on recognising this year's
Reactor.

The check that this works is a set of **known-clean assemblies** run through the
same pipeline as controls. They are the unprotected equivalents of protected
samples in the corpus. Cleanup must remove nothing from them at all. If a change
to the tool ever starts deleting program code, those controls fail before
anything else does.

## Why the output can be trusted

Every mutating stage sits inside a transaction covering the whole method body —
instructions, branch targets, local variables, stack depth, and exception
regions — so a change that fails validation is undone completely rather than
leaving a half-edited method.

Before anything is written, the modified module is compared against the original.
It may differ only in ways the passes explicitly declared. Public API, resource
names, entry point, and strong-name state must be intact. Every branch and
exception-region boundary must be inside its method. No reachable call may have
an invalid operand.

The file is then written and **compared again against the module it came from**,
because serialising metadata is itself a step that can go wrong. That comparison
is by member name rather than by metadata token, since deleting a row forces the
writer to renumber everything after it.

If any of that fails, or any stage that can affect the module was incomplete, no
file is written and the reason is reported. This is why you will sometimes get a
report and no cleaned copy. It is the tool working correctly: the alternative is
handing over a file that looks fine and is not.

## What this approach costs

Being honest about the trade-off, since the whole design turns on it.

An execution-based tool calls the sample's real decryption routine, so it handles
ciphers and encodings nobody has modelled. ReactorUnpack has to model what it
interprets, so an unmodelled framework call stops recovery. When Reactor ships a
scheme that reaches outside the modelled surface, the execution-based tool will
keep working and this one will refuse until the model is extended.

That refusal is the design working as intended rather than a bug, but it is a
real capability gap and it is the reason the corpus and the fail-closed gates
exist. A tool that would rather produce nothing than produce something wrong has
to be very sure about when it produces nothing.

## Further reading

- [compatibility.md](compatibility.md) — the exact support contract, the
  structural detection signals, the verification gates, and the fail-closed
  boundaries, in reference form.
- [parity.md](parity.md) — stage-by-stage comparison against NETReactorSlayer,
  including where this tool is weaker.
- [corpus.md](corpus.md) — how correctness is measured against real samples.
- [reading-the-output.md](reading-the-output.md) — what the reports contain.
