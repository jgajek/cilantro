# How CILantro undoes it

This is the counterpart to [how-net-reactor-works.md](how-net-reactor-works.md)
and [how-confuserex-works.md](how-confuserex-works.md). It assumes you have read
one of them, or already know what the protector does.

Most of what follows is protector-neutral, because the technique is. The ordered
pipeline in the middle is Reactor's, and the shorter one after it is ConfuserEx's;
everything before and after applies to both.

## The central idea

The protections all share one weakness: **the decryption routine ships with the
file**. It has to. The program must be able to decrypt itself on the machine it
runs on, with no network and no key server, so everything needed to undo the
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

CILantro takes the other way. It **interprets** the decryption routine in a
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
debugger is attached, the process is number 1 and the only one, the runtime
reports itself as .NET Framework 4.8, and nothing else is answered at all. (That
runtime answer is a built-in default; a sample that expects modern .NET can be
told otherwise through a profile, and CoreCLR samples are recovered regardless,
since recovery does not turn on the sample believing a particular version.)
Protected code asks the debugger
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

## The order things happen in, under Reactor

The protections are layered, so they have to come off in a specific order. Some
of the ordering is obvious, some of it is not. What follows is the Reactor
pipeline, which is the longer of the two;
[the ConfuserEx one](#the-order-things-happen-in-under-confuserex) is below it.

**0. Get to a managed file at all.** Before any of the below, a file with no CLR
header is checked for being a Reactor native bootstrap, and if it is, the
assembly is decrypted out of its resources and written out. That run ends there:
what comes out is a protected assembly of its own, so it is handed back as a
recovered stage rather than carried into the steps below. Everything that
follows assumes a managed input, which for a bootstrap means a second run.

**1. Look before touching.** The raw metadata is parsed by hand first — before
handing the file to a library that would normalise it — to record duplicate
table rows, malformed stream bounds, and native-packing markers. Reactor puts
deliberate anomalies here to break tools, and they are evidence rather than
errors. If the file is a mixed-mode image, whose CLR header declares a native
entry point, this is where the tool stops.

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

A loader that stops partway is not the same as a loader that proved nothing. The
bodies it had already written are each held to every check above, so they are
grafted and reported, and the stage reports itself partial rather than complete —
which keeps every stage that would modify the assembly gated, exactly as an
unrecovered stub does. What changes is that the bodies are readable and the report
names them, instead of the run ending with nothing to show.

Those bodies are then used to interpret the loader again. Reactor protects its own
runtime with the same JIT hook it uses on everything else, so on a sample whose
loader calls into its own virtualized code, the first interpretation reads a
placeholder where the engine should be and stops on state the engine would have
built. The second reads the real engine, which is the state a process is in once
the JIT hook has fired. This repeats while each round recovers a body the previous
rounds did not, so a loader that runs to completion the first time pays nothing
for it.

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

**9. Read back what was virtualized.** What follows is the design of this step;
[devirtualization.md](devirtualization.md) is the same ground covered for someone
meeting it for the first time, with worked examples and a discussion of what
transfers to other protectors.

A method a virtualizer emptied is found
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

Three of that sample's operations resisted everything for a while, and each
needed a different question. One is refused by every arrangement alike, which
looks like failure until you notice what the refusal says: it names the type it
wanted. Handing it one of those and finding it throws exactly what it was given
is what a throw looks like from outside. Another has no effect on anything the
trials can see and carries no operand, which is a description of doing nothing —
adopted only as a last resort, after every other way of naming an operation has
declined, because "it does nothing" is also what an operation looks like when the
trials failed to reach it. The third leaves one value and takes none, like a
table load, and the value it leaves is its own operand every time: a constant
push, and reading it as a load of a slot that happens to hold the same number
would have produced a body that names slots the method does not have.

That leaves one operation of the forty-seven that nothing asked and nothing
watched. It takes one value and leaves one, and at every site its operand names a
method of the assembly whose signature accounts for that, so the listing reads it
as a call and says on what grounds.

A method the reading does not settle in full is left as the stub it shipped as,
because a body that is nearly right is worse than none: an analyst told a method
does something it does not will act on it, where one told an operation is unknown
will go and look.

**10. Build the readings back into code.** Where the reading is complete, the
listing is lowered to IL and written into the method it belongs to. It happens
here, before cleanup, for two reasons: a virtualized method is one nothing calls
by name, so the pass that removes what recovery orphaned would delete it, and the
new bodies call helpers that have to survive with them. Declaring the built
methods as roots settles both. Every method built this way is marked with an
attribute naming it a reading, which is the difference between it and every other
body in the cleaned copy, and a strict run does none of it. The step is described
at length in [devirtualization.md](devirtualization.md), including the guarded
regions it has to reconstruct and the run that checks the result against the
original.

**11. Remove the protector.** Covered in its own section below.

**12. Verify, then emit.** Covered in the section after that.

## The order things happen in, under ConfuserEx

The same machine, the same gates, and a much shorter list — because ConfuserEx
does its decryption in one stage rather than lazily, and because some of its layers
are not undone at all.

**1. Look before touching, and identify the protection.** Both as above, and
neither is Reactor-specific. Recognition asks a separate question per protector
and then settles which answer the run is acting on, so a detector saying "not
mine" is not mistaken for the run having failed to recognise anything. What
identifies ConfuserEx is structural: a section that is encrypted, writable and
executable with method bodies inside it, a module initializer reaching into it,
and names built from characters with no visible width.

**2. Decrypt the section by interpreting the initializer.** The module
initializer is interpreted from its first instruction. Its first call is the
anti-tamper decryptor, which hashes the rest of the image, derives its key, and
writes the plaintext back over the ciphertext — into the simulated image, where
the writes are recorded rather than performed. That log is then replayed into a
copy of the file, the copy is reparsed, and the bodies are grafted back into the
assembly under their original tokens.

The gates are the ones step 3 of the Reactor pipeline uses, because it is the same
code: the two interpretation runs must agree on status, on step count, on the
write log, on the loader-initialized integer fields and on what the loader was
observed doing before anything is replayed; every restored body must reparse and
begin with a well-formed method header at the address its metadata declares — the
check that separates a section decrypted with the right key from one decrypted
with the wrong one; and the whole graft verifies or rolls back.

What differs is only the bound on which writes may be replayed. Reactor patches
individual body slots and must not touch a byte outside them; ConfuserEx decrypts
a whole section it owns, and would fail a slot-shaped bound for doing exactly what
it is supposed to do. So the bound is a section, established twice over: the span
the write log itself covers must fall inside one section, and that section must be
the encrypted one recognition independently identified. Neither alone would do —
the first would let a decryptor nominate its own target, and the second would not
notice writes scattered outside it.

Unlike Reactor's, this bound has to cover field data as well as code, because the
constants table lives in the same section. A recovery that reinstated only the
bodies would hand back a module whose code was readable and whose literals were
still ciphertext, and nothing downstream could tell.

If any of that fails, no cleaned copy is written. A half-decrypted section is
worse than none.

**3. Read the constants table by asking the sample's own lookup methods.** The
literals are now back, compressed and encrypted, in field data. Rather than
decompress the buffer, the tool runs the initializer stage that fills it and then
calls the lookup methods the program calls, with the numbers the program passes —
only the numbers that appear literally at a call site, so a buffer of unknown size
is never enumerated.

Finding those numbers takes some care, because a flattened body does not keep the
number next to the call that consumes it. The tool follows control flow backwards
from the call while there is exactly one way in; a call reachable from two places
was reached with two different numbers, and picking either would mean reporting
one of the program's paths as the program.

Two machines, built separately and asked in opposite orders, must return the same
value before it is used, and a lookup whose frame leaves state behind is refused
rather than removed, since removing that call would remove the effect with it.
Strings then go back into the code as literals, in one transaction that verifies
or rolls back. Byte arrays are reported instead of rebuilt: re-emitting one as
field data and an initializer call changes more of the module than reading its
contents does, and the contents are what an analyst is after. They go to a
constants report beside the assembly.

**4. Unflatten the dispatchers.** ConfuserEx's flattener does not keep its state
in the state variable the way Reactor's does. It pushes the next state on the
evaluation stack and leaves it there across the jump, and the dispatcher picks its
case from the remainder of that value rather than from the value itself. That is a
different shape, so it gets its own analyzer — but the same rewrite, the same body
transaction, the same stack and whole-assembly validation, and the same cleanup
passes behind it.

Because the state is never anything but integer arithmetic over constants and the
previous state, it can be settled without running the program. The analyzer
enumerates the reachable combinations of instruction, modelled stack and state, and
records which case each instruction that hands control to a dispatcher selects.
Where every path through that instruction selects the same case, the instruction
becomes a direct jump to it and the arithmetic that computed the state is erased.

Four things make that safe rather than merely plausible. The claim being proven is
about an instruction, not a path, so an edge is only rewritten when every visit
agrees — which is why running out of budget abandons the whole method instead of
keeping the part already proven. The arithmetic erased has to be a contiguous
run of side-effect-free integer instructions with nothing jumping into the middle
of it, so erasing it cannot remove anything but the state, and nothing may jump to
the edge itself either, since what jumped there would not have run the arithmetic.
The direct jump has to stay inside the same exception regions.

The fourth is the one that cost the most to learn, and it is what makes the other
three enough. Jumping straight to a case skips the dispatcher, and the dispatcher
does one thing besides jumping: it writes the state into its variable. A fragment
reached directly never has that write performed for it, so anything reading the
variable afterwards sees whatever was there before — which is not a hypothetical. An
earlier version of this pass erased the arithmetic and left the write undone, and
that broke the constants initializer on both corpus samples, taking every recovered
string with it.

The fix is for the edge to carry the write. Where an instruction outside the erased
arithmetic still reads the state, each redirected edge assigns it, so the edge is an
exact substitution for the path it replaces. That is worth more than correctness
alone: because a redirect no longer depends on what happened to the other edges, they
stop having to be proven together. A method with one edge nobody can settle now gets
the rest of its edges straightened and keeps its switch only for that one. Where two
states select the same case the edge is given up rather than guessed at, since there
is no single value to assign.

Two further things follow from the state travelling on the stack rather than in a
variable, and both are about the result being a method a runtime will accept rather
than about which edges can be proven. Neither showed up in the stack-depth checks the
pass already ran, and both were found by running an unflattened program.

The first is that a dispatcher is entered with its state pushed, so every jump into it
carries something on the stack. CIL allows that for a backward jump only when a
forward path has already established what the stack looks like there, and the forward
path is the single fragment that falls into the dispatcher instead of jumping to it.
Redirecting that one fragment is therefore what makes all the remaining jumps back to
the dispatcher illegal — a partly unflattened method could be correct edge by edge and
still be rejected wholesale. Rather than protect the fall-through, the pass takes the
state off the stack: the dispatcher is given a variable to read its state from, and the
edges still going through it store into that variable before jumping. The constraint
then does not apply to any of them, which is also what makes the edges genuinely
independent rather than nearly so.

The second is that scaffolding nothing reaches any more cannot simply be left. A
fragment that only consumed what an edge used to push still consumes it where it
stands, and unreachable code is checked against an empty stack, so the dispatcher's
own arithmetic becomes an error the moment nothing pushes a state for it. Whatever the
redirects strand is therefore neutered.

With the state in a variable, a path that merges with another before reaching the
dispatcher can be resolved where it computed its own state instead of at the merge.
This is worth doing because the merge is exactly what a branch in the original program
turns into: the two arms each settle on a state, and only their meeting point has two.
Attributing the state to the arm sends each arm straight to its case and recovers the
original conditional, leaving the merge in place for anything else that reaches it.

What that comes to on the two samples is 4,645 of 4,844 edges and 5,933 of 6,200 —
about nineteen in twenty — with 51 of 127 and 66 of 155 flattened methods losing their
dispatcher entirely. Every edge left standing is left for one reason: two states that
meet before either has finished being computed, so neither the merge nor the last
instruction to push names a single path. Nothing is lost to unremovable arithmetic or
to exception regions.

Going further would mean duplicating each shared fragment per state, or turning its
exit into a test against the state. Both would end the property that the cleaned copy's
blocks are the sample's own.

**5. Junk, then cleanup, then verify and emit.** The protector-neutral stages
apply unchanged: unreachable code that recovery accounts for is removed — which
now includes the dispatchers every edge was redirected away from — generated names
get readable placeholders, which matters more here than anywhere else, since
invisible names are otherwise indistinguishable from one another rather than merely
ugly, and the same verification gate decides whether anything is written at all.

**What is not in this list.** ConfuserEx's strong reference proxies, its encrypted
resources and its embedded payloads. Its mild proxies need no entry of their own:
they are plain static forwarders, and the forwarder redirection written for
Reactor's wrappers substitutes their targets without knowing whose they are. Its
strong ones bind a delegate at run time from the proxy field's own signature blob
through a `DynamicMethod` the bridge emits, and reading that statically would mean
modelling `Reflection.Emit`, so a sample using them comes out with them intact.

## Deleting Reactor's code without deleting the program's

Once recovery is done, Reactor's runtime is still sitting in the assembly. The
obvious way to remove it is to work out which types belong to the protector and
delete those. That is what recognition-based tools do, and it works until the
protector changes shape, at which point the tool deletes the wrong thing or
nothing at all.

CILantro uses a different rule, and it is the most distinctive thing about
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
ciphers and encodings nobody has modelled. CILantro has to model what it
interprets, so an unmodelled framework call stops recovery. When a protector ships
a scheme that reaches outside the modelled surface, the execution-based tool will
keep working and this one will refuse until the model is extended.

The other side of that trade is what made a second protector cheap. Adding
ConfuserEx meant a detector, a replay bound, a way of reading its constants table,
and nothing else: no cipher, no key schedule, no table format. The machine that
interprets Reactor's decryptor interprets ConfuserEx's too, because it was never
told anything about either.

That refusal is the design working as intended rather than a bug, but it is a
real capability gap and it is the reason the corpus and the fail-closed gates
exist. A tool that would rather produce nothing than produce something wrong has
to be very sure about when it produces nothing.

## Further reading

- [how-net-reactor-works.md](how-net-reactor-works.md) and
  [how-confuserex-works.md](how-confuserex-works.md) — what the two protectors
  do to a file, which is what the pipelines above are answers to.
- [devirtualization.md](devirtualization.md) — step 9 above at length: what code
  virtualization does, how the hidden program is recovered and read, and what of
  the approach transfers to other protectors.
- [compatibility.md](compatibility.md) — the exact support contract, the
  structural detection signals, the verification gates, and the fail-closed
  boundaries, in reference form.
- [parity.md](parity.md) — how this tool compares to NETReactorSlayer, de4dotEx
  and Krypton, stage by stage against the first of them, including where this
  tool is weaker.
- [corpus.md](corpus.md) — how correctness is measured against real samples.
- [reading-the-output.md](reading-the-output.md) — what the reports contain.
