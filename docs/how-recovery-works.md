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
model and refuses everything else.

It handles integers, objects, arrays, fields, branches, switches, and enough
exception-handling flow to follow real loader code. Pointers are modelled
symbolically, so when Reactor's loader writes decrypted bytes into what it thinks
is executable memory, the write lands in a simulated buffer that the tool can
read afterwards.

Calls out to the .NET framework are **deny-by-default**. There is an allowlist of
modelled operations — reading embedded resources, streams, text encoding, hashing,
decompression, symmetric ciphers, a few `Marshal` operations, and synthetic stand-ins
for things like "which module am I in". Anything not on that list stops
interpretation rather than being guessed at or skipped.

That refusal is the safety property, and it is also load-bearing for correctness.
Because the machine refuses every call it does not model, a routine that
interprets all the way to completion cannot have done anything outside the
modelled surface. There is no hidden side effect it could have had, because there
was no unmodelled call through which to have one. Several later stages depend on
that guarantee.

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

All of that is then written out a second time in the assembly's own terms: the
operations that were named as the IL they stand for, the operands that turned
out to be tokens as the methods, fields and types they name, and the ones
nothing settled as `??` beside what was counted about them. Around 95% of each
sample's operations can be written this way.

Reading it back is also what checks it. The dispatcher of a flattened program
carries a table of places rather than a single one, and taking every arm of it
turns the program back into blocks; from the first operation onwards the depth
of the stack can then be walked through the whole thing, adding what each
operation leaves and subtracting what it takes. Every place two paths arrive at
has to agree about how deep the stack is, or one of the readings is wrong. In
the three samples the walk reaches 96%, 99% and 99% of the program and finds no
disagreement anywhere — which is a far stronger statement about the readings
than any one of them could make alone.

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
