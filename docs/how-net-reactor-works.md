# How .NET Reactor works

This explains what .NET Reactor does to a file, for an analyst who does not work
in .NET day to day. You do not need to know C#. Where a .NET term is
unavoidable it is explained the first time it appears.

The companion document, [how-recovery-works.md](how-recovery-works.md), explains
what ReactorUnpack does about each of these.

## Why .NET is different

A native Windows executable contains machine code. To hide it, a packer
compresses or encrypts the whole thing and prepends a stub that unpacks it into
memory at startup. Analysis means dumping memory after the stub has run.

A .NET executable is not machine code. It contains two things:

- **Metadata** — structured tables describing every type, method, field, and
  string in the program, by name. This is a database, not code.
- **IL** (Intermediate Language) — a compact stack-based instruction set. The
  runtime compiles IL into machine code method by method, on first call, using
  the **JIT** (Just-In-Time compiler).

The consequence is that a .NET binary is *self-describing*. A decompiler reads
the metadata and IL and reconstructs source that is often close to what the
author wrote — variable names and all. There is no disassembly guesswork.

That is what protectors exist to break, and it is why they attack differently
from native packers. Reactor is not mainly trying to stop you from getting code
into memory. It is trying to make the metadata lie, make the IL unreadable, and
make the real IL absent from the file altogether.

## The loader

Almost everything below depends on one shared mechanism, so it is worth
understanding first.

Reactor adds a hidden type to the assembly containing its runtime — the
decryption routines, the lookup tables, the hooks. It then inserts a call to
this runtime at the very start of the program, and also at the head of the
initializer of nearly every type in the assembly. (A **type initializer** is code
the runtime runs automatically the first time a type is used.)

The effect is that no matter which part of the program runs first, Reactor's
runtime is already installed. It decrypts what needs decrypting and installs the
hooks that handle the rest lazily.

This also means the protector's code is reachable from application code
everywhere, which is deliberate: it makes the runtime hard to simply delete.

## Name obfuscation

Every type, method, and field name in the metadata is replaced with a generated
string — `H1lrRRwH0tOVtn61XvY`, `vwAcYxvHwU`. Some of these use characters that
are legal in metadata but not in C#, so a decompiler cannot even render them
normally.

**What you see:** class and method names that are meaningless.

**What survives:** anything that has to keep its name to work. Public API of a
library, types used by reflection, P/Invoke targets, and anything the author
explicitly excluded. In practice a protected library often keeps most of its
public surface named, which gives you a foothold.

**Recoverable?** No. The original names are deleted, not encrypted. They are not
in the file, and no tool can bring them back. Renaming features in deobfuscators
substitute readable placeholders (`Class7`, `Method12`), which helps you navigate
but is not restoration.

## String encryption

Every string literal is removed from the metadata and stored encrypted in a
table. Each place that used a string is rewritten to call a decryption routine
with an integer — an offset into that table.

**What you see:** `strings` on the file returns nothing useful. In a decompiler,
code reads `Something.Decrypt(148263)` instead of `"http://evil.example/gate.php"`.
URLs, registry keys, filenames, and command strings are all gone.

**Extra defence:** the decryption routine typically checks *who called it* by
walking the call stack. If you try to call it yourself from your own harness, it
notices it was not called from inside the protected assembly and returns garbage
or throws.

## Control flow obfuscation

The instructions of a method are chopped into fragments and reassembled inside a
loop driven by a `switch` on a state variable. Instead of running straight
through, the method loops: read state, jump to the fragment for that state, run
it, set the next state, loop.

The fragments are emitted in arbitrary order, so the textual order of the code
has nothing to do with execution order. This is often called a **dispatcher** or
flattened control flow.

**What you see:** a decompiled method that is one huge `while` loop containing a
`switch` with dozens of cases, each ending by assigning a number to a variable.
The logic is all present and completely unreadable.

## Junk instruction insertion

Reactor inserts sequences that are never executed but that decompilers must try
to make sense of. A common shape is a branch that always jumps, followed by a
call to something that does not exist or has a deliberately malformed reference.

Because the call is never reached, the program runs fine. Because the reference
is invalid, tools that try to resolve everything either produce garbage or crash.

**What you see:** decompiler errors, or methods that fail to decompile at all.

## Proxy calls

Instead of one method calling another directly, the call goes through an
indirection. Reactor's runtime builds a table at startup mapping identifiers to
real targets, and the call site fetches from the table and invokes whatever comes
back.

**What you see:** a call graph that is mostly empty. Cross-references do not
work. You cannot tell what calls `CreateProcess`, because nothing appears to call
it directly.

## Hidden metadata references

Related to the above. Where code needs to refer to a type or method, it can do so
by **metadata token** — a 4-byte number identifying a row in the metadata tables —
looked up at run time, rather than by a direct reference.

**What you see:** code that manipulates integers and produces types out of
nowhere. The dependency exists but is invisible to any tool reading references.

## NecroBit: encrypted method bodies

This is Reactor's headline feature and the one that matters most.

The IL of every method is removed from the file and stored encrypted. Each method
is left as a stub that does nothing. Reactor then installs a **hook into the JIT
compiler** — the component that turns IL into machine code. When the runtime asks
the JIT to compile a method, Reactor's hook intercepts the request, decrypts the
real IL for that method, and hands it over instead of the stub.

The consequence is severe: **the real code is never in the file in readable form,
and never all in memory at once.** It is decrypted one method at a time, at the
moment that method is first called. A memory dump gets you the methods that
happened to run, and nothing else.

**What you see:** a decompiler shows the full class structure — every type, every
method signature — with every method body empty or a trivial `return 0`. It looks
like a skeleton of a program.

## Anti-tamper

Reactor computes a checksum or signature over the assembly at build time and
embeds it. At startup, the runtime recomputes it and compares. If the file has
been modified — by you, by a patch, by a deobfuscator that got it wrong — the
program refuses to run or corrupts itself.

Related: **strong-name verification**, a .NET signing mechanism, is also checked
so that re-signing a modified assembly does not defeat the check.

**Why it matters to you:** it is the reason careless deobfuscation produces a
file that will not run. It is also why a tool needs to remove the check
*correctly* rather than just patching a jump.

## Anti-debug

The runtime checks for a debugger — `IsDebuggerPresent`, timing checks, checks on
the .NET debugging environment variables — and terminates if it finds one. This
targets dynamic analysis specifically.

## Encrypted resources and embedded payloads

.NET assemblies can carry embedded **resources**: arbitrary blobs stored inside
the file, normally used for images and localised text.

Reactor encrypts the application's own resources and stores them as one blob. At
run time it hooks the .NET resource-lookup event so that when the program asks
for a resource, the runtime decrypts it on the fly.

The same mechanism is used to hide **entire assemblies**. A malware family will
commonly protect a small loader with Reactor and stash the real payload inside it
as an encrypted resource, which the loader decrypts and runs directly from memory
without ever writing it to disk.

**What you see:** one or two large high-entropy blobs, and a program that
appears to do very little. The interesting code is inside the blob.

## Native packing

Everything above assumes the file is still a .NET assembly. Reactor can also
compress the whole managed assembly and wrap it in a **native** loader stub, so
the file on disk is a normal Windows executable with the .NET part hidden inside.
There is also a variant where the NecroBit decryption routine itself is compiled
to machine code rather than IL.

**What you see:** the file does not open in a .NET decompiler at all, or opens
with almost nothing in it.

ReactorUnpack detects this and reports it as unsupported rather than producing a
damaged result. It is not implemented, for the reason given in the README: no
sample has been available to develop against.

## Code virtualization

The strongest and least common option. Selected methods are translated into
bytecode for a custom virtual machine that Reactor generates and embeds. The
original IL does not exist anywhere, in any form, at any point.

Undoing this means reverse-engineering a bespoke instruction set per sample —
and it really is per sample: across the samples examined here, the same engine
numbers the same operations differently in every build, so a table of opcode
meanings learned from one is worthless on the next.

No other public tool lifts it at all. What ReactorUnpack does is recover the
hidden program and read it: the affected methods are
named, the program behind each one is taken by running the engine's own decoder
rather than by parsing its bytecode, and what each operation means is established
by making the engine perform it on chosen values, by watching what it fetches,
stores and jumps to while the program really runs, and by recording what the
engine works out on its behalf. The result is written out as an annotated listing
and as the assembly operations it stands for, with every reference into the
assembly named, and a walk of the stack's depth over the whole program is used to
check the readings against each other. You cannot read the method, but you can
usually tell what it is for and how it is shaped.

It also builds those readings back into IL in the cleaned copy, where a
decompiler will open and follow them — verbose, boxed, and still flattened, but
navigable. A body built that way is a reading rather than a proof, so each method
it goes into is marked with an attribute saying so and a `--strict` run builds
none of them unless you ask with `--devirtualize`; where the protected method is
on the sample's own unpacking path, the tool interprets that path with the built
bodies in place and reports whether the same payload came out.

That is a large subject and it has its own document:
[devirtualization.md](devirtualization.md) covers what the protection does, how
the program is recovered and read, what the output files mean, and how much of
the approach would survive a protector other than Reactor.

One consequence is worth knowing here, because it affects samples whose methods
you never look at: payload extraction still works when the unpacker itself is
virtualized, since the interpreter is ordinary IL and can simply be run.

## Generations

Reactor's runtime has changed shape across versions, and the two that matter for
current samples are:

- **JIT-hook generation** — the NecroBit design described above, with encrypted
  bodies restored through a JIT callback. This is what most current samples use.
- **Delegate-runtime generation** — an older design leaning more heavily on proxy
  call tables and less on body encryption.

ReactorUnpack identifies which one it is looking at from structural evidence —
the shape of the metadata and the code — rather than from version strings or file
hashes, which is what lets it work on samples it has never seen.

## Putting it together

A typical protected sample combines: name obfuscation, string encryption, control
flow flattening, junk insertion, NecroBit body encryption, anti-tamper, and an
encrypted payload resource. Opening it in a decompiler shows a structurally
complete but entirely empty program, with a handful of meaningless names and no
strings.

Every one of those layers has to come off before the code reads, and they have to
come off in a particular order — you cannot read the control flow of a method
whose body has not been decrypted yet.

That ordering is the subject of [how-recovery-works.md](how-recovery-works.md).
