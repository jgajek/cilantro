# How ConfuserEx works

This explains what ConfuserEx does to a file, for an analyst who does not work in
.NET day to day. You do not need to know C#. Where a .NET term is unavoidable it
is explained the first time it appears.

Its sibling document, [how-net-reactor-works.md](how-net-reactor-works.md),
covers the other protector this tool handles, and
[how-recovery-works.md](how-recovery-works.md) explains what CILantro does about
each of the layers below. If you have read the Reactor document, the section
after this one is the short version of what is different.

ConfuserEx is free and open source, which is the first thing worth knowing about
it. Reactor is a product somebody buys; ConfuserEx is a project somebody
downloads, reads, and modifies. That difference shows up everywhere in what
follows: the design is public, and so are the forks, which means the protector
you are looking at may not be quite the one that was released.

## Where it differs from Reactor

Both protectors encrypt the code, the text, and the names. The structural
difference is *when* the decryption happens, and it changes what analysis looks
like.

Reactor's NecroBit decrypts one method at a time, at the moment that method is
first called, through a hook in the compiler. Nothing is ever all readable at
once, and a memory dump gets you only the methods that happened to run.

ConfuserEx, in the configuration these samples use, decrypts everything before
the program starts. A whole region of the file is encrypted at build time, and
the first thing the assembly does when it loads is decrypt that region in place,
in memory, in one pass. Every method body and the whole table of literals come
back together.

That sounds weaker, and for a dynamic analyst it is: a dump taken any time after
startup has all of the code in it. Statically it is not weaker at all, because
the file on disk still contains none of the code, and the routine that decrypts
it is one long arithmetic loop whose key is derived from the file itself.

## The module initializer

Almost everything below hangs off one entry point, so it is worth understanding
first.

A .NET assembly can carry a **module initializer**: code the runtime runs once,
before anything else in that file, no matter which part of the program is
entered first. ConfuserEx puts its whole startup sequence there. In the samples
examined here it is a short method calling five others in a fixed order — the
anti-tamper decryptor first, because nothing else can run until it has finished,
then the anti-debug check, the constants table, and the remaining runtime.

The ordering has a consequence that catches people out. The decryptor's own body
has to be readable, so it sits outside the encrypted region — but the stages it
calls *after* it are inside the region, which means that until the decryptor has
run, those methods look like methods with no code at all. A tool reading the file
statically sees an initializer that calls four empty methods.

## Invisible names

Every type, method, and field name is replaced, as with any obfuscator. What is
distinctive is the alphabet ConfuserEx can use for the replacements: characters
that are legal in .NET metadata but have no visible width — zero-width spaces,
left-to-right and right-to-left marks, and the Unicode bidirectional formatting
characters.

The result is not merely unreadable, it is *indistinguishable*. Two different
methods are both named what appears to be nothing at all, in a listing that
cannot show you the difference, and you cannot type either name to search for it.

**What you see:** a decompiler tree of types and methods whose names are blank,
or a row of identical-looking boxes. Copying a name out and pasting it into a
search finds nothing, or finds the wrong member. Forty-five distinct methods on
one hidden type, all apparently called the same thing.

**What survives:** the same things Reactor leaves alone — anything that has to
keep its name to work, and anything the author excluded.

**Recoverable?** No. As with Reactor, the originals are deleted rather than
encrypted. Substituting readable placeholders is not restoration, but here it is
doing more work than usual: it is the only way to tell two members apart at all.

## Anti-tamper: the encrypted section

This is the layer that hides the code, and it is called anti-tamper rather than
anything about encryption because guarding the file and encrypting it are the
same mechanism.

A **PE section** is a named, contiguous region of an executable file — `.text`
for code, `.rsrc` for resources, and so on. At build time ConfuserEx moves every
method body it is protecting into a section of its own, encrypts the whole
thing, and marks it readable, writable and executable. The key is not stored. It
is derived by hashing the rest of the file, which is what makes this anti-tamper:
change a byte anywhere else and the key comes out wrong, so the code decrypts to
noise and the program dies rather than running modified.

At startup the decryptor finds where Windows mapped the file, walks every other
section hashing it four bytes at a time, derives the key from that hash, and then
decrypts its own section four bytes at a time, writing the plaintext back over
the ciphertext in memory. In the two samples here that is 227,761 and 299,305
bytes rewritten in place, uncovering 242 and 279 method bodies.

**What you see:** a decompiler shows the complete structure — every type, every
method signature — and every body empty, exactly as NecroBit looks. In a PE
viewer there is an extra section with an unusual name, entropy near the maximum,
and the unusual combination of write and execute permissions.

**Extra defence:** the decryptor asks the operating system what protection each
page of the image currently has, and treats a page that is already writable *and*
executable as evidence that something has been done to the file. On an untouched
image Windows maps a writable section copy-on-write, so the honest answer is not
the suspicious one; a tool that models the query carelessly and answers
"writable and executable" tells the sample it is being watched, and the sample
then declines to decrypt and fails later somewhere unrelated.

**Also worth knowing:** ConfuserEx offers a second anti-tamper mode that works
per method through a compiler hook, much as NecroBit does. The support in this
tool is written against the whole-section mode, which is what both samples use.

## Constants: one table for every literal

Every string, and optionally every number and byte array, is taken out of the
metadata and put into a single buffer that is compressed and then encrypted. Each
place that used a literal is rewritten to call a lookup method with an integer
identifying where in the buffer its value lives.

The lookup method is generic — one method that returns whatever type the call
site asks for, so the same table serves strings, byte arrays and numbers. The
buffer itself lives in the encrypted section as **field data**, which is a blob
the metadata points at rather than a resource, so it comes back as part of the
same decryption that recovers the code.

**What you see:** `strings` on the file returns nothing useful, and the metadata
stream that holds string literals is four bytes long — that is, empty. In a
decompiler, code reads `\u200b\u202e(1752640)` instead of
`"http://evil.example/gate.php"`, where the method name is one of the invisible
ones. Every URL, registry key, filename and command string in the program is a
number.

**Extra defence:** the lookup method checks that it is being called from inside
the assembly it was built into, by asking the runtime for the assembly currently
executing and the assembly that called it and comparing the two. Called from your
own harness the two differ, and it hands back an empty value rather than the
literal — quietly, with no exception to notice.

## Anti-debug

One of the initializer's stages checks for a debugger, by the usual means: asking
the runtime whether one is attached, asking the operating system the same
question, and checking the environment variables that the .NET debugging
machinery uses. If it finds one the process ends.

In both samples here that stage's own body is inside the encrypted section, which
means it cannot be read until the decryptor has run — and the decryptor runs
before it. There is nothing to see in the file.

## Control flow obfuscation

The instructions of a method are cut into fragments and reassembled inside a loop
driven by a `switch` on a state variable, so that the order the code is written
in has nothing to do with the order it runs in. This is the same idea as
Reactor's flattening, and it is often called a **dispatcher**.

ConfuserEx has a distinctive touch here: the state variable can be updated by
arithmetic rather than assignment, so working out which fragment follows which
means evaluating an expression rather than reading a number.

**What you see:** a decompiled method that is one large `while` loop around a
`switch` with many cases, each ending by computing the next state.

**Why it matters to you:** this is the layer that survives into the cleaned copy.
The unflattening pass is not written per protector — it looks for a dispatcher
shape it can prove an ordering for, whoever built it — so it does run here, and
in both of these samples it found two dispatchers and unflattened neither. The
right way to read that is untested rather than refused: nothing about ConfuserEx
excludes it, and no sample has yet shown it working. Either way the methods you
open will still be in this shape.

## Reference proxies

Instead of one method calling another directly, the call can be routed through a
field holding a delegate — a .NET value that stands for a method — which the
runtime fills in at startup. The call site invokes whatever the field holds.

**What you see:** a call graph with holes in it. Cross-references fail, so you
cannot ask what calls the process-creation API and get an answer.

**Why it matters to you:** this is the other layer left in place, and here the
position is weaker than for control flow: there is no recognition of it at all
for this protector. Reactor's proxies are found and followed by a pass written
against Reactor's shape, and that pass does not recognise this one. So a
ConfuserEx sample using reference proxies will come out with the proxies intact
and nothing in the report drawing attention to them.

## Compression, which is a different program

ConfuserEx can also pack the entire assembly: the real file is compressed, stored
as a resource inside a small stub, and loaded from memory at startup, so what you
have on disk is a program whose only job is to unpack another one. This is
ConfuserEx's compressor, and it is closer in spirit to Reactor's native packing
than to anything above.

**What you see:** a tiny assembly with one large high-entropy resource and almost
no code.

Neither of the samples this support was developed against is packed this way, and
the tool does not unpack it.

## Mutations, or why the numbers change per build

ConfuserEx does not ship one algorithm; it generates one per build. The
constants that go into the key derivation, the order of the arithmetic, and the
exact form of the compression are all randomised when the protector runs, from a
seed that changes with the build. The published source calls these mutations and
it is a deliberate feature: a tool that hard-codes what one sample's decryptor
does is correct for that sample and wrong for the next one from the same
protector.

This is the single most important fact about analysing it, and it is why the
approach in [how-recovery-works.md](how-recovery-works.md) is to interpret the
decryptor the sample carries rather than to reimplement it. What the file
contains is not an instance of a known algorithm. It is its own algorithm, and
the only complete description of it is the code sitting next to it.

## Versions and forks

ConfuserEx 1.0.0 is the last release under that name, and it is what this tool's
support is written against. Because the project is open source and was abandoned
by its author, what circulates in samples is frequently a fork — with layers
added, constants changed, or the whole protector renamed. Some of those forks
are close enough that recognition still works and the decryptor still interprets;
others are not.

The detection here is structural rather than a version string or a hash: what it
looks for is an encrypted, writable, executable section with method bodies inside
it, a module initializer that calls into it, and names built from characters that
do not print. A fork that keeps those properties is recognised whatever it calls
itself, and one that changes them is reported as unrecognised rather than
guessed at.

## Putting it together

A typical protected sample combines invisible names, the encrypted section, the
constants table, anti-debug, and control flow flattening. Opening it in a
decompiler shows a structurally complete and entirely empty program, with names
you cannot read or type and not one readable string.

The layers have to come off in order, and the order is less negotiable than
Reactor's: the constants table is inside the encrypted section, so nothing about
the literals can be read until the section has been decrypted, and the decryption
happens by running the sample's own decryptor from the module initializer. One
stage, and everything else depends on it.

That ordering is the subject of [how-recovery-works.md](how-recovery-works.md).
