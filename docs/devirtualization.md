# Virtualized methods

Some Reactor-protected samples contain methods that no decompiler will ever show
you, because the code you are looking for was never compiled into the file. This
explains what happened to those methods, what CILantro recovers from them,
and how much of the technique would still work against a protector that is not
Reactor.

You do not need to know C# or .NET internals. Where a term is unavoidable it is
explained the first time it appears.

## What you see first

You open a sample in dnSpyEx, find a method that ought to be interesting, and it
decompiles to this:

```csharp
public static void GNswBvhgmV(object obj, int num)
{
    object[] array = new object[2];
    array[0] = obj;
    array[1] = num;
    MX0Kl5l4ZOPAvLKpQes.o59H0OtQow(0, array, null);
}
```

Underneath the C#, .NET code is stored as an assembly language of its own, called
IL, and a decompiler will show you that instead if you ask. Here it is eighteen
instructions:

```
   ldc.i4      2
   newarr      System.Object
   stloc.0
   ldloc.0
   ldc.i4      0
   ldarg       0
   stelem.ref
   ldloc.0
   ldc.i4      1
   ldarg       1
   box         System.Int32
   stelem.ref
   ldc.i4      0
   ldloc.0
   ldnull
   call        System.Object[] XmkIHQlf9I8XWsyVH01.MX0Kl5l4ZOPAvLKpQes::o59H0OtQow(System.Int32, System.Object, System.Object)
   pop
   ret
```

Either way, that is the whole method, and all it does is this:

1. Make a box with two compartments (`newarr` — a new array of two slots).
2. Put the method's first argument in compartment 0, and its second in
   compartment 1.
3. Call one particular method, `o59H0OtQow`, handing it the box and the
   number **0**.
4. Throw away whatever comes back and return.

Every virtualized method in a sample looks like this. They differ only in how
many compartments the box has and in that one number, which is what tells the
interpreter which of them it is being asked to run. Nothing else in any of them
does any work.

The method you wanted is gone. What is left is a note saying *"run program
number 0, here are its arguments"*.

## What virtualization is

`o59H0OtQow` is an interpreter — a program that reads a list of numbered
instructions and carries them out one at a time. Reactor generated it, wrote it
into the sample, and translated the real method into a list of numbers that only
this interpreter understands. Those numbers live in the file as data, not as
code.

An analogy. A recipe says "heat the pan, add oil, add onions". Virtualization
replaces the recipe with a numbered list — `7, 3, 41, 12, 41, 19` — plus a
kitchen robot that knows 7 means heat, 3 means add, and so on. Someone who
finds the list learns nothing without the robot, and the robot's numbering is
made up fresh for each recipe book printed.

Two things follow from that, and they are the whole reason this protection is
hard.

**The original code does not exist anywhere.** Not encrypted, not compressed,
not hidden. The compiler's output for that method was consumed by the protector
and thrown away. There is nothing to find, so there is nothing to decrypt.

**The numbering is different in every build.** Across the samples examined
here, the same engine gives the same operation a different number in each
sample, with only a handful of numbers happening to line up between any two.
A table of meanings learned from one sample is worthless on the next one.

### Why this is not like the other protections

Most of what Reactor does is reversible because the original is still in there
somewhere. Encrypted method bodies (NecroBit) are the clearest case: the real
instructions are in the file, encrypted, and the sample has to decrypt them to
run, so working out what the decryption produces gives you the original bytes
back exactly. Same for encrypted strings and hidden references.

Virtualization is the one protection where there is no original to get back. The
best anyone can do is read the numbered list and work out what it means, which is
a *reading* rather than a recovery — and that distinction is why CILantro
writes what it learns into a report and never puts it back into the assembly.
More on that below.

## What the hidden program looks like

Here is the start of program 0 from the sample above, as CILantro writes it
out:

```
     0: op   43 pushes its operand 227
     1: op   45 stores where its operand indexes 3
     2: op  136 loads what its operand indexes 3
     3: op  135 branch by table    [2378, 1345, 2244, 1308, ... 355 in all]   -> 350
     4: op  136 loads what its operand indexes 3
     5: op   43 pushes its operand 361
     6: op   31 branch if beq      1914   -> 1914
```

Each line is one operation: its position in the program, the operation number,
what that number was found to mean, and the operand it carries. The whole
program is 2,935 operations long and uses 29 distinct operation numbers.

Now look at the pair at positions 2 and 3: load whatever is in the program's own
slot number 3, then jump to whichever of 355 places that number selects. That
pair recurs every few operations, and it is a **dispatcher**. The program is a
flat pile of small fragments, slot 3 holds "which fragment runs next", and every
fragment ends by setting slot 3 and going back to the table. It is the same
control-flow flattening Reactor applies to ordinary methods, applied here to the
hidden program. Following it by eye is hopeless, which is the point.

## How the tool reads it

Four steps, each of which produces something checkable.

### 1. Find the methods

CILantro does not look for a known interpreter, because the interpreter is
renamed in every sample. It looks for the **seam** — the join between compiled
code and the interpreter, which no virtualizer can avoid.

Something has to take the arguments the runtime passes and hand them to an
interpreter that knows nothing about this particular method's signature. Every
tool of this kind solves it the same way: pack the arguments into an array, pass
a number saying which program to run, call once, return. That shape is what
CILantro matches, and it holds whatever the interpreter is called and
however its instructions are encoded.

The match has to be exact. A stub that does any work of its own is not reported,
because then the interpreter is not the whole method and saying it was would
overstate what was found.

### 2. Get the program out — by running the protector's own decoder

The obvious approach is to find the bytes and parse them. CILantro does not
do that, for a practical reason: the encoding is the protector's business and
changes between builds, so a parser is a guess that fails silently when it is
wrong.

Instead the tool runs the engine's own decoder. Interpreters do not decode an
instruction each time they need one — that would be slow — so they unpack the
whole program into a list of objects first, and only then start executing it.
CILantro interprets the sample's decoder statically, without running the
sample, lets it build that list, and reads the list out of the interpretation's
memory before the first operation is carried out. The report says as much, naming
the engine's own list:

```
GNswBvhgmV: The engine decoded 2935 operation(s) of program 0, read back from
its own mMaFqnZqOXLOAe7TVuI list. It performed 6 of them before stopping,
because ... BinaryReader requires a modeled stream.
```

Read that second sentence again, because it is the point. Actually *running* this
program got six operations in before it reached something the tool will not model
and stopped — and it did not matter in the least, because all 2,935 operations
had already been decoded and taken. Getting the program does not require getting
through the program.

What comes out is not an approximation. It is the program as the protector's own
code understands it, which is the strongest position available: to have it wrong,
the protector's decoder would have to be wrong.

### 3. Work out what the numbers mean

This is the part that makes the listing worth reading. Three independent sources
of evidence, none of which requires understanding the interpreter's source.

**Ask the engine directly.** The interpreter has one piece of code per
operation. CILantro sets up a stack with values chosen for the purpose,
makes the engine carry out a single operation, and looks at what came back —
then repeats with different values, because one answer rarely settles anything.
Operation 57 turns 7 and 3 into 4, which exclusive-or does and subtraction also
does. It then turns 4 and 2 into 6, which subtraction does not, and 6 and 5 into
3. Only exclusive-or gives all three, so operation 57 is `xor`. The same trials
give `add`, `sub`, `shl`, `shr`, `neg`, `not`, `dup`, the conversions, array
length, and reading and writing array elements.

Some operations refuse to be performed this way. An operation that jumps has
nowhere to jump to when nothing is running; one that reads the program's own
tables faults when the program has not set them up. Those need the other two
sources.

**Watch a real run.** The engine is set going on the actual program and watched.
Where it starts matters more than you would think: entered cold it stumbles
within a handful of operations, while entered from the place that really calls it,
holding the arguments that caller really passes, it runs 3,506 operations of this
program before anything stops it. Along the way, wherever the operation it
carried out next was not the next one along, the previous one jumped — which
names the branches and finds their targets.

The same run measures the operations that would not be performed in isolation.
Reading the engine's stack either side of each one, and matching what appeared
against what the engine was holding elsewhere, is what identifies the loads and
stores: this operation put on the stack exactly what was sitting in the engine's
own slot 3, so it reads slot 3. No amount of poking at it from outside would have
found that.

**Listen to what the engine works out.** While it carries out an operation, the
interpreter computes things of its own, and CILantro records them, with the
housekeeping that every operation does subtracted. What is left is the
operation's own working. A `branch if` that computes `clt` is a branch made on
"less than". An operation that computes `Module::ResolveType` and
`Array::CreateInstance` is making an array of a type the program names.

Reading the interpreter's code directly is not a practical alternative, which is
worth knowing if you have tried. In this sample the handlers are one flattened
method of 7,386 instructions behind an 806-arm switch, and most of what it calls
goes through a lookup table that picks its target at run time. Watching it run
sidesteps all of that, because by then the interpreter has resolved it for you.

For the sample here, the trials performed 28 of the 29 operations in isolation
and named 16 of them outright; the watched run measured 23, named 14, read the
working of 12, and caught 7 of them jumping, to 345 destinations between them.
The counts overlap because the sources overlap, and where two of them speak about
the same operation they have so far agreed — which is itself evidence, since
nothing makes them agree except being right.

What comes out is a header like this one, at the top of every listing:

```
;   op   43  pushes its operand [leaves int32]
;   op   45  stores where its operand indexes (writes .xTCDXDDnnL[3], ...); computes List::get_Item x2
;   op   57  xor; computes xor [takes int32, leaves int32]
;   op   82  makes an array of the type it names; computes Array::CreateInstance, Module::op_Equality, Module::ResolveType [takes int32, leaves System.Byte[]]
;   op  108  calls the method it names; computes Type::op_Equality x13, ... [leaves int32]
;   op  135  branch by table (writes .oTCDihOrI8); computes conv.i8 x4, blt x2, bge, bne.un [takes int32]
;   op  166  returns the value it takes (writes .oTCDihOrI8=-3, .ssFDMi3XHg=what it took, ...)
```

Two operations in each sample have no fixed number of values they take, which is
how they give themselves away: being handed a method's arguments looks exactly
like that. Those two are the call and the object construction, and their operand
names the method — which makes them, in practice, the most informative lines in
the whole file.

Anything none of this settles is left unnamed. The header says how many values it
took and produced and what it insisted on being handed, and stops there.

### 4. Check the reading

A reading you cannot check is a guess with a confident tone, so the tool checks
this one against the program itself.

Because the dispatcher's jump carries a table of 355 destinations rather than
one, the flat program comes apart into fragments with known entry points. That
makes it possible to walk the depth of the stack from the first operation
through every branch: each operation takes some values and leaves some, so the
depth at every point is determined — and every place two different paths meet
has to agree about what the depth is there.

For this sample the walk reaches 2,921 of the 2,935 operations, and everywhere it
arrives twice it arrives at the same depth. Nothing disagrees. Since each
operation's contribution to the depth came from the readings, thousands of
independent agreements are strong evidence that the readings are right.

The walk earns its keep twice over. Where every operation around an unmeasured
one is known, the depths on either side leave that one only one possible effect,
which is how the last few get settled without anything having measured them. And
the 14 operations the walk never arrives at are worth knowing about too: since
the walk was never once at a loss, everything reachable was reached, so those 14
are code the protector emitted and never uses.

## What you get

For each virtualized method, `cilantro/suspicious.virtualized/` gets two
files.

**`NAME.lifted.il`** is the program written in ordinary assembly terms. Read
this one first:

```
   2624:  ldloc      10
   2625:  ldloc      0
   2626:  ldc.i4     1
   2627:  newobj     System.Void System.Security.Cryptography.CryptoStream::.ctor(System.IO.Stream, System.Security.Cryptography.ICryptoTransform, System.Security.Cryptography.CryptoStreamMode)
   2628:  dup
   2629:  ldloc      11
   2630:  ldc.i4     0
   2631:  ldloc      11
   2632:  ldlen
   2633:  conv.i4
   2634:  call       System.Void ...::h5bTpuvG9giGM6rEuXl(System.Object, System.Object, System.Int32, System.Int32)
   2635:  dup
   2636:  call       System.Void ...::AkiDCJvwSWy6yH7wA8K(System.Object)
   2637:  ldloc      10
   2638:  call       System.Object ...::px4E1VvpQREo8oO95Pa(System.Object)
   2639:  stsfld     System.Object ...::wBHpICowg0
```

You cannot read that as C#, and you can still tell what it is. `CryptoStream` is
the .NET class for pushing bytes through a cipher, and one is being built on line
2627.

The three calls with unreadable names are not an obstacle: they are ordinary
methods elsewhere in the sample, so you can go and look at them, and the listing
has just told you which three out of several hundred are worth the trouble. Each
turns out to be a one-line wrapper that takes its arguments as plain objects,
casts them, and makes one framework call — which is how the interpreter gets to
call anything at all with a single uniform shape:

| In the listing | What the method actually does |
| --- | --- |
| `h5bTpuvG9giGM6rEuXl(a, b, c, d)` | `a.Write(b, c, d)` — write bytes to a stream |
| `AkiDCJvwSWy6yH7wA8K(a)` | `a.FlushFinalBlock()` — finish the cipher |
| `px4E1VvpQREo8oO95Pa(a)` | `a.ToArray()` — take the bytes out of a memory stream |

Substitute those back and the fragment reads: build a cipher stream over a memory
stream, write a byte array through it from index 0 for its whole length, finish
the cipher, take the bytes out, and store them in a static field. That is a
decryptor — and you have just read it out of a method whose body does not exist
in the file.

This is the general shape of what the listing buys you. Every operand that
points into the assembly is resolved to a name, so even where the arithmetic
means nothing to you, the file tells you which methods, fields and types the
hidden code reaches for.

**`NAME.vmprogram.txt`** is the operation-by-operation listing with the header
above it. Go here when you want to know *how* a line in the lifted file was
arrived at.

A few markings are worth knowing:

| Marking | Means |
| --- | --- |
| `-> 1914` | The engine really was watched jumping there |
| `~> 174` | Not watched on this run, but every watched jump of that kind went where the operand said, so this one is read the same way |
| `2?` in the lifted file | A jump target read off the operation rather than observed. The stack walk follows it, so a wrong one would show up as a depth disagreement |
| `??` | An operation whose meaning was not established, written with what was counted about it rather than guessed at |

The header of each file states its own limits — how much was read, how many
targets are conjectural, how far the walk got, and what it never reached. Read
that before trusting the rest. [reading-the-output.md](reading-the-output.md#the-methods-are-decrypted-but-still-unreadable)
is the field guide to every line of it.

One detail that catches people out: the header describes more operations than the
program uses. Here it names 34 while the program uses 29. The extra five are
operations the engine supports and this program never reaches, asked about by
handing the engine an operation made to carry them. They are in the header
because the engine's other programs — the one that builds the string table, for
instance — do use them.

## Turning the reading back into code

Everything above is a report. The reading also goes back into the assembly, which
an ordinary run does for you:

```bash
cilantro suspicious.exe
```

The cleaned copy that lands beside your sample has the virtualized methods
holding real IL instead of a stub. You open the same file you were going to open
anyway, read the method as C#, follow its calls with the cross-reference view,
and search it like any other code — with the strings already decrypted and the
names already replaced, which a copy of the raw input could not give you.

The lowering assumes nothing about types, because the reading establishes none.
The engine holds every value as a boxed object and so does the emitted body:
every slot is an `object` local, every constant is boxed where it is made, and a
value is converted back only where the assembly itself says what it must be — the
parameter of a call, the type of a field, the element of an array. Arithmetic
goes through `System.Convert` rather than unboxing to a width nobody established.
The result is verbose but faithful. This is what the `CryptoStream` block from the
listing above looks like after the round trip, decompiled by ILSpy:

```csharp
case 237:
{
    CryptoStream cryptoStream = new CryptoStream((Stream)value3, (ICryptoTransform)value2, (CryptoStreamMode)obj112);
    object obj116 = Convert.ToInt32((object)((Array)obj114).Length);
    h5bTpuvG9giGM6rEuXl(cryptoStream, obj113, (int)obj112, (int)obj116);
    AkiDCJvwSWy6yH7wA8K(cryptoStream);
    wBHpICowg0 = px4E1VvpQREo8oO95Pa(obj109);
    FHYABrvl1RBkXRoAdtY(obj109);
    FHYABrvl1RBkXRoAdtY(cryptoStream);
    value = 242;
    ...
}
```

The flattened shape survives — that is the dispatcher, now a C# `switch` inside a
`while (true)` — and the boxing is everywhere. It is still a method you can read.

Two things it refuses rather than guesses at. An operation whose meaning was
never established stops the whole body, not just that instruction: a body that is
right in 2,934 places out of 2,935 runs the wrong code, and nothing in the file
tells a reader which place it was. And an operation the stack walk never arrives
at is written as a `throw`, because there is no stack for it to work on and any
lowering would be a story about one.

### Try and catch, which live outside the operations

The operations are not the whole program. Alongside them the engine parses a list
of *guarded regions*: a range of operations, a range that handles what they throw,
and the type of exception the handler catches. None of that appears in the
operation stream, so a reading of the operations alone would miss it entirely and
a body built from that reading would run the protected code with its safety net
removed — a `try` that is not a `try` behaves differently the moment anything
goes wrong, which in unpacking code is a path the sample takes on purpose.

Reading a region means telling its two ranges apart, and for a long time the tool
could not: it recovered the numbers a region covers without knowing which of them
were the guarded code and which the handler. It refused to build such a method,
because putting the handler in the wrong place runs the wrong code exactly when
something has already gone wrong. That is now settled by following the objects the
engine builds — the clause object knows its handler and the object that holds it
knows what it guards — so a region comes out as four numbers and a type:

```
operations 36-1611 guarded, handled at 1612-1615, kind 0, catching System.Object
```

which becomes a real `catch` clause in the emitted body. One further thing has to
be true for the runtime to accept it: a jump that leaves a guarded region must be
written as `leave` rather than `br`, and it may not carry values on the stack.
The emitter converts those jumps, and refuses the method where a conditional jump
or a jump table tries to cross the boundary, since neither has a `leave` form and
neither can be faked without changing what the code does. On the payload sample
whose engine uses handlers, all four of its regions come out this way, and with
them the whole method: 4,854 operations become 15,270 instructions over 44 slots,
where before the regions were readable the method could not be built at all.

**It is a reading, and it is marked where you will see it.** Everything else
CILantro writes into the cleaned assembly is the protector's own output,
provable byte for byte; a body built from a reading is the reading itself, and if
the reading is wrong the body is wrong in a way no reader can see. For a while
that argument kept these bodies out of the cleaned copy altogether, in a second
assembly built from the raw input — which meant reading the one method you cared
about in a file where nothing else had been recovered, while the file with
everything else recovered showed that method as an empty stub. Nobody was served
by that.

So the bodies go into the cleaned copy, and each method that gets one carries an
attribute saying where it came from:

```csharp
[RebuiltFromReading("CILantro built this body from its reading of the interpreter's program. It is not the original code and was not recovered from the file; see the run's report.")]
private static void GNswBvhgmV(object P_0, int P_1)
```

dnSpyEx and ILSpy both show that line directly above the method, which is where
the reader is looking. The attribute class is added to the assembly as an
internal type — one type and one constructor, declared to the verification gate
like any other change, so an addition nobody accounted for still fails the run.

A `--strict` run builds nothing unless you ask by name with `--devirtualize`, so
the cleaned copy of a strict run holds only what was proved. `--no-devirtualize`
does the same for a triage run, and is also the faster one: building the bodies
and running the check is most of the time an ordinary run spends.

What can be said is that the emitted bodies pass ECMA-335 verification. Running
Microsoft's `ilverify` over the samples here reports not one error in any method
that was built, which means the types line up, the stack balances on every path,
every branch lands somewhere legal, and the exception clauses nest the way the
runtime requires. The files are not error-free — Reactor's own code accounts for
between 14 and 77 complaints in each of them — but every cleaned copy reports
exactly the same ones with the bodies in as without, so nothing written in added
any.
That is a real check and it caught several mistakes while this was being written.
It is not a proof of equivalence, though: verifiable IL can still be the wrong IL.

### Running it, which is the check that counts

There is one more check, and it is the only one whose evidence does not come from
the same reading it is testing. These samples unpack an assembly at startup, and
in some of them the protected method is on the path that does it. So the tool
prepares a second copy of the input, puts the built bodies in place of the stubs,
and interprets the startup path again. Both runs begin from the same state in the
same module, and the only difference between them is the code the protected
method holds. If the second run arrives at the same hidden assembly — the same
megabyte of decrypted bytes, SHA-256 for SHA-256 — the bodies did the work the
engine did. Nothing produces a matching megabyte by accident, and none of the
several thousand operations behind it can be misread without changing it.

When that happens the summary says so on the line that reports the building:

```
    Built back      1 method(s) in the cleaned copy, marked [RebuiltFromReading] (they unpacked the same payload as the original)
                      GNswBvhgmV: 2935 operation(s) became 8997 instruction(s) over 13 slot(s), every value carried as an object. 14 of them are places nothing reaches and throw instead.
                      Checked by running it: with the built bodies in place of the stubs, the module unpacks SHA-256 1db4e9c40d83bb79 and SHA-256 e4e746f968a3ec89 — byte for byte what it unpacks as it shipped — and a built body was entered 1 time(s) doing it.
```

The run that produces that verdict is not the cleaned copy being executed. It is
a second in-memory copy of the input, prepared the same way, interpreted twice:
once as it shipped and once with the built bodies in place. Nothing is executed
at any point, here or anywhere else in the tool.

Two ways this could pass while testing nothing, and both are ruled out. If the
run as it shipped unpacks nothing, there is no reference to compare against. If
the second run never enters a built body, then the rest of the module unpacked
the payload on its own and the bodies were never exercised. Either way the answer
is *the check was not made*, which the tool prints in those words — it is a
different thing from the check passing, and the two are never allowed to look
alike. Of the four samples here, two are checked this way and pass; one has a
virtualized method that is not on the unpacking path, and one is itself an
already-unpacked payload with no startup path to run.

## What this does not do

**It is not a decompiler.** You get assembly-level operations, not C#, and where
the bodies are written back you get C# in name only: local variables are numbered
slots, there are no names, and the control flow is still the flattened dispatcher
shape the protector emitted.

**No public tool does better on this.** NETReactorSlayer, the closest comparison,
detects virtualization by recognizing a known runtime and reports it as a flag; it
does not recover the program or say anything about what the operations mean. If
you find a tool that lifts Reactor's virtualized methods back to real IL, that is
worth knowing about.

## Where the reading pays off anyway

Two things fall out of it that matter more than the listing.

**Payloads still come out.** When a sample's unpacker is virtualized, the usual
approach of following the unpacker's code hits a wall. But the *interpreter* is
ordinary compiled code, so CILantro can simply run it — statically, the same
way it runs everything else — and let it unpack the payload itself. It costs
about a minute instead of a few seconds, and you get the hidden file. Running the
protector's machine is easier than undoing it.

**Strings come out.** In several of the samples here, including the one above,
the table of decrypted strings is built by a virtual program rather than by
ordinary code. Reading that table needs the meanings of that build's operations,
which is exactly what the trials and the watched run establish — so string
recovery evaluates the virtual program itself, using the learned numbering, and
gets all 23 string sites out of a sample that would otherwise have no readable
text at all. Leave the virtualization step out and that same sample reports no
strings.

That second one is the clearest argument for doing this work even without
lifting. The readings are not just a report for a human; they are precise enough
to run the program with.

## What is Reactor-specific, and what transfers

Worth separating, if you are wondering whether any of this helps against a
virtualizer that is not Reactor's — another product, something written in-house,
or whatever turns up next year.

### Transfers to almost any virtualizer

**The seam.** Every virtualizer has to bridge compiled code and its interpreter,
and the argument-packing shape is the natural way to do it. Detecting a
virtualized method by that shape — rather than by recognizing a known engine —
survives renaming, re-encoding, and switching protector entirely.

**Running the engine's decoder instead of parsing bytes.** This is the single
most transferable idea here. Whatever the encoding, the sample must contain code
that decodes it, and that code is correct by definition. Interpreting it and
reading the result is easier than reverse-engineering a format, and it does not
break when the format changes.

**Learning meanings by experiment.** Feeding chosen values into one operation and
watching what comes back does not care how the interpreter is written. Nor does
watching a real run for jumps and slot accesses, nor recording what the engine
computes on an operation's behalf. All three treat the engine as a black box that
can be poked, which is the right posture when the engine is deliberately
unreadable.

**Checking with a stack-depth walk.** Any stack-based virtual machine — which is
most of them, because the .NET and JVM instruction sets are stack-based and
virtualizers tend to mirror the thing they replace — admits this check. It costs
nothing, it needs no knowledge of the protector, and it catches a wrong reading
that would otherwise look plausible.

**Expecting per-build numbering.** Build a tool that learns the numbering rather
than one that knows it, and re-numbering stops being an event.

### Specific to Reactor

**The exact seam pattern.** Arguments boxed into an `object[]`, program id as a
constant, one call, discard the result. Another protector might pass arguments in
fields, or through a closure, or push them individually. The idea transfers; this
particular matcher does not.

**Decode-everything-up-front.** CILantro reads the program list out of
memory before execution begins, which works because this engine builds the whole
list first. An engine that decodes each instruction as it reaches it — or
decrypts the next one using the last one as a key, which is a known trick —
would need the program collected during the run instead.

**The dispatcher-with-jump-table shape.** The 355-arm table is what lets the flat
program be cut into fragments for the stack walk. A virtual program with ordinary
branching would need the fragments found another way.

**The instruction set itself.** Around thirty stack-based operations, one operand
each, calls that take their arity from the method they name. A register-based
virtual machine, or one with instructions that do several things at once, would
need different probes — the *method* of probing would be unchanged, but what
counts as a result would not be.

**Where the exception handling is kept.** In this engine the guarded regions are
a separate structure the interpreter walks, not instructions in the program, and
they are recovered by following the objects the engine builds rather than by
decoding anything. Most of the programs here use no handlers at all; the payload
sample on the other engine uses four. A virtualizer that encoded regions in the
instruction stream, or that implemented `try` by some means of its own, would
need this part rewritten — though the shape of the problem, *the reading is not
only in the operations*, is one to expect anywhere.

### What would need real work

An engine that decodes lazily, or one that decrypts each instruction from the
state of the last, breaks the read-the-list-first approach. A virtualizer that
mixes real compiled code into the stub breaks the seam matcher, on purpose,
because then there is no clean join to find. And an engine whose operations are
deliberately non-deterministic — different behaviour on the second execution of
the same operation — would break the trials, since those rely on an operation
meaning one thing.

None of those is exotic. They are the obvious next moves for a protector author
who reads this document, which is worth saying plainly: this is a reading of
today's builds, not a general solution to virtualization.

## Try it yourself

```bash
cilantro suspicious.exe
```

If the sample has virtualized methods, the summary says so:

```
  PROTECTION   .NET Reactor

    - Some methods are bytecode for a custom interpreter, not code a decompiler can show

  WROTE

    Hidden code     2 listing(s) in cilantro/suspicious.virtualized
    Built back      1 method(s) in the cleaned copy, marked [RebuiltFromReading] (they unpacked the same payload as the original)
```

The listing count is of files, and there are two per virtualized method, so that
is one method: its lifted IL and the listing behind it.

The parenthesis is the verdict of the run described above, and it is the part to
read. `a reading, unchecked` means the comparison could not be made and the lines
under it say why; `IT DID NOT MATCH THE ORIGINAL` means the bodies were built and
did something else, which is a reason not to trust them.

Reading a virtual program is the slowest thing the tool does — ten seconds on top
of the rest for a sample the size of the one above, and longer for a larger one.
Building the bodies back is cheap beside reading them. The check is the expensive
part, because it runs the whole pipeline again on a second copy, and it is only
paid on a module that unpacks something for the check to watch; on one that
unpacks nothing there is nothing to compare, and the run says so instead of
paying. `--no-devirtualize` keeps the listings and skips the building. If you
are working through a directory of samples and do not need either, you can leave
the whole thing out:

```bash
cilantro suspicious.exe --declarations skip-vm.json
```

where `skip-vm.json` is:

```json
{ "passes": { "skip": ["virtualization-disassembly"] } }
```

Do that knowing what it costs. On a sample whose string table is built by a
virtual program, this is also the pass that learns how to read it, so skipping it
takes the strings with it: the same sample that reports `Strings decrypted 23 of
23` with the pass reports no strings at all without it. The summary always says
which passes were left out, so you will not mistake one result for the other.

## Further reading

- **[How .NET Reactor works](how-net-reactor-works.md)** — the other protections,
  and how virtualization sits among them.
- **[How CILantro undoes it](how-recovery-works.md)** — the pipeline this is
  one step of, and the bounded machine that makes running the engine safe.
- **[Reading the output](reading-the-output.md#the-methods-are-decrypted-but-still-unreadable)**
  — the field guide to every line of the two files.
- **[Compatibility and provenance](compatibility.md#virtualized-methods)** — the
  precise figures for each sample, the per-build numbering tables, and what the
  gates require.
