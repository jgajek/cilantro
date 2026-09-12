# Reading the output

What CILantro writes, what the numbers mean, and what to do when something
does not work.

## The files

Running `cilantro suspicious.exe` leaves two things next to the sample.

**`suspicious.cleaned.exe`** — the readable copy. This is what you open in
dnSpyEx or ILSpy. A cleaned library keeps the `.dll` extension.

**`cilantro/`** — a folder containing:

| File | What it is |
| --- | --- |
| `suspicious.analysis.json` | Everything the tool observed and did |
| `suspicious.changes.json` | Every individual edit, one entry per change |
| `suspicious.blockers.json` | Everything that stopped the run short, and what to declare to get past it |
| `suspicious.payloads/` | Files that were hidden inside the sample |
| `suspicious.virtualized/` | Per method turned into interpreter bytecode: the program read as IL, and the listing it was read from |
| `suspicious.renames.json` | Old-to-new name map. Not written by a `--strict` run unless you add `--rename` |
| `suspicious.config.json` | Constants recovered from a protector's table that could not all go back into the code — byte arrays, mostly. Written only where the sample had some |
| `suspicious.status.json` | Which pass is running and how far along, updated while the run goes. Written only with `--status`, for watching a long run from elsewhere |

The folder is not named after the sample, so a directory of samples all report
into one folder without colliding. If a file named `cilantro` is already
there — which is what happens when the published Linux binary sits beside the
sample — the folder is named `cilantro.out` instead, because a directory cannot
be created on top of a file.

If something other than a person is reading this, `--json` prints one object
naming all of the above, along with what stopped the run and what to declare
about it, so that none of it has to be found by convention first. See
[agents.md](agents.md).

## The summary

The first thing the summary says is whether the run worked:

```
  RESULT   Recovered
```

`Recovered` means the tool finished and wrote a cleaned copy. `Failed` means it
did not, and the rest of the page says why. `Not protected` means the file is
not something this tool undoes. That line is the one to read first.

A default run then lists what came back and where it was written, and stops.
How the reading was licensed — assumed host facts, calls stepped over, whether
a rebuilt body was cross-checked — is printed only under `--strict` or
`--verbose`. Those are the modes that asked for the assumptions to be named.
Printing them on an ordinary successful run is what made a finished recovery
look like a failure.

Files extracted from the input are named individually under `WROTE`:

```
  WROTE

    Cleaned copy    cilantro/suspicious.cleaned.exe
    Extracted files 2 in cilantro/suspicious.payloads
      Zebekeadu.dll (90.5 KB)
        Assembly    Zebekeadu
        SHA-256     417032e561fe410a246fea4f580b7ae8de4a8cc5098a508931a78322916199dd
        From        KyVgypcyOSoGANSpXe::uMqwgnxr1
```

Those lines report only what extraction established: the written filename,
managed assembly name, size, content hash, and source resource. They do not
assign a malware family or claim whether a file is a loader, support library,
or final payload. Those conclusions require analysis outside this tool.

```
  RECOVERED

    Method bodies decrypted        253 of 253
    Strings decrypted              163 of 163
    Proxy calls restored           412
    Hidden calls resolved          17
    Methods with control flow simplified   266
    Constant branches resolved             216
    Flattened methods restored             350 of 351 candidates
    Junk instructions removed      1,942
    Encrypted resources restored   1
    Protector types deleted        12
```

**Method bodies decrypted — `n` of `m`.** How many encrypted method bodies were
recovered, out of how many were found. This is NecroBit and the like: the
original IL was in the file, encrypted, and came back. It should read `n of n`;
if it does not, no cleaned copy is written, because a partially decrypted
assembly is misleading rather than useful. The line is omitted when the sample
did not encrypt method bodies at all.

**Methods devirtualized — `n` of `m`.** How many virtualized methods were
converted into readable .NET code in the cleaned copy, out of how many the
protector turned into instructions for its private virtual machine. These were
never encrypted IL; they were a custom instruction set, and the bodies in the
cleaned copy are the tool's reconstruction of that.

**Interpreter programs found elsewhere — `n`, listed but not rebuilt.** A
protector is free to run one of its programs from the middle of a method that
also does ordinary work, and Reactor does. Such a program is not a method that
failed to be devirtualized — there is no body to put anything into, because the
method is not the program — so it is counted here instead of raising the
denominator on the line above. It still gets a listing under `VM listings`, so
`VM listings` counts these as well as the rebuilt ones.

This line is worth reading closely on a Reactor file, because the program it
usually names is the one a type initializer runs to assign the state that every
opaque predicate in the module tests. That is also why the flattening survives:
no instruction in the file writes those fields, so searching for what writes
them finds nothing, and yet they are not the zeroes that absence would suggest.
The interpreter assigns them through code it builds while it runs, which is
nowhere in the file to be found. Until that program is given meaning, the
predicates stay undecided and the dispatchers stay standing.

**Strings decrypted — `n` of `m`.** Recovered string sites out of sites found.
Also all-or-nothing: either every site is proven and replaced, or none are, so
you never have to wonder whether a particular string can be trusted.

**String calls decoded.** Some samples keep their text behind a decoder of their
own rather than behind Reactor's, called with a number where a string belongs.
This counts the calls that were run and replaced with the string they return.
There is no "of `m`" here because there is no set of sites to have covered: a
decoder is proven constant and folded, or it is left alone and named in the
report.

**Proxy calls restored.** Sites that went through Reactor's delegate lookup
table, rewritten to call the real method. Only printed when the sample used
that protection. It is a different thing from the next line: these were
ordinary method calls hidden behind a table, not metadata handles hidden
behind `Module.Resolve*`.

**Hidden calls resolved.** Metadata references that were being looked up at run
time to hide a dependency, turned back into direct references. Raises the number
of working cross-references in your decompiler.

**Hidden true/false values resolved.** Reactor can encrypt booleans the way it
encrypts strings. Only appears when the sample used it.

**Methods with control flow simplified.** Methods in which the run proved and
removed at least one fake branch or unreachable instruction. This is broader
than full unflattening: a method can become substantially clearer without
having a dispatcher.

**Constant branches resolved.** Branches whose outcome was proven in advance
and replaced with the destination they always take.

**Flattened methods restored — `n` of `m` candidates.** Dispatcher-like methods
whose indirect state-machine edges were safely replaced with direct control
flow. `m` says candidates rather than methods found because some shapes are
ambiguous: they resemble flattening but cannot be proved to be flattened.
Those are preserved unchanged rather than guessed at.

A method counts here if any of its jumps into a dispatcher were made direct, not
only if all of them were, because the two are proved separately. A whole method
is provable when every way into its dispatcher is a block assigning the state a
constant and nothing else reads it; a single jump is provable on much less,
since a block that assigns the state and then jumps arrives with the state
already known regardless of what the other jumps do. Most real flattened methods
have a few jumps that fail the check — a state computed from an argument, a
handover across an exception boundary — and the rest that pass are still worth
taking. The dispatcher stays in place for whatever still needs it, and the
methods that end up with jumps left over are named under `--verbose`, with the
reason each one was left.

The count can exceed what one pass over the module could find, because the late
run repeats until a round comes back empty. Making an edge direct is itself one
of the things that makes the next dispatcher recognizable: the shape being
looked for is a block holding nothing but the state read and the switch, and
every redirect erases the arithmetic behind an assignment while the fold behind
it deletes what nothing reaches any more. Both leave blocks shorter, so a block
that stood one instruction too long to match now matches. On three real
libraries the rounds after the first found a third of all the edges between
them, and what they reached were mostly the entry edges of otherwise-clean
methods — the one jump whose survival keeps a constructor reading as a switch
over a state variable instead of as four assignments and two conditions.

**Junk instructions removed.** Instructions proven unreachable once the fake
conditions were folded away, together with values worked out and then thrown
away. Large numbers are normal.

The second kind has two sources. Reactor computes numbers nothing uses, so that
the arithmetic has to be read before it can be dismissed. And making a
dispatcher's edge direct leaves the store of its state behind, because the
switch the edge no longer goes through still reads it; once every edge is direct
and the switch is gone, that store has no reader left. Neither is dismissable at
a glance, which is why they are removed rather than counted: a local nobody
reads prints as a named variable holding a number, indistinguishable from state
that matters, and a dropped computation prints as a discarded expression. On the
three corpus libraries there were 144, 271 and 297 of them against unprotected
originals carrying two apiece, and removing them took one library's `goto` count
to nil and turned constructors whose whole content was a switch on zero back
into the empty constructors they are.

Only the part that cannot matter for another reason is removed: constants, reads
of locals and arguments, and the arithmetic over them. A call, a field read — a
static one can run a type initializer — or a load through a pointer stops the
walk, and then nothing is removed at all.

**Encrypted resources restored.** The application's own resources, decrypted and
put back where the program expects them.

**Protector types deleted.** Reactor's own types, removed after recovery proved
they had nothing left to do. See "Why is Reactor's code still there?" below.

**Obfuscated names replaced.** Reactor's generated names given readable ones.
Counts types, methods, fields and namespaces together. A `--strict` run leaves
them all alone unless you add `--rename`. What a name is replaced with depends on
what could be established about the thing it names, and the three cases read
differently on purpose:

- A method whose body does one knowable thing is named after it.
  `SymmetricAlgorithm_CreateDecryptor` is a method that casts its argument and
  calls exactly that; `AlwaysTrue` is one of Reactor's opaque predicates, and the
  name is the whole of what it does. These are worth looking for, because after
  proxy restoration they are what the recovered call sites point at — a body that
  reads as a hundred calls to `generatedMethod_0101` is a hundred calls to
  `CreateDecryptor`.
- A type is named for what kind of thing it is: `GeneratedDelegate_0075`,
  `GeneratedStruct_0063`, `GeneratedAttribute_0004`. A field is named for what it
  holds where that says more than a number, as in `int32Field_0047`.
- A method rebuilt from the protector's virtual machine is named
  `RebuiltFromVirtualMachine`, followed by up to two areas of the framework it
  provably reaches: `RebuiltFromVirtualMachineCryptographyReflection`. These are
  the longest and least readable methods in a cleaned copy and the ones a reader
  most often opened the file for, so a number is the worst thing to call them.
  The name claims only the two things that were established — that the body is a
  reconstruction, and which framework it touches — and deliberately stops short
  of naming a purpose, because a guess at one in the identifier would be read
  everywhere the method is called as though it had been proved. What it actually
  calls is listed under `DEVIRTUALIZED METHODS`.
- Anything else keeps a numbered placeholder. A method that does several things
  gets `generatedMethod_0075` rather than a name summarising one of them, because
  a name describing part of a method reads as a description of all of it.

Namespaces are renamed too, to `GeneratedNamespace_0000` and so on. Three kinds
are left exactly as they are: one holding anything externally visible, because
its name is a contract with whatever references the assembly; one an embedded
resource is named after, because resource lookup goes by the declaring type's
full name; and any name shared with either of those, so that a namespace and the
namespaces nested inside it never disagree about their common prefix. A cleaned
copy can therefore still show one or two original-looking namespaces, and those
are the ones that could not be moved safely.

Every replacement is recorded old-to-new in `NAME.renames.json`, namespaces
under an `N:` prefix alongside `T:`, `M:` and `F:`, so a name in the cleaned copy
can always be traced back to the one the protected file carried.

## The DEVIRTUALIZED METHODS section

Printed when the run devirtualized methods: converted code virtualization's
private virtual-machine instructions into readable .NET code. It is the way
into the hardest code in the cleaned copy:

```
  DEVIRTUALIZED METHODS

    CILantro converted methods protected by code virtualization into readable
    .NET code. These are reconstructions from the virtual machine's instructions,
    not the original method bodies.

    GeneratedNamespace_0003.GeneratedType_0005::generatedMethod_0075
      uses      Activator.CreateInstance, Array.Reverse, Assembly.GetName,
                AssemblyName.GetPublicKeyToken, BinaryReader.ReadBytes,
                CryptoStream.FlushFinalBlock, SymmetricAlgorithm.CreateDecryptor,
                new AesCryptoServiceProvider, new RijndaelManaged
      changes   generatedField_0030, int32Field_0047
      status    nothing in the cleaned copy calls this: recovery replaced the
                code that used to, so its caller went with it
```

**uses** is the list to read first, and often the only thing you need. A
protector renames what it generates but cannot rename the framework, so the calls
leaving a lifted body still say `SymmetricAlgorithm.CreateDecryptor` and
`AssemblyName.GetPublicKeyToken` in full. Those names are fixed points, and the
list above says what the method is for — an assembly-identity-keyed decryptor
filling a table — before you have read a line of it. The list follows the small
forwarders Reactor leaves between the code and the framework, so what is named is
the framework member at the end of the chain rather than the generated method in
front of it.

**changes** is where the method leaves its work, which is what to search for next
if you want to know who consumes it.

**status** appears when nothing in the cleaned copy calls the method. That is the
usual outcome and it is a result rather than a fault: recovery replaces the code
that needed the method, so the caller becomes dead and cleanup removes it. The
body is still there and still correct; nothing reaches it any more.

The same information is in the report under `RebuiltMethods`, uncapped, and on
the method itself in the `[RebuiltFromReading]` attribute, which dnSpyEx and
ILSpy print directly above the body. All of it is written after renaming, so
every name in it is the name you will find in the cleaned copy.

## The ASSUMED section

Shown only with `--strict` or `--verbose`. A default run does the same work and
does not lecture about it.

```
  ASSUMED   about the machine, from the "windows-10-workstation" profile

    env:UserName                            "mhoffman"  (assumed)
    native:user32!SetProcessDPIAware        1  (assumed)
    wmi:Win32_DiskDrive.SerialNumber        "WD-WCC4E5PJ0KZT"  (you stated this)
    registry:HKEY_CURRENT_USER\Software\X   not stated, so the code that asked was not read
```

Protected code asks questions about the computer it is running on — the time, the
machine name, a disk serial number — and the tool cannot read the answers off the
machine it is running on, which is not the one the sample expects. So this is where
the answers came from. Facts nobody asked about are not listed.

Each answer says whether **you stated** it or the tool **assumed** it. An assumed
answer is the tool's portrait of a plausible workstation, is nobody's assertion, and
would change the reading if the real machine differed — so a recovered value that
depends on one is worth checking. Under `--strict` there are no assumed answers:
anything nobody stated appears as **not stated** instead, and the code that asked was
not read.

A value shown here was used like any other: it can decide a branch and it can end
up in the cleaned copy. If that matters for what you are doing, the full report
carries the profile's name and a hash of its contents next to the input's hash, so
you can tell which answers a result depended on.

A line reading **not stated** is the useful one. It names a fact that stopped the
interpretation, spelled exactly as a profile would spell it. Write it into a JSON
file and pass `--host-profile` to get further:

```json
{ "facts": { "wmi:Win32_PhysicalMemory.SerialNumber": "8FA2C31B" } }
```

`profiles/windows-10-workstation.json` is a filled-in example. Facts a profile
does not mention keep their built-in answers, so a profile only has to state what
it knows.

A fact can also be bytes, which is how a value that is not text gets stated:

```json
{ "facts": { "registry:HKEY_CURRENT_USER\\Software\\X!blob": { "base64": "H4sIAAAA..." } } }
```

That is the line to write when a **not stated** entry names a registry value
holding a blob. A stager that stores its next stage there is unpacked from the
bytes you paste in, so the payload comes out of the run rather than out of a
manual decode.

A further ASSUMED section lists what the tool could not read and carried on past:

```
  ASSUMED   not to matter: what the tool could not read, carried on past

    System.Void System.Threading.Thread::Start(System.Object)  (x6)
    user32.dll!GetWindowText  (x2)
    isinst:unrecorded->System.Reflection.ConstructorInfo
```

Most are calls. An `isinst:` entry is a type test — the program asked whether one of
its objects is a given type, and the metadata in hand could not settle it, so the
answer given was no. That matters more than it looks: the program takes the no as a
fact about its own object, so a wrong one sends the run down a path the program never
took, and it fails somewhere with no visible connection to the test. Tests the
hierarchy does answer are the program's own logic and are not listed.

Each of those returned nothing the run could know, and the frame carried on without
it. Most are on the way to the part worth reading rather than in it, which is why the
default steps over them; the risk is the other case, where the call did something the
reading needed. If a result looks wrong, this is the list to read first, and
`--strict` stops at these instead.

One more ASSUMED section appears when a run was allowed to be told what a call the
tool cannot read does. Those are assertions rather than readings, so they are listed
whether or not anything else went wrong. An **UNUSED** section lists declarations
nothing asked about, which is what a mistyped key looks like.

## The BLOCKED section

Shown on a failed run, and on a successful one only with `--strict` or
`--verbose`. If the cleaned copy was written, a leftover stop did not prevent
recovery.

```
  BLOCKED   what stopped the run, and what would get past it

    UnstatedFact  wmi:Win32_DiskDrive.SerialNumber  (x4)
      in System.String W8ysC31VAB3Rg7yojQi.bHOEmc16m1KHmOsR4gd::TJ51Wrvldq(...) IL_0030
      declare: "facts": { "wmi:Win32_DiskDrive.SerialNumber": <value> }

    All of them, in full: cilantro/sample.blockers.json
```

Each entry is one thing that stopped the interpretation, what it is about, where
it happened, how often it came up, and the exact line to write down to get past
it. An entry reading **no declaration fixes this** is one that needs a change to
the tool rather than a line in a file, and saying so is the point: it tells you
to stop looking for something to declare. A **Threw** entry is different. It is
the program's own exception reaching the top of a method the tool was reading —
the sample deciding, not a gap in the model — and the line under it says that.

`cilantro/NAME.blockers.json` carries all of them, with the tool version and
the hashes of the input and the declarations, and is the file to read when a
program rather than a person is deciding whether to try again. `Blockers` there
means what stopped the run; `ContinuedPast` is what it carried on past, and
`Strict` says which mode produced the file. Each entry carries its remedy twice:
`Declare` is the line printed above, and `Remedy` is the same statement in parts
a program can apply. The kinds and the file's shape are in
[declarations.md](declarations.md), and the published schema is in
[schema/](../schema/).

## The NOTES section

A failed stage is always named. Incomplete stages that declined because the
sample does not use that feature appear only with `--strict` or `--verbose`.

Declining is normal and usually means the sample does not use that feature — a
sample with no encrypted booleans will report the boolean stage as incomplete.
The notes are worth reading rather than worrying about.

If no cleaned copy was written, the notes say why. That is the tool refusing to
hand over a result it cannot stand behind.

## The full report

`analysis.json` has the following top-level keys.

| Key | Contents |
| --- | --- |
| `InputSha256`, `InputLength`, `ModuleName` | Identifies exactly what was analysed |
| `Protector` | Which protector the run settled on, by the name a program uses — `reactor`, `confuserex`, or `none`. Said outright because the capability list alone does not tell two protectors apart. `reactor` names the .NET Reactor family without asserting a version, since 6 and 7 are not separable by structure alone |
| `TypeCount`, `MethodCount`, `ConcreteMethodCount` | Size of the cleaned module |
| `Resources` | Every embedded resource with size, SHA-256, entropy, and inferred role |
| `Payloads` | Hidden assemblies found, with hashes at every decoding stage and the file each was written to |
| `Evidence` | Every observation, tagged by category, with a confidence |
| `Passes` | Each stage with status, change count, and diagnostics |
| `Recovery` | The counters shown in the summary |
| `VerificationPassed`, `VerificationDiagnostics` | Whether the output was accepted, and why not |
| `HostProfile` | Which profile answered questions about the machine, its hash, and every fact consulted, each marked stated or assumed |
| `Blockers` | Everything that stopped the interpretation, with the declaration that would get past each |
| `ContinuedPast` | What the tool could not read and carried on past — calls it stepped over, and type tests it could not settle — with how often each came up |
| `Strict` | Whether the run refused rather than assuming; everything else here is conditional on it |
| `Declarations` | What the run was told, its hash, and which declared calls were used and which were not |

Three categories in `Evidence` are worth knowing. `capability` entries are the
protections that were detected, and they are what the summary turns into English;
which protector they belong to is `Protector`, since both have a capability called
anti-tamper and they mean different mechanisms by it. `metadata-anomaly` entries
are the deliberate metadata damage a protector introduces to break tools — useful
for detection rules. `trusted-library` entries name each
assembly supplied with `--library`, with the version and SHA-256 of the exact file
whose code was read.

`Resources` includes an entropy figure per resource. Values near 8.0 mean
encrypted or compressed; that is how the encrypted bundles stand out.

## The changes file

`changes.json` is a flat list, one entry per edit:

```json
{
  "Pass": "method-body-recovery",
  "Kind": "restore-method-body",
  "Location": "0x06000004 System.String nlRE084v66tVsDlG7I.RuY163fyVIPrQvH69g::JbTNngvA7(System.String)",
  "Description": "Grafted deterministic statically restored CIL by unchanged MethodDef token."
}
```

There will be thousands. It exists so that any difference between the input and
the cleaned copy can be traced to the stage that caused it — useful when you are
suspicious of a result, and necessary if you are reporting a bug.

## Common situations

### No cleaned copy was written

The tool writes one only when it can show the result still matches the original
in every respect it promised to preserve. Read the NOTES section for which stage
was incomplete. The most common causes are an unmodelled encryption scheme, code
virtualization in the sample, or a protector version whose loader reaches outside
what the interpreter models.

The analysis report is still complete and still useful. You will often have the
strings, the payloads, and the resource inventory even when no assembly could be
emitted.

### "This file is not protected by a recognised protector"

Both detectors were asked and neither claimed it. Either it is under a protector
this tool does not handle, or it is a fork or configuration of one of the two
whose structure is not recognised — the ConfuserEx forks are the common case.
.NET Reactor 7.5 is *not* one of these: it shares the Reactor 6 JIT-hook
structure and is reported as `reactor`. Eazfuscator and Babel are the usual other
answers, and [de4dot](https://github.com/de4dot/de4dot) handles those.

The report names which protector the run settled on, or `none`, so a sample you
believe is one of the two and that comes back `none` is worth reporting, with the
sample.

### "is not a .NET assembly"

The file is not managed code, and it is not a Reactor native bootstrap either —
that case is unpacked rather than refused, and reports itself as one. So this
message means what it says. See the native packing section in
[how-net-reactor-works.md](how-net-reactor-works.md) for the two shapes and
which of them this tool opens.

### ".NET Reactor native bootstrap ... but it could not be opened"

The file *is* a bootstrap — native code with the managed assembly encrypted
inside it — and the assembly could not be recovered. The rest of the message
says which step failed. A key that could not be found means the decrypt routine
did not match, which is the expected outcome for a stub built by a Reactor
version this has not seen; a length or inflate failure after a key *was* found
usually means the resource has been modified since the stub was built. Either
way nothing is written, because a half-decrypted assembly is indistinguishable
from a whole one until something tries to read it.

### The cleaned copy still has meaningless names

Partly expected. Reactor deletes the original names rather than encrypting them,
so they are not in the file and cannot be recovered by any tool. Nothing will
tell you what the author called a class.

What a normal run substitutes is described under "Obfuscated names replaced"
above. Some of it does carry meaning — a method named
`SymmetricAlgorithm_CreateDecryptor` was read off its body, not guessed — and
the rest is numbered placeholders that make navigation possible without claiming
anything. A `--strict` run substitutes neither unless you add `--rename`.

If the namespaces still look untouched, check whether they are the ones renaming
refuses to move: a namespace holding an externally visible type, or one an
embedded resource is named after. Those two are left alone deliberately, and
`NAME.renames.json` shows which namespaces were renamed and which were not.

Where names are absent, behaviour is not. The framework calls a method makes were
never obfuscated, so reading the calls leaving a method tells you what it does
even when nothing it is called tells you anything — which is the technique the
`DEVIRTUALIZED METHODS` section applies automatically to the worst case.

### Why is Reactor's code still there?

Some of it usually is, and this is deliberate. The tool deletes a declaration
only when recovery can account for why it has no use left, rather than deleting
whatever looks like it belongs to the protector. Leftovers are counted in the
`runtime-cleanup` diagnostics under `--verbose`.

Erring the other way costs more than a leftover would. Wearing an attribute is a
use of its type that no signature and no instruction mentions, and the scan
deciding what to delete has to be told about it separately for each kind of
declaration that can wear one. It was told about types and methods but not about
fields, so an attribute type worn by one field and nothing else was judged
unreachable and removed — an attribute belonging to the original program, not to
the protector. What the reader lost was not that declaration but every method of
the type holding the field: a decompiler resolving attributes to print a field
gives up on the whole file when one names a constructor that is gone. On the
reactor7 probe that file was the one holding the devirtualized body.

If you would rather keep all of it — for building detection signatures, say —
use `--keep-runtime`.

One diagnostic there is worth recognising, because it explains a large amount of
surviving code at once:

> Every virtual method whose shape a call here matches was kept, because this
> module can get behind the question of which types can have instances: …

A virtual method can only be called on an instance of the type declaring it, so
one whose type nothing ever constructs is ordinarily dropped — which is what
lets a whole interpreter go, its types being constructed only by itself. Where
the module can make an instance without naming its type, through `Activator` or
reflection or code it builds as it runs, there is no type such an instance could
not be of, and the question has no answer worth giving; the diagnostic names the
call that made it unanswerable. Expect more of the protector's code to remain in
that case, and see [devirtualization.md](devirtualization.md) for what is and is
not treated as getting behind the question.

### The methods are decrypted but still unreadable

Check whether the summary reported code virtualization. If it did, those methods
are bytecode for a custom interpreter and no tool will decompile them. What
follows is the field guide to the files that get written;
[devirtualization.md](devirtualization.md) is the longer explanation of what the
protection is and how the files are arrived at.

Look in `suspicious.virtualized/` — there is a listing per affected method. The
operation numbers are that build's own and mean nothing anywhere else, but the
listing tells you two useful things about them. Every operand that is a
reference into the assembly is named, so a listing mentioning `CryptoStream` and
a `CipherMode` is telling you what the method does even though you cannot read
how. And a header explains what each operation was found to do — `add`, `xor`,
`dup`, reading and writing array elements and so on where that could be
established, and otherwise just how many values it consumed and produced, and
what it insisted on being handed. Some of that comes from the interpreter being
made to perform the operation on chosen values, and some from watching it in the
middle of the real program, which is the only way to reach the ones that need
the program to have set something up first, and the only way to catch an
operation loading or storing — `loads what its operand indexes` and its opposite
are the virtualizer's locals, and `reads the static field it names` says which
field on the line itself.
Operations that none of it settled are left unnamed rather than guessed at, and
the header says why each one was left alone.

Some entries also say what the operation `computes`. That is what the
interpreter itself was seen working out while carrying the operation out, with
the housekeeping every operation does subtracted — `computes clt` under a
`branch if` is the comparison the branch is made on, and `computes
Module::ResolveType, Array::CreateInstance` is an operation making an array of a
type named in the program. An entry reading `effect not established` has had its
working read but not its effect on the stack, and is not claiming to do nothing.

`calls the method it names` and `makes a new object with the constructor it
names` are usually the most useful lines in the file: each names the method
being reached for, and together they are often a third of the program. They are
recognized by having no settled number of values, which is what being handed a
method's arguments looks like, so their entries say that much too.

Jumps are marked on the lines that make them, so you can follow the shape of the
method even without reading it. `-> 1840` means the interpreter really was
watched going there. `~> 1840` means it was not, on this run, but every jump of
that kind that was watched went to the number the operation carries, so this one
is read the same way. A loop, an early exit, or a switch with a hundred arms is
visible from those markings alone.

Beside each listing is a `.lifted.il` file, which is the same program written in
the assembly's own terms: `ldloc`, `add`, `stelem`, `call` with the method it
calls named, `switch` with its arms. That is the file to read first — every
operation in each of the three samples comes out this way — and the listing
beside it is where to go
when you want to know how a line was arrived at. Anything unsettled is written
`??` with what was counted about it, so a line you cannot read is admitted
rather than invented, and nothing in the file has been put back into the
assembly.

Its header is worth a look before you trust it. It says how much was read, how
many jump targets are conjectural (marked `?` on the line), and how far the
stack could be walked: the depth is tracked from the first operation through
every branch, and every place two paths meet has to agree about it. `every one
it reaches twice it reaches at the same depth` across a few thousand operations
is the strongest evidence the file offers that the reading is right. If it
reports disagreements, treat the affected region with suspicion.

Two other header lines are worth knowing. `the rest of the program leaves them
no choice` lists operations nothing could measure whose effect on the stack is
nevertheless fixed by the depths on either side of them — the number is what
they add to the stack, not a reading of what they do, and those lines still say
`??`. The other names what no path arrives at, and how it is worded is the
distinction worth reading for. `operation(s) nothing in the program reaches`
means the walk was never once at a loss, so everything there was to follow it
followed and what is left over is unreachable — in these samples it sits after
an unconditional jump and in no arm of the dispatcher's table, which is to say
the protector emitted it and never uses it. `operation(s) no path arrives at`
is the weaker statement, made where the walk stopped somewhere: the code may
only be past the place it stopped.

Where the sample had methods turned into private instructions, a default run
counts them under `RECOVERED`, explains each one under `DEVIRTUALIZED METHODS`,
and points at the listings under `WROTE`:

```
    Methods devirtualized                  1 of 1
    Interpreter programs found elsewhere   1, listed but not rebuilt

  DEVIRTUALIZED METHODS

    CILantro converted methods protected by code virtualization into readable
    .NET code. These are reconstructions from the virtual machine's instructions,
    not the original method bodies.

    GeneratedNamespace_0003.GeneratedType_0005::generatedMethod_0075
      uses      ... SymmetricAlgorithm.CreateDecryptor, new RijndaelManaged

    VM listings     1 in cilantro/a.virtualized
```

The `DEVIRTUALIZED METHODS` section is described in full above, and it is the
place to start on a translated method. Read what it uses before reading the body
itself: the body is faithful, and faithful to a private instruction format is
still a long way from the method someone wrote.

The locals are worth knowing about before you meet them. The engine's format had
no types — every value it handled was boxed, and every use of one converted it
back — so a body built straight from it declared `object` for every local and
wrote `Convert.ToInt32` at every use. CILantro instead works out what each of
the engine's slots holds, from what the program writes to it, and declares the
slot as that where every path agrees:

```
    int num = 305;                   // rather than  object obj = 305;
    switch (num3)                    // rather than  switch (Convert.ToInt32(value))
    int num4 = 67 + 27;              // rather than  Convert.ToInt32(v3) + Convert.ToInt32(v2)
```

A slot two paths disagree about, and a slot nothing writes, stay `object`, and
their uses still convert; the build notes in the report say how many of each a
body came out with. The gain is not only cosmetic — the dispatcher stage reads a
state variable, and a state variable it can read is one holding a number, so a
rebuilt body's own jump table is usually rewritten into ordinary control flow
now rather than left standing.

`--strict` and `--verbose` add the verdict of the check, and the part in
brackets is then the part to read:

```
    Built back      1 method(s) in the cleaned copy, marked [RebuiltFromReading] (they unpacked the same payload as the original)
```

Those methods hold real IL in the cleaned copy, so the decompiler shows code
where it used to show an empty stub. Each one carries a `[RebuiltFromReading]`
attribute, which dnSpyEx and ILSpy print on the line above the method: under any
verdict these bodies are the tool's reading of the interpreter's program, not
code recovered from the file, and that is the difference between them and
everything else in the assembly.

The bracket is the verdict of an actual run. Where the protected method is on
the sample's own unpacking path, the tool interprets that path twice — once as
the sample shipped, once with the built bodies in place of the stubs — and
compares what comes out. `they unpacked the same payload as the original` means
both runs produced the same hidden assembly, byte for byte, with a built body
entered on the way. `a reading, unchecked` means the comparison could not be made
at all, and the lines under it say why: usually the module unpacks nothing to
compare, or the built body was never entered. `THEY DID NOT MATCH THE ORIGINAL`
means the bodies were built and did something else, which is a reason not to
trust them.

If it did not, and the control flow still looks flattened, the dispatcher stage
declined on those methods. It only rewrites where it can prove the result is
equivalent. `--verbose` reports how many it left alone.

### It is slow

Ten to thirty seconds for a normal sample. The time goes into interpreting the
loader, which is the price of not running it. Very large assemblies take longer.

A sample with methods turned into bytecode takes half a minute or more instead,
because reading the hidden program and building it back are work the ordinary
sample does not need — and if the module unpacks something, running the result to
check it costs as much again as everything else together. `--no-devirtualize` skips the
building and the check and gets you the listings on their own.

### Can I run it on a whole folder?

Not yet, one file at a time. A shell loop works:

```bash
for f in *.exe; do cilantro "$f"; done
```

All the reports land in one `cilantro` folder, named per sample.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Analysis completed |
| 1 | Analysis ran but the result was not fully successful |
| 2 | The command was wrong — bad option, missing or unreadable file |

## Reporting a problem

Include the `--verbose` output and the SHA-256 of the sample. If you can share
the sample, say so; samples are the limiting factor on this project far more than
ideas are.
