# Reading the output

What ReactorUnpack writes, what the numbers mean, and what to do when something
does not work.

## The files

Running `ReactorUnpack suspicious.exe` leaves two things next to the sample.

**`suspicious.cleaned.exe`** — the readable copy. This is what you open in
dnSpyEx or ILSpy. A cleaned library keeps the `.dll` extension.

**`reactorunpack/`** — a folder containing:

| File | What it is |
| --- | --- |
| `suspicious.analysis.json` | Everything the tool observed and did |
| `suspicious.changes.json` | Every individual edit, one entry per change |
| `suspicious.blockers.json` | Everything that stopped the run short, and what to declare to get past it |
| `suspicious.payloads/` | Files that were hidden inside the sample |
| `suspicious.virtualized/` | Per method turned into interpreter bytecode: the program read as IL, and the listing it was read from |
| `suspicious.renames.json` | Old-to-new name map, only with `--rename` |

The folder is not named after the sample, so a directory of samples all report
into one folder without colliding.

## The summary

```
  RECOVERED

    Method bodies decrypted        253 of 253
    Strings decrypted              163 of 163
    Hidden calls resolved          17
    Junk instructions removed      1,942
    Encrypted resources restored   1
    Protector types deleted        12
```

**Method bodies decrypted — `n` of `m`.** How many encrypted method bodies were
recovered, out of how many were found. This is the number that matters most. It
should read `n of n`; if it does not, no cleaned copy is written, because a
partially decrypted assembly is misleading rather than useful.

**Strings decrypted — `n` of `m`.** Recovered string sites out of sites found.
Also all-or-nothing: either every site is proven and replaced, or none are, so
you never have to wonder whether a particular string can be trusted.

**String calls decoded.** Some samples keep their text behind a decoder of their
own rather than behind Reactor's, called with a number where a string belongs.
This counts the calls that were run and replaced with the string they return.
There is no "of `m`" here because there is no set of sites to have covered: a
decoder is proven constant and folded, or it is left alone and named in the
report.

**Hidden calls resolved.** Metadata references that were being looked up at run
time to hide a dependency, turned back into direct references. Raises the number
of working cross-references in your decompiler.

**Hidden true/false values resolved.** Reactor can encrypt booleans the way it
encrypts strings. Only appears when the sample used it.

**Junk instructions removed.** Instructions proven unreachable once the fake
conditions were folded away. Large numbers are normal.

**Encrypted resources restored.** The application's own resources, decrypted and
put back where the program expects them.

**Protector types deleted.** Reactor's own types, removed after recovery proved
they had nothing left to do. See "Why is Reactor's code still there?" below.

**Obfuscated names replaced.** Only with `--rename`.

## The ASSUMED section

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

```
  BLOCKED   what stopped the run, and what would get past it

    UnstatedFact  wmi:Win32_DiskDrive.SerialNumber  (x4)
      in System.String W8ysC31VAB3Rg7yojQi.bHOEmc16m1KHmOsR4gd::TJ51Wrvldq(...) IL_0030
      declare: "facts": { "wmi:Win32_DiskDrive.SerialNumber": <value> }

    All of them, in full: reactorunpack/sample.blockers.json
```

Each entry is one thing that stopped the interpretation, what it is about, where
it happened, how often it came up, and the exact line to write down to get past
it. An entry reading **no declaration fixes this** is one that needs a change to
the tool rather than a line in a file, and saying so is the point: it tells you
to stop looking for something to declare.

`reactorunpack/NAME.blockers.json` carries all of them, with the tool version and
the hashes of the input and the declarations, and is the file to read when a
program rather than a person is deciding whether to try again. `Blockers` there
means what stopped the run; `ContinuedPast` is what it carried on past, and
`Strict` says which mode produced the file. The kinds and the file's shape are in
[declarations.md](declarations.md).

## The NOTES section

Notes appear when a stage did not fully succeed. A line beginning `-` is a stage
that declined to act; a line beginning `!` is a stage that failed.

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
| `TypeCount`, `MethodCount`, `ConcreteMethodCount` | Size of the cleaned module |
| `Resources` | Every embedded resource with size, SHA-256, entropy, and inferred role |
| `Payloads` | Hidden assemblies found, with hashes at every decoding stage |
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
protections that were detected, and they are what the summary turns into English.
`metadata-anomaly` entries are the deliberate metadata damage Reactor introduces
to break tools — useful for detection rules. `trusted-library` entries name each
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
virtualization in the sample, or a Reactor version whose loader reaches outside
what the interpreter models.

The analysis report is still complete and still useful. You will often have the
strings, the payloads, and the resource inventory even when no assembly could be
emitted.

### "This file is not protected by .NET Reactor"

Either it is not Reactor, or it is a version whose structure is not recognised.
Check whether it is another protector — ConfuserEx and Eazfuscator are the usual
alternatives, and [de4dot](https://github.com/de4dot/de4dot) handles those.

If you are confident it is Reactor, that is worth reporting, with the sample.

### "is not a .NET assembly"

The file is not managed code. If you expected .NET, it may be natively packed
with the .NET part hidden inside — see the native packing section in
[how-net-reactor-works.md](how-net-reactor-works.md). That case is detected and
reported separately when the file is still recognisably a .NET image.

### The cleaned copy still has meaningless names

Expected. Reactor deletes the original names rather than encrypting them, so
they are not in the file and cannot be recovered. `--rename` substitutes readable
placeholders, which makes navigation easier but does not restore anything.

### Why is Reactor's code still there?

Some of it usually is, and this is deliberate. The tool deletes a declaration
only when recovery can account for why it has no use left, rather than deleting
whatever looks like it belongs to the protector. Leftovers are counted in the
`runtime-cleanup` diagnostics under `--verbose`.

If you would rather keep all of it — for building detection signatures, say —
use `--keep-runtime`.

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

If it did not, and the control flow still looks flattened, the dispatcher stage
declined on those methods. It only rewrites where it can prove the result is
equivalent. `--verbose` reports how many it left alone.

### It is slow

Ten to thirty seconds for a normal sample. The time goes into interpreting the
loader, which is the price of not running it. Very large assemblies take longer.

### Can I run it on a whole folder?

Not yet, one file at a time. A shell loop works:

```bash
for f in *.exe; do ReactorUnpack "$f"; done
```

All the reports land in one `reactorunpack` folder, named per sample.

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
