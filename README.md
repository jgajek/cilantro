# ReactorUnpack

**Recovers readable code and the hidden next stage from .NET malware protected
with .NET Reactor — by reading the file, never by running it.**

Open a Reactor-protected sample in dnSpyEx and you get empty methods, no strings,
and class names like `H1lrRRwH0tOVtn61XvY`. Reactor is a commercial protector
that malware authors buy to stop exactly what you are about to do, and it works:
there is nothing to read, nothing to grep for, and no obvious way in. Worse, the
part you actually want is usually not in the file at all. It is encrypted inside
it — the stealer, the loader, the thing that names the family — waiting to be
unpacked by code you cannot read either.

This hands that back. One command gives you a copy of the assembly you can open
in a decompiler and read, the payload hidden inside it written out as a file where
the sample carries one, and a report of what was proved, what was assumed, and
what could not be done. On a sample that comes out clean, that is the difference
between a day in a debugger and a couple of minutes of reading.

It is for whoever has a sample and a deadline: an analyst triaging a detonation,
someone trying to name a family before the sandbox report lands, and pipelines
with nobody in them to read a summary at all.

```
ReactorUnpack suspicious.exe
```

No options to get right, no runtime to install, no VM, and nothing executed:

```
  File     rsServiceController.dll  (191.3 KB)
  SHA-256  15931d5e8c20547c24c851dcb2e29b747699e8b81b925c46c2245269c93d1c91

  PROTECTION   .NET Reactor

    - Method bodies are encrypted, and decrypted in memory as they run (NecroBit)
    - Every method was replaced by an empty stub that gets filled in at run time
    - Text is encrypted, so no readable strings appear in the file
    - Control flow is scrambled, so decompiled code reads as nonsense
    - The file checks itself for modification and can refuse to run
    - Other files are hidden inside this one, encrypted

  RECOVERED

    Method bodies decrypted        253 of 253
    Strings decrypted              163 of 163
    Hidden calls resolved          17
    Junk instructions removed      1,942
    Encrypted resources restored   1
    Protector types deleted        12

  WROTE

    Cleaned copy    rsServiceController.cleaned.dll
    Hidden files    1 in reactorunpack/rsServiceController.payloads
    Full report     reactorunpack/rsServiceController.analysis.json

  Open the cleaned copy in dnSpyEx or ILSpy to read the code.
```

## Why this one

Four open-source tools deal with .NET Reactor. Here are all four on the same
sample — a Reactor crypter payload that is protected twice, with a second
obfuscator hiding strings underneath Reactor
([`81cf796c…`](docs/parity.md#all-four-on-one-hard-sample)):

| | ReactorUnpack | [Slayer](https://github.com/SychicBoy/NETReactorSlayer) | [de4dotEx](https://github.com/GDATAAdvancedAnalytics/de4dotEx) | [Krypton](https://github.com/dawwinci/krypton-devirtualizer) |
| --- | --- | --- | --- | --- |
| Readable strings in the output | **192** | 31 | 8 | 0 |
| Of the 172 encrypted string sites | **all 172** | none | 17 | none |
| C2 address, port, campaign ID | **recovered** | no | no | no |
| Ran the sample | **no** | yes — and crashed there | no | tried to |
| Time | 6m 55s | 2.9s | 2.3s | 18s |

Only this tool's output names the thing: `https://logs.uvexio.com` on port 8443,
campaign `36f871795ba82`, and the sample's full anti-analysis blacklist from
`sbiedll.dll` to `x64dbg`. The 155 strings that carry all of it sit in a layer
*underneath* Reactor, in a dictionary with no encrypted byte table to find, built
by code that is itself written in Reactor-encrypted strings. You have to finish
the outer layer before the inner one is even legible — and Reactor's own table
here is built by a method that is no longer CIL. That is the case this tool is
built for.

It is also slower than every alternative by two orders of magnitude, and on
Windows the two tools that run the sample would do better than they did here.
[docs/parity.md](docs/parity.md) has the full measurement, the reproduction
commands, and where this tool loses.

The reasons behind that result:

**Nothing is executed. Not once, not in a helper process.** Most .NET
deobfuscators load the malware and call its own decryption routines — that is
why they carry warnings about only being used in a VM. ReactorUnpack works out
what the decryption *would* produce. Analysing a sample is as safe as running
`strings` on it, which makes it usable on a laptop, a build agent, or a queue.

**It refuses rather than guesses.** If it cannot prove a change is correct it
does not make it, and it says so. It will write no cleaned copy at all rather
than hand you a subtly broken file that costs you an afternoon. Anything it had
to assume is labelled as assumed, in the summary and in the report.

**It gets the next stage out.** Reactor is most often a wrapper around something
else, and that something else is what you actually want. It comes out to a file,
whatever crypter put it there — not just Reactor's own.

**It reads the methods no decompiler can show — and checks that it read them
right.** Reactor's strongest option replaces a method with bytecode for an
interpreter it generates per sample. ReactorUnpack recovers that program, works
out what it means, and builds it back into real code in the cleaned copy. Where
the sample's own unpacking path goes through such a method, it then interprets
that path twice — once as shipped, once with the rebuilt bodies in place — and
tells you whether the same payload comes out byte for byte.

**MIT, single file, agent-ready.** The other three Reactor tools are GPLv3, which
decides whether you can build on them. This one is MIT and clean-room. It ships
as one binary with no dependencies, and it speaks JSON and MCP for pipelines that
have no one to read a summary.

| If you want to | Reach for |
| --- | --- |
| Know what an unfamiliar sample is and get the next stage out, without running it | **ReactorUnpack** |
| Read a virtualized method without running anything | **ReactorUnpack** |
| The most thoroughly cleaned assembly a Reactor tool will give you | [NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) |
| Handle Reactor 7+, or a sample that turns out not to be Reactor at all | [de4dotEx](https://github.com/GDATAAdvancedAnalytics/de4dotEx) |
| A devirtualized binary you can run and debug | [Krypton](https://github.com/dawwinci/krypton-devirtualizer) |
| Rename everything, including public types, the way de4dot does | Slayer or de4dotEx |

## Install

Download from the
[Releases page](https://github.com/jgajek/reactor-unpack/releases) and unpack.
There is nothing to install: it is a single file with everything it needs inside,
so it works on a fresh analysis VM that has never had .NET on it.

| Platform | Download |
| --- | --- |
| Windows 64-bit | `ReactorUnpack-win-x64.zip` |
| Linux 64-bit | `ReactorUnpack-linux-x64.tar.gz` |

Check it against `SHA256SUMS.txt`, which you should. `ReactorUnpackMcp` is in the
same archive — the same tool, spoken to over the Model Context Protocol.

## Use it

```
ReactorUnpack suspicious.exe
```

That is the whole thing. It leaves two things beside your sample:

- **`suspicious.cleaned.exe`** — the readable copy. Open it in
  [dnSpyEx](https://github.com/dnSpyEx/dnSpy) or
  [ILSpy](https://github.com/icsharpcode/ILSpy).
- **`reactorunpack/`** — the full JSON report, every change made, whatever was
  hidden inside the sample, and the operation-by-operation reading of any method
  that shipped as interpreter bytecode.

Your input file is never touched.

| Option | What it does |
| --- | --- |
| `--analyze-only` | Say what the file is without writing anything |
| `--strict` | Assume nothing (below) |
| `--json` | Print the run as one object instead of a summary |
| `--verbose` | Show every step, which is what a bug report wants |

`ReactorUnpack --help` has the rest; there are only a handful.

### Two modes, and why the default is the loose one

Malware asks where it is running: the machine name, a disk serial, whether a
debugger is attached. Since nothing is being executed, there is no such machine
to read the answers off.

**By default** the tool answers as a plausible Windows 10 workstation, steps over
the framework calls it has not modelled, and marks every one of those answers as
assumed rather than stated. You get the most it can say, clearly labelled as to
where it came from. This is the mode for a first look at something unfamiliar.

**`--strict`** assumes nothing. It stops at any call it cannot read, and leaves
the assembly as it stands — no renaming, no rebuilding virtualized methods, since
both of those are the tool's reading rather than the protector's output. Less
comes out, and all of it rests on the file alone. This is the mode for an answer
you are going to rely on. Either extra can still be asked for by name, with
`--rename` and `--devirtualize`.

Nothing is ever invented. An unknown value may be carried, but the moment it
would have to become a branch, an index, or a length, the run stops.

### When a run stops short

Every run writes `reactorunpack/suspicious.blockers.json`, naming each thing that
stopped it, where, how often, and the exact line that would get past it:

```json
{
  "Kind": "unstatedFact",
  "Key": "wmi:Win32_DiskDrive.SerialNumber",
  "Declare": "\"facts\": { \"wmi:Win32_DiskDrive.SerialNumber\": <value> }",
  "Where": "System.String W8ysC31VAB3.bHOEmc16::TJ51Wrvldq(...) IL_0030",
  "Times": 4
}
```

What you know goes back in one file — host facts, assemblies the sample needs but
does not carry, how much work the run may do, and, with `--allow-declared-calls`,
what a call the tool cannot read does:

```
ReactorUnpack suspicious.exe --declarations ptnifif.json
```

So the way through a stubborn sample is a loop: run it, read what stopped it,
write down what you know, run it again. Where no declaration would help, the
entry says so, and that is a bug report rather than a file to edit.
[docs/declarations.md](docs/declarations.md) is the contract.

## Driving it from a pipeline

The other way this gets used is with nobody watching. There is no separate mode
for it: what a program needs is the same decisions with a machine-readable
answer, not different decisions.

```
ReactorUnpack suspicious.exe --json
```

One object on stdout, naming every file written, every payload with its hash and
the path it landed on, and every stop — each carrying a `Remedy` a program
applies as `declarations[Section][Name] = Value` without parsing English.
`MoreToDeclare` is the loop's stopping condition: false means another round
cannot help and the sample needs a change to the tool.

The same tool is also an MCP server, with `unpack`, `next_declarations` — which
turns what stopped a run into the file to run with next — and `read_output`:

```jsonc
{ "mcpServers": { "reactorunpack": { "command": "/opt/reactorunpack/ReactorUnpackMcp" } } }
```

Nothing escalates on its own. A budget stop comes back with the figure to raise
it to; whether the extra minutes are worth spending stays with the caller. And
`read_output` will not hand an extracted payload back to a model — that is
malware, and the manifest names the path so a sandbox can be pointed at it.

[docs/agents.md](docs/agents.md) is the guide, [schema/](schema/) is what the
output promises and for how long.

## The two hard parts

Most of what Reactor does has a standard answer. Two things are harder, and they
are usually the reason to reach for this tool rather than another.

### Getting the hidden file out

The sample you have is often a shell whose real job is to decrypt something else
and run it. ReactorUnpack works out what that unpacker would have produced and
writes it to `reactorunpack/suspicious.payloads/`, ready to analyse on its own —
or to put through the tool again, if it turns out to be Reactor-protected in its
turn. Three cases come up, and all three end with you knowing something:

- **The payload is carried in the file**, as an encrypted resource or a blob.
  This is the common one, and the file comes out.
- **The payload is downloaded.** There is nothing to unpack, so the reader
  follows the sample as far as the connection — including through `async`
  methods, which it drives to completion — and tells you where it was going, host
  and port. That address is the thing worth having.
- **The unpacker is itself virtualized**, so there is no unpacker code to follow.
  The tool then reads Reactor's interpreter the same way it reads everything
  else, and lets it do the unpacking. That costs about a minute rather than a few
  seconds, and the file still comes out.

### Reading methods that were turned into bytecode

Reactor's strongest option replaces a method's code with a numbered list of
operations for an interpreter it generates and embeds. The original code is not
in the file anywhere, so there is nothing to decrypt, and no public tool — this
one included — recovers the source.

What you get instead is the hidden program, read and named. The tool recovers it
by interpreting the protector's own decoder, works out what each operation means
by experiment and by watching the interpreter work, checks the readings against
each other with a stack-depth walk over the whole program, and writes it out with
every method, field and type the hidden code touches named:

```
   2627:  newobj     System.Security.Cryptography.CryptoStream::.ctor(...)
   2632:  ldlen
   2634:  call       ...::h5bTpuvG9giGM6rEuXl(...)
   2636:  call       ...::AkiDCJvwSWy6yH7wA8K(...)
   2638:  call       ...::px4E1VvpQREo8oO95Pa(...)
   2639:  stsfld     System.Object ...::wBHpICowg0
```

Those three unreadable names are ordinary methods elsewhere in the sample, and
looking them up takes a minute: one-line wrappers around `Stream.Write`,
`CryptoStream.FlushFinalBlock` and `MemoryStream.ToArray`. So the fragment is a
decryptor, writing a byte array through a cipher and keeping the result — read
out of a method whose code does not exist in the file.

You also get it as code, in the cleaned copy, where the rest of the recovery
already is: verbose, boxed, still flattened, but readable in a decompiler and
navigable by cross-reference. A reading is not the same kind of proof as a
decrypted body, so each rebuilt method carries a `[RebuiltFromReading]` attribute
that dnSpy and ILSpy show on the line above it. And where the sample's own work
can test the reading, the tool makes it do so and reports the verdict:

> Checked by running it: with the built bodies in place of the stubs, the module
> unpacks SHA-256 `7fa1a9d7…` and SHA-256 `81cf796c…` — byte for byte what it
> unpacks as it shipped, and a built body was entered 2 time(s) doing it.

Both of those unpackings are interpretations, not executions — the check costs
the guarantee at the top of this page nothing. Where it cannot be made, the tool
says so rather than implying one.
[docs/devirtualization.md](docs/devirtualization.md) is the whole story, written
for someone who does not work in .NET.

## What it handles

.NET Reactor 6, which covers the large majority of Reactor-protected samples in
circulation: encrypted method bodies (NecroBit), encrypted strings, scrambled
control flow, junk-call insertion, proxied calls, hidden metadata references,
anti-tamper and anti-debug checks, encrypted embedded resources, embedded payload
assemblies, and code virtualization.

## What it does not handle

Being straight about this matters more than the feature list.

- **Proving what a virtualized method did.** The bodies built into the cleaned
  copy are the tool's reading, not code recovered from the file, and each says so
  in an attribute. Where the sample's own work can test them it does; where it
  cannot, the reading stands unchecked.
- **Native-packed files.** A sample wrapped in a native stub rather than being
  pure .NET is detected and reported as unsupported, not mangled.
- **Reactor 7 and later, and other protectors.** ConfuserEx, Eazfuscator, Babel
  and friends are out of scope — try
  [de4dotEx](https://github.com/GDATAAdvancedAnalytics/de4dotEx).
- **Getting original names back.** Reactor destroys them; they are not in the
  file. The cleaned copy substitutes readable placeholders, which helps
  navigation but is not the same thing.

If a sample is not Reactor-protected, it says so and stops.

## Is the cleaned file safe to run?

**No.** It is still malware, and it is now malware with its protection removed,
which is worse. The cleaned copy is for reading in a decompiler. It is not
sanitised or defanged in any way. Treat it exactly as you would the original.

## Documentation

- **[How .NET Reactor works](docs/how-net-reactor-works.md)** — what each
  protection does to the file, for someone who does not know .NET internals.
  Start here if the output mentioned something you did not recognise.
- **[How ReactorUnpack undoes it](docs/how-recovery-works.md)** — the technique
  used against each protection, and why it is safe to do statically.
- **[Virtualized methods](docs/devirtualization.md)** — what virtualization does
  to a method, how the hidden program is recovered and read, and how much of that
  would work against a protector other than Reactor.
- **[Reading the output](docs/reading-the-output.md)** — the report format, what
  each number means, and what to do when something does not work.
- **[Declarations](docs/declarations.md)** — what a run can be told, what it
  reports back when it stops, and the loop between the two.
- **[Driving it from a program](docs/agents.md)** — `--json`, the MCP server, and
  how a pipeline works a sample through the loop without a person in it.
- **[Compatibility and provenance](docs/compatibility.md)** — the precise support
  contract and the verification gates.
- **[How it compares](docs/parity.md)** — which of NETReactorSlayer, de4dotEx,
  Krypton and this one to reach for, and where this one is weaker.
- **[Corpus](docs/corpus.md)** — how correctness is measured.

## Building from source

Requires the .NET 10 SDK.

```bash
dotnet restore ReactorUnpack.slnx
dotnet build ReactorUnpack.slnx -c Release
dotnet test ReactorUnpack.slnx -c Release
```

Use `-c Release` for the tests. Most of the suite is the analysis engine working
through real samples, which an unoptimised build runs about five times slower.

While you work, run the suite without the six tests that put whole samples
through the machine:

```bash
dotnet test ReactorUnpack.slnx -c Release --filter "Cost!=High"
```

That is 396 of the 402 tests in about five seconds, against the eight minutes
those six cost between them. They still run on a plain `dotnet test`, which is
what to do before pushing, because they are the ones that prove the tool recovers
real malware.

When the change is to one pass and you need a real sample to see it, skip the
passes that come after the one you are working on rather than waiting for the
whole pipeline. Payload extraction and virtualization disassembly account for two
minutes of a run on their own, and nothing before them depends on either:

```bash
cat > /tmp/fast.json <<'JSON'
{ "passes": { "skip": ["payload-extraction", "virtualization-disassembly"] } }
JSON
dotnet run --project src/ReactorUnpack.Cli -c Release --no-build -- \
    samples/NAME.exe --analyze-only --declarations /tmp/fast.json --report-dir /tmp/loop
```

Eleven seconds instead of two and a half minutes, and the report still carries
the passes you kept, with their diagnostics and blockers. The output is not a
recovery — skipping a pass that gates emission means no cleaned copy is written,
which is the point: this is for reading a report, and the full run is what says
whether the change was right.

The samples themselves are malware and are not in the repository, so a fresh
checkout has none. The tests that read one are skipped there rather than failed,
and say so with a reason, which is how CI runs: green means everything checkable
without samples was checked, and the skip count says what was not. Put samples in
`samples/` and the same command runs them too — see
[docs/corpus.md](docs/corpus.md).

## Contributing

Samples are the bottleneck, not ideas. If you have a Reactor-protected sample
that ReactorUnpack handles badly, that is the most valuable thing you can
contribute — particularly native-packed ones, which are unimplemented purely
because no sample has been available to develop against.

Bug reports should include the `--verbose` output and the SHA-256 of the sample.

## Licence and credits

MIT. See [LICENSE](LICENSE).

ReactorUnpack is independent of
[NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) and contains no
de4dot-derived or other GPL code; it was built clean-room from behaviour observed
in samples, which is what allows it to be MIT rather than GPL. It depends on
[dnlib](https://github.com/0xd4d/dnlib), also MIT.

.NET Reactor is a product of Eziriz. This project is not affiliated with or
endorsed by them.
