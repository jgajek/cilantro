# ReactorUnpack

**Recovers readable code from .NET malware protected with .NET Reactor — without ever running it.**

You pulled a .NET sample out of a sandbox, opened it in dnSpyEx, and every method
is empty. No strings. Class names like `H1lrRRwH0tOVtn61XvY`. That is .NET
Reactor, a commercial protector that malware authors buy to stop exactly what you
are trying to do.

ReactorUnpack undoes it and hands you a copy you can actually read.

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

## Why you might want it

**It never runs the sample.** This is the important one. Most .NET deobfuscators
work by loading the malware into memory and calling its own decryption routines.
That is malware execution, on your machine, and it is why those tools carry
warnings about only being used in a VM. ReactorUnpack reads the file as data and
works out what the decryption *would* produce, so analysing a sample is as safe
as running `strings` on it.

**It tells you when it is unsure.** If it cannot prove a change is correct, it
does not make the change, and it says so. It will refuse to write a cleaned copy
rather than hand you a subtly broken file that wastes an afternoon. Everything it
did is listed in the report.

**It gets the hidden files out.** Reactor is often used to wrap a second payload.
ReactorUnpack decrypts and extracts those, so the thing you actually care about
is sitting on disk instead of buried in an encrypted blob.

**It leaves your file alone.** The input is never modified. Output goes to new
files beside it.

## Install

Download the archive for your platform from the
[Releases page](https://github.com/jgajek/reactor-unpack/releases) and unpack it.

There is nothing to install. It is a single file with everything it needs
inside, so it works on a fresh analysis VM that has never had .NET on it.

| Platform | Download |
| --- | --- |
| Windows 64-bit | `ReactorUnpack-win-x64.zip` |
| Linux 64-bit | `ReactorUnpack-linux-x64.tar.gz` |

Check the download against `SHA256SUMS.txt` if you care to, which you should.

## Use it

Point it at the file:

```
ReactorUnpack suspicious.exe
```

That is the whole thing. There are no required options.

It leaves two things next to your sample:

- **`suspicious.cleaned.exe`** — the readable copy. Open this in
  [dnSpyEx](https://github.com/dnSpyEx/dnSpy) or
  [ILSpy](https://github.com/icsharpcode/ILSpy).
- **`reactorunpack/`** — a folder with the full JSON report, a list of every
  change made, and any files that were hidden inside the sample.

If you only want to know what a file is without producing anything:

```
ReactorUnpack suspicious.exe --analyze-only
```

If you want to watch what it is doing, or you are reporting a problem:

```
ReactorUnpack suspicious.exe --verbose
```

Run `ReactorUnpack --help` for the rest. There are only a handful.

### When the sample asks about the machine

Malware asks where it is: the machine name, a disk serial number, whether a
debugger is attached. This tool runs on Linux and never runs the sample, so there
is no such machine to read the answers off. It answers from a **host profile**
instead, and says which answers it used.

Out of the box the profile states only the few things the tool has always
answered. Anything else stops the run, naming the fact that would let it
continue — `wmi:Win32_BIOS.SerialNumber`, say. Put the facts you know in a file
and hand it over:

```
ReactorUnpack suspicious.exe --host-profile profiles/windows-10-workstation.json
```

The summary's `ASSUMED` block lists what was asked and what it was told, and the
report carries the profile's hash next to the sample's, because a stated fact is
used like any other value and can end up in the cleaned copy.

A fact can be bytes, written as `{ "base64": "..." }`. That is what to use when
the sample keeps its next stage in a binary registry value: paste the value in and
the run unpacks the stage out of it.

### When the payload is not in the file

Some samples download the next stage instead of carrying it. The reader follows
them as far as the connection — including through `async` methods, which it drives
to completion — and then stops and says where the connection was going, host and
port. There is nothing to unpack in such a file, and the address is the thing
worth having.

### When the sample unpacks itself through a library

Some samples decrypt themselves using a third-party assembly they reference but
do not carry. Supply it and the reader can follow the call:

```
ReactorUnpack suspicious.exe --library ./protobuf-net.dll
```

The assembly has to be one the sample actually references, its hash is recorded
in the report, and nothing in it is executed — its IL is read the same way the
sample's is. Repeat the option for more than one.

## What it handles

.NET Reactor 6, which covers the large majority of Reactor-protected samples in
circulation. Specifically: encrypted method bodies (NecroBit), encrypted strings,
scrambled control flow, junk-call insertion, proxied calls, hidden metadata
references, anti-tamper and anti-debug checks, encrypted embedded resources, and
embedded payload assemblies.

## What it does not handle

Being straight about this matters more than the feature list.

- **Code virtualization.** When a method has been turned into bytecode for a
  custom interpreter, ReactorUnpack does not turn it back into a readable
  method. No public tool does. What it does instead is name the affected methods
  and write out the program behind each one: how many operations it has, and —
  because operands that are metadata tokens are resolved — which methods,
  fields, and types the hidden code reaches for. It also works out what most of
  the operations do — all 29 in the samples here, every one of them named,
  calls, object constructions, returns, discards and static field writes among
  them — by
  having the interpreter carry them out one at a time on values chosen for the
  purpose, by watching what they fetch, store and jump to while the program
  really runs, and by noting what the interpreter itself computed on their
  behalf, which is the closest thing to reading the hidden method's own source.
  All of that is then written out a second time as the IL it stands for —
  every operation in each of the three samples, none of them left unknown.
  That listing checks itself: the dispatcher's jump
  table turns the program back into blocks, and walking the depth of the stack
  through all of them reaches every operation any path arrives at, in all three
  samples, without ever reaching a place two ways and disagreeing; what it does
  not arrive at is code nothing in the program reaches. The walk is
  also what settles the last operations nothing could measure: with everything
  around them known, the depths leave them one possible effect and no other. It
  is a reading, not a decompilation, and
  nothing is put back into the assembly on the strength of it — but it is
  usually more than enough to say what a method you cannot read is *for*. It can
  also still pull hidden files
  out of a sample whose unpacker is virtualized, because it runs the interpreter
  rather than trying to undo it; that just takes a minute or so instead of
  seconds.
- **Native-packed files.** If the sample is wrapped in a native stub rather than
  being a pure .NET file, it is detected and reported as unsupported rather than
  being mangled. See [docs/how-net-reactor-works.md](docs/how-net-reactor-works.md).
- **Other protectors.** ConfuserEx, Eazfuscator, Babel, and friends are out of
  scope. Try [de4dot](https://github.com/de4dot/de4dot) for those.
- **Getting original names back.** Reactor destroys them; they are not in the
  file. `--rename` substitutes readable placeholders, which helps navigation but
  is not the same thing.

If a sample is not Reactor-protected, it says so and stops.

## Is the cleaned file safe to run?

**No.** It is still malware. The cleaned copy is for reading in a decompiler.
It is not sanitised, defanged, or made safe in any way — quite the opposite, it
is the malware with its protection removed. Treat it exactly as you would treat
the original.

## Documentation

- **[How .NET Reactor works](docs/how-net-reactor-works.md)** — what each
  protection actually does to the file, written for someone who does not know
  .NET internals. Start here if the output mentioned something you did not
  recognise.
- **[How ReactorUnpack undoes it](docs/how-recovery-works.md)** — the technique
  used against each protection, and why it is safe to do statically.
- **[Reading the output](docs/reading-the-output.md)** — the report format, what
  each number means, and what to do when something does not work.
- **[Compatibility and provenance](docs/compatibility.md)** — the precise
  support contract and verification gates.
- **[Comparison with NETReactorSlayer](docs/parity.md)** — stage-by-stage,
  including where this tool is weaker.
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
