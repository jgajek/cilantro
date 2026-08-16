# Declarations: telling a run what it cannot work out

**You do not need this for a first look at a sample.** A default run assumes a
plausible Windows machine, steps over the calls it cannot read, and tells you what
it assumed; see [the two modes](compatibility.md#the-two-modes). This file is for
the case after that: a particular sample whose payload you actually want, where the
run has stopped at a fact only you can supply — a registry value holding the key,
most often — and for an agent working through such stops one at a time.

A stop is only useful if you can tell what would get past it. So every run writes
down what stopped it and what to say to get further, and takes what you say back in
one file.

```
  ReactorUnpack sample.exe --declarations d.json
        │
        ├── reactorunpack/sample.blockers.json   what stopped it, and what to declare
        │
        └── you (or an agent) append the declaration to d.json and run it again
```

Every stop carries its remedy twice: as a line to retype, and as parts a program
can apply without reading English. [agents.md](agents.md) covers the second.

Nothing in this file widens what the interpreter will do on its own. Every
section answers a question the machine already knows how to ask, and a section
nobody writes leaves the refusal exactly where it was.

What you state always beats what the tool assumes. A stated fact is credited to you
in the summary rather than marked assumed, and a declared call outcome is consulted
before the tool would step the call over. Under `--strict` nothing is assumed at all,
so the declarations are the only thing standing between the run and a refusal — which
is why the loop below belongs with that flag when the answer is going to be relied
on.

## The file

```json
{
  "name": "ptnifif",
  "facts": {
    "env:MachineName": "DESKTOP-7QK2",
    "wmi:Win32_DiskDrive.SerialNumber": "WD-WCC4E5PJ0KZT",
    "registry:HKEY_CURRENT_USER\\Software\\X!blob": { "base64": "H4sIAAAA..." }
  },
  "libraries": ["./protobuf-net.dll"],
  "budgets": { "steps": 40000000, "allocatedBytes": 1073741824, "depth": 128 },
  "passes": { "skip": ["virtualization-disassembly"] },
  "calls": {
    "System.Void System.Threading.Thread::set_IsBackground(System.Boolean)": { "inert": true },
    "System.String Vendor.Support.Licence::Check()": { "returns": "MIT-9931" }
  }
}
```

Every section is optional. `--host-profile` is the `facts` section written in its
own file and `--library` is one entry of `libraries`, so anything that worked
before still works; the file simply lets one thing carry all of it. Passing a
profile *and* declarations that state facts is refused: keep the facts in one
file, since otherwise one of the two would lose without saying so.

| Section | What it says | Weight |
| --- | --- | --- |
| `facts` | What the Windows machine the sample expects looks like | A statement about a computer |
| `libraries` | Assemblies whose IL the interpreter may read | Names a file, hashed in the report |
| `budgets` | How much work the run may do | Changes nothing about meaning |
| `passes` | Stages to leave out | Withholds the cleaned copy |
| `calls` | What a call the tool cannot read does | An assertion; needs `--allow-declared-calls` |

### facts

Keys are the ones the refusals print, in families: `env:`, `time:`, `guid:`,
`debugger:`, `process:`, `runtime:`, `native:`, `wmi:`, `registry:`, `volume:`,
`net:`. A key in no family is rejected rather than ignored, because a misspelled
key in a file that looks like it is doing something is the mistake worth
catching. A value is text, a whole number, `true`, `false`, `null` for absent, or
`{ "base64": "..." }` for bytes. `profiles/windows-10-workstation.json` is a
filled-in example.

### libraries

Paths are read relative to the declarations file, so a file and the assemblies it
mentions travel together. The report names the version and SHA-256 of the exact
file whose code was read.

### budgets

`steps`, `allocatedBytes` and `depth`. Each pass has its own figures because each
does a different amount of work; a declared budget replaces the figure wherever
it is set, since it is a statement about the run rather than about one pass.
Raising `allocatedBytes` carries the largest single array up with it, because a
budget raised for the sake of one large read would otherwise refuse that read.

### passes

`{ "skip": ["pass-name"] }`, spelled as the pass names itself in the summary. A
skipped pass counts as incomplete, so the cleaned copy is still withheld — this
is for getting a report out of a sample where one stage is the problem, not for
talking the tool into emitting something it cannot stand behind.

### calls

The one section that can put a value into the interpretation which no code
produced, so it takes a second decision: it is ignored unless the run is given
`--allow-declared-calls`. The key is the signature the refusal printed, exactly:

```json
"calls": { "System.Boolean Vendor.Guard::Ok()": { "returns": true } }
```

Each entry says either what the call returns or that it is `inert` — does nothing
observable — and never both. A call that returns a value cannot be declared
inert, because "does nothing" says nothing about the value the program is about
to use.

Three things keep this honest. It is consulted last, after every way of actually
following the call has been tried, so a declaration can never stand in front of a
model, a body in the module, or a trusted library. Every value it produces
carries `Declared` provenance, so a reader tracing a recovered constant back
reaches the assertion it rests on. And a call declared inert is recorded as
having handed something to the runtime, so the pass that removes loader frames it
can prove do nothing cannot prove it from a declaration that they do nothing.

## What comes back

`reactorunpack/NAME.blockers.json` is written on every run:

```json
{
  "ToolVersion": "0.1.0",
  "InputSha256": "e4e746...",
  "DeclarationsName": "ptnifif",
  "DeclarationsSha256": "0b777e...",
  "CallsAllowed": true,
  "Blockers": [
    {
      "Kind": "unstatedFact",
      "Key": "wmi:Win32_DiskDrive.SerialNumber",
      "Detail": "the host profile \"ptnifif\" does not say wmi:Win32_DiskDrive.SerialNumber; ...",
      "Remedy": {
        "Section": "facts",
        "Name": "wmi:Win32_DiskDrive.SerialNumber",
        "Value": null,
        "Wants": "value",
        "Flag": null
      },
      "Declare": "\"facts\": { \"wmi:Win32_DiskDrive.SerialNumber\": <value> }",
      "Where": "System.String W8ysC31VAB3Rg7yojQi.bHOEmc16m1KHmOsR4gd::TJ51Wrvldq(...) IL_0030",
      "Pass": "constant-strings",
      "Times": 4
    }
  ],
  "UnconsultedDeclarations": []
}
```

`Declare` is the whole of what to do about a blocker: paste it into the file and
run again. Where it is `null`, no declaration will help and the next step is a
change to the tool.

`Remedy` is the same statement with the parts kept apart, for whatever is doing
the pasting when it is not a person. Applying one is
`declarations[Section][Name] = Value`. Where `Wants` is null the tool knew the
whole answer and wrote it — a budget arrives carrying twice the figure that was
refused, and a call that returns nothing arrives as `{ "inert": true }`. Where
`Wants` is not null, only you can know the answer: `Value` holds a single `null`
standing where it goes, and `Wants` names the kind of value that would be
believed. `Flag` is `--allow-declared-calls` or nothing.

| `Kind` | What it means | What to do |
| --- | --- | --- |
| `unstatedFact` | Something was asked about the machine that nobody stated | State it in `facts` |
| `unmodeledCall` | A managed call nothing models | Model it in code, or declare it in `calls` |
| `platformCall` | A call that leaves the runtime | Declare the wrapper in `calls`, if you know what it does |
| `budget` | The run reached a limit on work | Raise it in `budgets` |
| `unsupportedInstruction` | An instruction the machine does not run | Change the tool |
| `unsupportedBody` | A method whose body or handlers it cannot run | Change the tool |
| `unknownValue` | A decision that turned on a value nothing produced | Act on the earlier refusal, not this one |
| `threw` | The program threw and nothing caught it | Read the throw; often a fact away |

A stop met more than once is one entry with `Times` beside it, keyed by what it
is about, and the order is the order things were first hit. Two runs of the same
thing therefore produce the same list, which matters because the tool interprets
everything twice and compares.

`UnconsultedDeclarations` is the other half. A declaration nothing asked about
did not fail — it was never consulted, usually because the key is spelled
differently from the one the run asks under, and that calls for a different fix
than a declaration that did not work. Facts are accounted for the same way, in
the `ASSUMED` section of the summary and in `HostProfile.Consulted` in the
analysis report.

## The loop, for an agent

1. Run with `--analyze-only` and `--declarations d.json`. Add `--strict` when the
   point of the loop is to leave nothing assumed; without it the run gets further on
   its own, and `ContinuedPast` tells you which calls it walked past to do so.
2. Read `NAME.blockers.json`. If `Blockers` is empty, there is nothing left to
   declare — though under the default some of the reading may rest on the entries in
   `ContinuedPast`, which no declaration is needed for and any of which can be closed
   by declaring the call outright.
3. For each blocker with a `Remedy`, decide whether you actually know the
   answer. One with `Wants` null needs no decision at all. Facts and budgets are
   cheap and safe. A `calls` entry is an assertion about somebody else's code:
   make it only when you know, and expect it to be named in the report.
4. Merge into `d.json` and go back to 1. Check `UnconsultedDeclarations` each
   time, since a declaration that answered nothing is the commonest mistake.
5. Stop when what remains has no `Remedy`. Those are the tool's problem, and the
   `Detail` and `Where` are what a bug report needs.

`--json` puts all of this in one object on standard output, including where the
reports went, so that none of it has to be found first; and the MCP server does
steps 2 to 4 as a single call. [agents.md](agents.md) is the guide for driving
the tool this way.

## What stays true

A declaration does not lower the bar the output has to clear, and neither does the
default mode. Recovered code still has to verify, still has to round-trip, and the
two interpretations still have to agree, so a wrong declaration — or an assumption
that mattered — surfaces as a failed check rather than as a quiet lie. What a run rests on is written down: the declarations' name and hash
are in both reports, every fact consulted is listed, and every declared call is
printed in the summary under `ASSUMED`.
