# Driving it from a program

The other way this tool gets used is not by a person at all. A pipeline meets a
.NET sample, wants the payload out of it and the strings readable, and has no
one to read a summary. Everything below is for that case.

There is no special mode for it. What a program needs is not a different set of
decisions about what may be assumed — it needs the same decisions with a
machine-readable answer, and those are different axes. So `--strict` still means
what it means, and `--json` is how you ask for the answer in a form you can
parse.

```
cilantro suspicious.exe --json
```

One JSON object on standard output, nothing else, and the exit code says how it
went: `0` for a run you can stand behind, `1` for a run that finished without
one, `2` for a file or an option the tool could not work with. Under `--json`
even that last case answers in JSON.

## What comes back

```jsonc
{
  "Schema": "cilantro.run/1",
  "Success": true,
  "Strict": false,
  "Protector": "reactor6",
  "Protections": ["protected-strings", "resource-container", "virtualization"],
  "Wrote": {
    "Cleaned":  "/samples/suspicious.cleaned.exe",
    "Analysis": "/samples/cilantro/suspicious.analysis.json",
    "Changes":  "/samples/cilantro/suspicious.changes.json",
    "Blockers": "/samples/cilantro/suspicious.blockers.json",
    "Renames":  "/samples/cilantro/suspicious.renames.json",
    "Config":   null,
    "Listings": ["/samples/cilantro/suspicious.virtualized/N66S3rciU7.lifted.il"]
  },
  "Payloads": [
    {
      "PayloadSha256": "417032e5...",
      "PayloadLength": 92672,
      "AssemblyName":  "Zebekeadu",
      "WrittenTo":     "/samples/cilantro/suspicious.payloads/Zebekeadu.dll"
    }
  ],
  "Blockers": [],
  "MoreToDeclare": false
}
```

Four fields carry most of the weight.

**`Protector`** is which of the recognised protectors the run acted on —
`reactor6`, `confuserex`, or `none`. Branch on this rather than on the contents of
`Protections`: both protectors have a capability called anti-tamper and mean
different mechanisms by it, and how much of a cleaned copy you should expect
differs by protector.

**`Wrote`** names every file the run produced. Nothing has to be rebuilt from
the naming convention, and nothing moves if the convention does. `Config` is
`null` on most runs; it is a path when a protector kept constants out of the
metadata that could not all be put back into it.

**`Payloads`** is the deliverable for most pipelines: what was hidden inside,
each with its SHA-256 and the path it was written to. Payload entries are
abbreviated above; the full shape is in
[`schema/analysis.schema.json`](../schema/analysis.schema.json).

**`MoreToDeclare`** is the loop's stopping condition. True means at least one
thing that stopped the run has a remedy, so running again with a fuller
declarations file could do better. False with `Blockers` still listed means the
rest need a change to the tool, and there is nothing to gain by trying again.

The full shape is [`schema/run.schema.json`](../schema/run.schema.json), and
what will and will not change under you is in
[`schema/README.md`](../schema/README.md).

### The one outcome that means "run me again"

`Protector` comes back `reactor-bootstrap` when the input was not a .NET file at
all, but native code with the assembly encrypted inside it. Such a run succeeds,
writes no `Cleaned` copy, reports no `Protections`, and puts exactly one entry in
`Payloads`. None of that is a failure: it is the whole result. What was recovered
is a protected assembly in its own right — usually much larger than the stub —
and it has not been analysed.

So branch on it. A pipeline that treats "no cleaned copy and no protections" as
nothing-to-see will throw away the only thing the run produced:

```python
run = unpack(path)
if run["Protector"] == "reactor-bootstrap":
    # Not a dead end. Feed the recovered assembly back in; it is the real sample.
    run = unpack(run["Payloads"][0]["WrittenTo"])
```

If the file is a bootstrap and the assembly could not be got out, the call fails
with a message beginning "is a .NET Reactor native bootstrap". That is worth
distinguishing from "is not a .NET assembly", which means the file was never
managed and there is nothing further to try.

## The loop

A sample that stops the run stops it somewhere nameable, and every stop that a
file could close says what to write:

```jsonc
{
  "Kind": "budget",
  "Key": "steps",
  "Detail": "Execution exhausted its 750000-step budget.",
  "Remedy": { "Section": "budgets", "Name": "steps", "Value": 1500000,
              "Wants": null, "Flag": null },
  "Declare": "\"budgets\": { \"steps\": 1500000 }"
}
```

`Remedy` is the half written for you. Applying one is
`declarations[Section][Name] = Value` and nothing else — no parsing, no
arithmetic, no rebuilding the object around it. `Declare` is the same statement
as a line of the file, for the summary and for a person; a program should use
`Remedy`.

The one thing to look at before applying is **`Wants`**:

| `Wants` | What it means |
| --- | --- |
| `null` | The tool knew the whole answer and wrote it. Apply as it stands. |
| a string | Only you can know this. `Value` holds a single `null` where your answer goes, and the string says what kind of value would be believed — `System.String` for a call, or just `value` for a host fact. |

`Flag` is `--allow-declared-calls` or nothing. Anything declared about somebody
else's code is ignored unless the run is given that switch, which is deliberate:
declaring what a call does is the one thing that puts a value into the reading
that no code produced.

A budget carries a figure already. That is a starting point rather than a
promise — the tool has no way of knowing how much further the sample had to go —
but it converges quickly if it converges at all. A step budget starts at
**10,000,000** and doubles from there; every other budget is simply **twice what
was refused**.

Steps get a floor because the ceilings they are refused at are often low, and
doubling out of a low one spends three or four whole runs arriving at a figure
that was predictable from the start. Naming a larger one costs nothing when it is
not reached, since steps are only spent as they are taken. Ten million covers a
module of roughly 4,000 protected methods, so one retry usually settles it.

Method-body recovery is the exception, and escalates on its own. It decides
whether any method body comes back at all, so a run that recovered nothing and
then asked to be run again with a larger number would be asking you to do
arithmetic the tool could do itself. It raises its own ceiling up to three times,
doubling each time, and says in its diagnostics that it did. You will not see a
budget stop from it unless the bootstrap is not merely large but non-terminating.

Every other budget stop is reported rather than acted on, and that is worth
knowing before you act on one. Measured on the largest sample on hand, every pass
that hit a step ceiling went on to succeed anyway, and raising all of them to the
figure that cleared the stops recovered **not one additional byte** while taking
roughly ten times as long. A budget stop from a pass whose `Status` is `success`
is a note about where an optional line of enquiry ran out, not a result being
withheld. Check the pass status before spending a run on one.

So the loop is:

1. Run with `--json`. Add `--strict` when the answer is going to be relied on;
   without it the run gets further by assuming a plausible machine, and says
   what it assumed.
2. If `Success` is true and you have what you came for, stop.
3. If `MoreToDeclare` is false, stop. What is left needs a change to the tool,
   and `Detail` and `Where` are what a bug report needs.
4. Otherwise apply the remedies you are willing to apply, answer the ones that
   want an answer, and run again with `--declarations`.

Each round should be cheaper than the last to reason about: stops are keyed by
what they are about, so the same list twice means nothing you did helped.

## Over MCP

The same thing, without the loop being yours to write. The server is in the
release archive beside the CLI, speaks over standard input and output, and is
pointed at the same way as any other:

```jsonc
{
  "mcpServers": {
    "cilantro": { "command": "/opt/cilantro/cilantro-mcp" }
  }
}
```

Six tools:

| Tool | What it does |
| --- | --- |
| `unpack` | Runs the pipeline on a file and returns the manifest above |
| `start_unpack` | The same run, started in the background, returning at once |
| `unpack_status` | How far a background run has got, and its manifest once done |
| `cancel_unpack` | Asks a background run to stop |
| `next_declarations` | Turns what stopped a run into the file to run with next |
| `read_output` | Reads back a report, a rename map, or a listing |

`next_declarations` is the loop's middle step done for you. Point it at the
blocker report, and it applies every remedy the tool can answer itself, hands
back under `Wanted` the ones only you can answer — each naming what it wants —
and tells you under `Beyond` what no file will close. It builds on the file you
were already using rather than replacing it, so rounds accumulate. It writes
nothing unless you pass `into`, and it runs nothing either way.

```jsonc
{
  "WrittenTo": "/work/suspicious.declarations.json",
  "Declarations": { "name": "suspicious", "budgets": { "steps": 1500000 } },
  "Applied": ["budgets.steps"],
  "Wanted": [],
  "Beyond": [{ "Kind": "threw", "Key": "System.InvalidCastException from ..." }],
  "Flags": [],
  "Advice": "Nothing is left to decide. Run again with this file, and expect what is
             under Beyond to stop it again: that needs a change to the tool."
}
```

`Advice` is the same judgement the loop above spells out, made for you and said
in a sentence: whether to answer something, whether to run again, or whether
this sample is as far as the tool goes.

Two differences from the command line are worth knowing. `unpack` does **not**
rebuild virtualized methods unless you ask, because on a sample that has them it
can cost minutes, and a pipeline working through a queue is paying a different price
for it than a person watching one run. And `read_output` will not hand back an
extracted payload: those are malware, and the manifest already names the path
and the hash so that something built to hold them can be pointed at the file.

## Runs that outlast the call

`unpack` returns when the pipeline finishes, which on a protected sample of any
size is minutes and can be ten. If your client gives up before then, the call is
killed with the analysis unfinished, and what it had left to write goes unwritten
— which is the expensive half, because payload extraction runs near the end. A
sample measured at six and a half minutes, killed at seven, cost 11,107 recovered
strings and five payloads, one of them the 3.86 MB assembly the sample existed to
carry. Nothing about the run was wrong; nobody was left to receive it.

So for anything that might take more than a minute or two, start it and ask:

```jsonc
// start_unpack — same arguments as unpack, returns immediately
{
  "StatusPath": "/work/reports/suspicious.status.json",
  "ReportDir": "/work/reports",
  "Advice": "Started. Poll unpack_status on statusPath every 10 to 15 seconds. ..."
}

// unpack_status — cheap, safe to call every few seconds
{
  "Run": {
    "Phase": "running",
    "Pass": "method-body-recovery",
    "PassesDone": 10,
    "PassesTotal": 40,
    "ElapsedSeconds": 132.4,
    "Ended": false,
    "Result": null
  },
  "Live": true,
  "SecondsSinceObserved": 1.2,
  "Stalled": false,
  "Advice": "Running method-body-recovery, 10 of 40 passes decided after 132s. ..."
}
```

`Phase` goes `starting`, `running`, then one of `finished`, `failed` or
`cancelled`; `Ended` is the same thing as one field. When it is `finished`,
`Run.Result` is the whole manifest, so the poll that sees the end needs no
further call.

Four things about it are worth knowing:

**The file is the contract, not the connection.** The status is on disk, beside
the reports and under the sample's stem, and `unpack_status` reads it. So a poll
that times out costs you nothing, a run started at the command line with
`--status` can be watched the same way, and nothing is lost by asking again.

**`Stalled` is how a killed run looks.** A run writes a heartbeat every few
seconds; when nothing has been written for a minute, the process is gone. Its
last phase would otherwise sit there looking current forever. Whatever it had
written is still in the report directory.

**A cancel is not immediate.** It takes effect at the end of the pass being run,
because that is where it is checked. That sounds coarse and is bounded: the
interpreter's step and allocation budgets stop any single pass from running
away, so the wait is the slowest pass rather than the whole run. A cancelled run
has no manifest and no cleaned copy — half a pipeline has nothing to claim —
though what reached disk stays there.

**The run lives in the server.** It survives a poll that times out. It does not
survive the server exiting, and there is no way to reattach to a run from a
previous server: `unpack_status` will show you the last thing it wrote and then
report it stalled.

Starting a second run into a report directory a live run is already using is
refused rather than allowed to interleave, whichever process owns the first one.

## Things worth doing

**Give each sample its own `--report-dir`.** Reports are named after the input
stem, so two samples with the same name in one directory overwrite each other's
reports.

**Keep the declarations file per sample, and keep it.** It is the record of what
your pipeline asserted, it is hashed into both reports, and a run that reproduces
an earlier answer needs it.

**Read `Strict` before believing a fact.** A triage run assumes a plausible
Windows machine and steps over calls it cannot read. Both are reported —
`HostProfile.Consulted` in the analysis report marks each fact as stated or
assumed, and `ContinuedPast` in the blocker report names each call walked past —
but a value that reached your database as fact should have come from a run that
did not have to invent anything.

**Treat an unknown `Kind` or `Status` as the conservative case.** Both
enumerations gain members; a reader that throws on one it has not seen turns a
new diagnostic into an outage.

**Do not run the cleaned copy.** It is the malware with its protection removed,
which is more dangerous than what you started with, not less.
