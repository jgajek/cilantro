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
| `suspicious.payloads/` | Files that were hidden inside the sample |
| `suspicious.virtualized/` | One listing per method that was turned into interpreter bytecode |
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

Two categories in `Evidence` are worth knowing. `capability` entries are the
protections that were detected, and they are what the summary turns into English.
`metadata-anomaly` entries are the deliberate metadata damage Reactor introduces
to break tools — useful for detection rules.

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
are bytecode for a custom interpreter and no tool will decompile them. Look in
`suspicious.virtualized/` — there is a listing per affected method. The
operation numbers are that build's own and mean nothing anywhere else, but the
listing tells you two useful things about them. Every operand that is a
reference into the assembly is named, so a listing mentioning `CryptoStream` and
a `CipherMode` is telling you what the method does even though you cannot read
how. And a header explains what each operation was found to do — `add`, `xor`,
`dup`, reading and writing array elements and so on where that could be
established, and otherwise just how many values it consumed and produced, and
what it insisted on being handed. Operations that could not be established are
left unnamed rather than guessed at, and the header says why each one was left
alone.

Jumps are marked on the lines that make them, so you can follow the shape of the
method even without reading it. `-> 1840` means the interpreter really was
watched going there. `~> 1840` means it was not, on this run, but every jump of
that kind that was watched went to the number the operation carries, so this one
is read the same way. A loop, an early exit, or a switch with a hundred arms is
visible from those markings alone.

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
