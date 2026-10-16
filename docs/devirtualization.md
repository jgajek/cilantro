# Read VM-protected methods

A method that only packages arguments and calls an unfamiliar interpreter may be virtualized. Its real program is stored as custom bytecode, so opening the original assembly in ILSpy does not reveal the method's normal .NET instructions.

CILantro can lift supported Reactor VM operations into CIL and reconstruct the method in an assembly. Start with the [Qbjuef before-and-after example](protection-removal.md#net-reactor) to see the protected stub, reconstructed instructions and decompiled C#.

## Recover a virtualized sample

Ordinary CLI runs enable supported VM reconstruction:

```text
cilantro sample.exe -o case/vm-recovery
```

Follow **OUTPUT** to the recommended assembly and report. Open the assembly in a .NET decompiler, then use the report and name map to locate the method you are investigating.

A surviving reconstructed method can carry `[RebuiltFromReading]`. This means CILantro translated a VM program into CIL; it is different from restoring original encrypted instructions.

Some VM programs belong to the protector's support machinery. If recovery replaces their work, the cleaned output can remove them and the original VM. The report records that removal. In the Qbjuef example, the decompiled decoding routine is shown at a checkpoint before this cleanup.

## Understand lifting and reconstruction

**Lifting** establishes what the VM's operations do and expresses them as CIL-level operations: load a value, call a method, write an array element, or take a branch.

**Reconstruction** turns those operations into a .NET method body with control flow, locals and supported exception handling. Later cleanup simplifies that body for reading.

For the analyst, the payoff is being able to follow calls, constants and branches in a .NET decompiler instead of manually translating the VM's dispatcher and handlers. The reconstruction remains an analysis of the VM program, rather than the original source code.

## Choose the right file

| File or view | What to use it for |
| --- | --- |
| Cleaned assembly | Read surviving reconstructed application methods alongside the rest of the program. |
| `.vmprogram.txt` | Examine decoded VM operations, operands and observations. Operation numbers belong to that particular VM build. |
| `.lifted.il` | Follow the inferred CIL-level operations and control-flow graph. |
| HTML report and analysis JSON | Review reconstructed counts, comparisons, remaining issues and removal records. |
| Rename map | Connect an original identifier to its replacement name. |

Use the paths recorded in the report. Listing text is an analysis aid; the cleaned assembly is the emitted artifact to open in the decompiler.

## Read a reconstruction comparison

The report can compare an original VM-backed method with the reconstructed path using controlled inputs. Check what was exercised before using the verdict.

| Result | Meaning for your investigation | Next step |
| --- | --- | --- |
| `agreed` | The captured observations matched in the stated trials. | Check the trial inputs and coverage against the behavior you are investigating. |
| `disagreed` | At least one captured observation differed. | Read the first differing state or outcome and inspect the affected code. |
| `notMade` or an inconclusive detail | The comparison did not establish agreement. | Look for an unsupported operation, missing fact, unexercised path or budget limit. |

**Example:** a decoder may work after its original initializer has filled a cache, but behave differently from a cold start. An agreement after that warm-up answers a narrower question than a startup comparison. The report retains those results separately so you can see the difference.

A difference in removed protector state can explain a disagreement, but it should be checked against the application behavior in your case. Matching a controlled trial does not cover every argument, host setting or callback.

## Compare the original protected structure

Use separate folders when changing a recovery option:

```text
cilantro sample.exe -o case/rebuilt
cilantro sample.exe --no-devirtualize -o case/vm-stubs
```

`--no-devirtualize` leaves VM-backed stubs in place while still allowing supported listings to be written. Use `--keep-runtime` when investigating protector support code. `--strict` also leaves VM stubs and names unchanged and changes the interpretation policy; it is a broader comparison than disabling reconstruction alone.

MCP has its own defaults: set `devirtualize: true` explicitly. See [automation and MCP](agents.md).

## When the method remains unreadable

Check whether the report found a VM program, established its operations, rebuilt the body and wrote a cleaned output. These are different stages, and the diagnostic at the first unfinished stage is usually the useful one.

Unknown operations, unresolved metadata, missing environment facts and budget limits can prevent reconstruction. A decompiler error after emission should be investigated at the affected CIL location. Keep the input hash, output hash and relevant listing when reporting it; see [troubleshooting](troubleshooting.md#report-a-reproducible-problem).

## Detailed comparison and validation reference

For investigation of a particular verdict, the [VM validation reference](assets/vm-validation-reference.md) explains cold-start, warm-up, independently evolved, module-initialization and callback trials, captured state and comparison budgets. Contributors should also run the [reconstruction and removal gates](corpus.md#reconstruction-cleanup-gates).
