# Virtualized methods

Reactor can replace a method with bytecode for a custom interpreter embedded in the assembly. Decrypting ordinary method bodies does not restore that method: the program now exists in a different instruction set.

CILantro decodes supported VM programs, investigates their operations, and reconstructs supported programs as CIL. The resulting assembly can be opened in a .NET decompiler. These bodies are interpretations of VM behavior, not recovered original source.

## What is written

- A `.vmprogram.txt` listing records decoded operations, operands, observations, and unresolved semantics.
- A `.lifted.il` listing shows the inferred CIL-level operations and graph information.
- With reconstruction enabled, supported methods are emitted into the cleaned assembly with `[RebuiltFromReading]` markers. Additional interpreter programs can become helper methods.
- The report records reconstructed counts, coverage, comparisons, and remaining issues.

Ordinary CLI runs enable reconstruction. `--no-devirtualize` disables rebuilding while still allowing disassembly. Strict CLI runs require explicit `--devirtualize`. MCP defaults reconstruction off; set `devirtualize: true` explicitly.

## How the reading is established

The tool interprets the sample's decoder to recover programs, observes handlers with controlled values and in program context, resolves metadata operands, and checks the inferred control-flow graph and stack depths. Supported exception regions and local types are reconstructed where the evidence supports them. Cleanup then simplifies the rebuilt bodies.

A stack-consistent graph is useful evidence, not behavioral proof. An operation's stack effect alone does not establish its semantics. Operations that remain unresolved can prevent reconstruction; unreachable regions may retain fail-fast placeholders rather than invented implementations.

## How to judge the result

Read **Validation** and **Needs review** before treating a reconstructed body as reliable. The detailed evidence distinguishes two forms of comparison:

| Comparison | What it checks | What it does not prove |
| --- | --- | --- |
| Payload comparison | Original and reconstructed paths produce the same extracted bytes in bounded interpretation | Every VM method was exercised or all application behavior agrees |
| Controlled method trials | Selected input/state combinations have matching observable outcomes | All inputs, complete external state, or native runtime behavior |

An `agreed` verdict is limited to the checks and coverage described. `notMade` includes inconclusive comparisons, such as unsupported state or unexercised bodies. `disagreed` requires investigation even if structural verification and the overall run succeeded.

For example, the current Mlfhntkcvb trial differs when a debugger-present fact is supplied: the original throws and the reconstruction completes. This could involve removal of a protection check, but it has not established equivalent application behavior. The release presents this as a qualification, not as a successful proof.

## Remaining limits

Complex exception paths, reflection, unknown state, and sample-specific handlers can prevent complete lifting or validation. “No direct callers” does not exclude reflective calls. A remaining dispatcher is not necessarily a protection artifact, and a decompiler's readable C# is not the original source.

Use the [output guide](reading-the-output.md) to locate evidence, [compatibility](compatibility.md) for release boundaries, and [historical research](history/pre-0.10/devirtualization.md) for earlier implementation experiments.
