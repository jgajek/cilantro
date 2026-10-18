# CILantro

<p align="center">
  <img src="docs/assets/cilantro-flow-lockup.png" alt="CILantro Flow logo: a cilantro leaf with branching recovery paths above the CILantro wordmark" width="320">
</p>

Recover readable .NET code and embedded payloads from supported **.NET Reactor, ConfuserEx and Babel .NET** protection layers. See the [support guide](docs/compatibility.md) for the supported features and sample evidence.

A protected method can hide a PowerShell launcher behind an empty-looking stub. A loader can disguise `Assembly.Load` behind a proxy and encrypt the type and method it invokes next. CILantro works through supported protection layers so you can follow that behavior in a .NET decompiler.

It also **lifts supported Reactor VM bytecode into CIL and reconstructs method bodies**, making those programs available for decompilation. See the [before-and-after malware walkthrough](docs/protection-removal.md) for VM reconstruction, hidden process execution, in-memory loading and command handling.

**Babel .NET recovery** includes generated strings, numeric tables, token-bound delegate adapters and encrypted/compressed resource streams, including supported layers wrapped by Reactor.

Recovery uses a bounded interpreter. It does not launch the sample or load its code into the host CLR.

## Recover a sample

Download and unpack the Windows x64 or Linux x64 archive from [Releases](https://github.com/jgajek/cilantro/releases). Both include the CLI and MCP server without requiring a separately installed .NET runtime. Check the archive against `SHA256SUMS.txt`.

From the unpacked directory on Windows:

```powershell
.\cilantro.exe C:\cases\sample.exe
```

On Linux:

```sh
./cilantro /cases/sample.exe
```

The normal run recovers the input, follows embedded managed stages and writes a fresh case folder beside the sample. Use `-o C:\cases\run-01` or `-o /cases/run-01` to choose a new or empty folder.

When the run finishes, follow **OUTPUT** to the recommended assembly and HTML report. Open the assembly in ILSpy or dnSpyEx, then read **NEEDS REVIEW** and **REMAINING** for that artifact. For a dropper, the useful code may be in a cleaned child DLL rather than the outer file.

## What becomes visible?

| What hides the behavior | What recovery gives the analyst |
| --- | --- |
| Encrypted method bodies and strings | Readable instructions and values at their use sites. |
| VM bytecode and an interpreter stub | Supported programs lifted into CIL and reconstructed for decompilation. |
| Flattened control flow | Ordinary branches after established dispatcher transitions are resolved. |
| Proxy calls | Explicit call targets such as `Assembly.Load(byte[])`. |
| Native wrappers and encrypted embedded content | Extracted stages with hashes and links to their source. |
| Protector support code | A clearer application after obsolete, attributable machinery is removed. |

Each case includes an offline report, extracted originals, cleaned assemblies where recovery permits them, change and rename maps, and any VM listings. Keep these together so you can trace a recovered method or stage back to its input.

## Choose an option for a specific task

| Task | Option |
| --- | --- |
| Choose a case folder | `-o DIR` |
| Extract and report without writing cleaned assemblies | `--analyze-only` |
| Compare a run without implicit host assumptions | `--strict` |
| Collect results in a script | `--json` |
| Investigate detailed recovery diagnostics | `--verbose` |
| Use plain console text | `--no-color` |

`--help` covers common workflows; `--help-all` lists specialist controls. The [CLI reference](docs/quick-start.md) explains each option, output folders and exit codes. Interactive output includes the cilantro-leaf banner, analysis progress and artifact paths; redirected output is plain text automatically.

## Understand the result

CILantro supports specific protection implementations and configurations. A successful run means its configured policy was met; structural verification checks metadata and CIL. Read the report's remaining work and reconstruction comparisons before drawing a conclusion about a particular path.

The tool does not identify malware families, fetch downloaded stages or recreate the original source project. Recovery outputs remain malware artifacts. The [support guide](docs/compatibility.md) explains coverage, and the [validation report](docs/status-report.md) records the corpus and release checks. Current release notes: [1.0.3](docs/releases/1.0.3.md).

## Continue the investigation

- [See real malware before and after recovery](docs/protection-removal.md).
- [Follow a dropper into its payload](docs/analyst-workflows.md).
- [Choose the right artifact and read the report](docs/reading-the-output.md).
- [Inspect VM-protected methods](docs/devirtualization.md).
- [Troubleshoot incomplete recovery](docs/troubleshooting.md).
- [Automate cases with JSON or MCP](docs/agents.md).
- [Browse the documentation](docs/README.md).

## Report a recovery problem

Include the tool version, input SHA-256, exact command, affected artifact/method and relevant diagnostics. Identify whether the input is untouched, extracted or previously rewritten. Review reports for private case data before sharing; do not post malware binaries in public issues. See the [reporting guide](docs/troubleshooting.md#report-a-reproducible-problem).

Contributors need the .NET 10 SDK; see [development](docs/development.md). CILantro is [MIT-licensed](LICENSE), uses [dnlib](https://github.com/0xd4d/dnlib), and is independent of Eziriz, Babel, ConfuserEx and other recovery tools.
