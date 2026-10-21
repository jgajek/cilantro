# CILantro

<p align="center">
  <img src="docs/assets/cilantro-flow-lockup.png" alt="CILantro logo" width="320">
</p>

CILantro is a **.NET deobfuscator and unpacker for malware analysts and reverse engineers**. It removes protection added by **.NET Reactor, ConfuserEx, Babel .NET and Dotfuscator** so you can read the program in ILSpy or dnSpyEx and follow what it does.

It decrypts strings and constants, restores encrypted methods, simplifies control flow, resolves hidden call targets and extracts embedded payloads. It also converts Reactor virtualized methods back into code that a .NET decompiler can read. Use it to expose a concealed process launcher, follow a loader into its next stage or inspect a protected command handler.

Give it an EXE or DLL. You get cleaned assemblies, extracted stages and an offline report showing what changed and what still needs investigation. **Analysis does not run the sample or load its code into the host .NET runtime.** See [before-and-after malware examples](docs/protection-removal.md) and [protector coverage](docs/compatibility.md).

## Recover a sample

Download the Windows x64, Linux x64/ARM64 or macOS Apple Silicon/Intel archive from [Releases](https://github.com/jgajek/cilantro/releases), check it against `SHA256SUMS.txt` and unpack it. Each archive includes the CLI and MCP server; no separate .NET installation is needed.

On Windows:

```powershell
.\cilantro.exe C:\cases\sample.exe
```

On Linux:

```sh
./cilantro /cases/sample.exe
```

CILantro follows embedded managed stages and writes a new case folder beside the sample. Add `-o DIR` to choose a new or empty output folder.

Follow **OUTPUT** to the recommended assembly and HTML report. Open the assembly in your decompiler, then inspect **NEEDS REVIEW** and **REMAINING**. For a dropper, the behavior you need may be in a cleaned child DLL. Extracted originals, hashes, change maps and rename maps let you trace the result back to its input.

## What it recovers

| Protection | Analyst result |
| --- | --- |
| Encrypted methods, strings and numeric values | Readable code and values where the program uses them. |
| Reactor virtualization | Reconstructed methods you can decompile. |
| Flattened control flow and hidden calls | Simpler branches and explicit call targets. |
| Native wrappers and embedded stages | Extracted assemblies with hashes and source relationships. |
| Encrypted resources and bundled dependencies | Recovered application data and deployed dependency DLLs. |
| Debugging, integrity and root checks | Removed protection checks while retaining application notifications. |
| Obsolete protector code | Less generated machinery obscuring the application. |

Coverage includes ConfuserEx 1.0.0 and ConfuserEx 2 (mkaring 1.6.0) constants, resources, proxies, anti-tamper and compressor payloads; Babel 12.1 method encryption and all seven cipher choices; and Dotfuscator 7.9 managed and native-key v2 strings. The [compatibility guide](docs/compatibility.md) lists versions, required files and limits.

## Useful options

| Task | Option |
| --- | --- |
| Choose the case folder | `-o DIR` |
| Extract and report without writing cleaned assemblies | `--analyze-only` |
| Collect results in a script | `--json` |
| Investigate recovery diagnostics | `--verbose` |
| Compare recovery without implicit host assumptions | `--strict` |
| Supply Babel external method data | `--babel-code-source FILE` |
| Re-sign cleaned assemblies with your key | `--signing-key key.snk` |

`--help` covers common workflows; `--help-all` lists every option. See the [CLI reference](docs/quick-start.md) for output files and exit codes, or [JSON and MCP automation](docs/agents.md) for scripted and agent-assisted analysis.

## Assess the result

Start from an untouched protected input and keep its companion files. Read the report before treating a recovered path as complete: unknown decoders, missing data and damaged inputs can leave work unresolved. Cleaned malware remains malware; a successful structural check does not establish that it is safe to execute.

CILantro does not identify malware families, fetch remote stages or recreate the original source project. See the [validation results](docs/status-report.md) and [1.0.6 release notes](docs/releases/1.0.6.md) for the tested scope.

## Continue the investigation

- [Follow a dropper into its payload](docs/analyst-workflows.md).
- [Read the report and choose the right artifact](docs/reading-the-output.md).
- [Inspect virtualized methods](docs/devirtualization.md).
- [Troubleshoot or report a recovery problem](docs/troubleshooting.md).
- [Browse the documentation](docs/README.md).

When reporting a problem, include the version, input SHA-256, command and affected method or artifact. Review reports for private case data before sharing; do not post malware binaries in public issues.

Contributors need the .NET 10 SDK; see [development](docs/development.md). CILantro is [MIT-licensed](LICENSE), uses [dnlib](https://github.com/0xd4d/dnlib), and is independent of the protector vendors.
