# CILantro

Recover readable .NET code and embedded assemblies from supported **.NET Reactor and ConfuserEx** samples, without executing the sample.

CILantro restores encrypted method bodies and strings, simplifies obfuscated code, extracts supported embedded stages, and produces an offline HTML report. Supported Reactor virtualized methods can be reconstructed into CIL for inspection in a decompiler.

**0.10.0 is an analyst preview.** A cleaned file is an analysis artifact, not a claim of complete unprotection or behavioral equivalence. The report separates structural checks, reconstruction comparisons, assumptions, and remaining work.

## Install

Download the Windows x64 or Linux x64 archive from [GitHub Releases](https://github.com/jgajek/CILantro/releases), unpack it, and verify it against the accompanying `SHA256SUMS.txt`. Release archives contain self-contained `cilantro` and `cilantro-mcp` executables; no separate .NET runtime is required. Building from source requires the .NET 10 SDK.

```powershell
Get-FileHash .\cilantro-win-x64.zip -Algorithm SHA256
.\cilantro.exe --version
```

## Recover a sample

```text
cilantro suspicious.exe --recover-embedded
```

Start with the **Open** section of the summary. It points to the recommended recovered assembly and the HTML report. Open the assembly in ILSpy or dnSpyEx, then read **Needs review**, **Remaining**, and **Validation** before relying on reconstructed code.

By default, the cleaned input is written beside the original as `suspicious.cleaned.exe`. Reports and extracted files go into a `cilantro/` directory beside the input. If that name is already a file, the directory is `cilantro.out/`. The input is preserved. Use a separate report directory for each case or repeat trial.

`--recover-embedded` also cleans extracted managed assemblies, within traversal limits. Supported Reactor native wrappers automatically continue into their managed stage, even without this option. Extracted originals and cleaned copies remain separate.

```text
cilantro suspicious.exe --report-dir case-output --output case-output/cleaned.exe
cilantro suspicious.exe --analyze-only
cilantro suspicious.exe --strict
cilantro suspicious.exe --json --status
```

`--analyze-only` suppresses the cleaned assembly; it still writes reports and extracted artifacts. `--strict` disables implicit host assumptions and permissive interpretation, and defaults renaming and VM reconstruction off. It still performs recovery and may write a cleaned copy.

## What it can recover

| Capability | What the analyst gets |
| --- | --- |
| Method and string recovery | Restored CIL bodies and readable literals for supported protections |
| Readability | Simpler branches, explicit call targets, recovered constants, reduced protector code, and readable replacement names |
| Embedded stages | Extracted assemblies and dependencies, hashes, parent-child provenance, and optional recursive cleanup |
| Native wrappers | Static extraction and managed recovery for the supported Reactor bootstrap shape |
| Virtualization | Listings and supported reconstructed methods, with explicit validation limits |
| Reporting and automation | Offline HTML, JSON reports, machine-readable stdout, status files, and MCP |

Recovery statically interprets supported instructions and modeled APIs. It does not launch the sample or invoke its code through the host CLR. The default interpretation can use assumed host facts and continue past some unsupported calls; these are recorded. Outputs are still malware artifacts, and static analysis is not a security guarantee for the parser or the tools used to open them.

## Limits that matter

- Support is configuration-dependent. Reactor 6 real-world samples, Reactor 7.5 benign probes, and a small ConfuserEx corpus establish the current coverage; they do not establish universal version support.
- Some control flow and protector infrastructure remain, particularly around reflection, numeric metadata tokens, and complex VM paths.
- A successful run and structural verification do not establish equivalent behavior. Reconstruction checks can agree, disagree, or remain inconclusive.
- Extraction is not exhaustive. Downloaded stages are not fetched, and unsupported decoding paths can leave embedded content behind.
- Renaming creates useful labels; it cannot restore deleted source names, comments, or the original source project.

Read the [support and limitations](docs/compatibility.md) before adopting CILantro in a production analysis workflow.

## Documentation

- [Analyst quick start and CLI reference](docs/quick-start.md)
- [Understanding the output](docs/reading-the-output.md)
- [Support, validation, and known gaps](docs/compatibility.md)
- [Automation and MCP](docs/agents.md)
- [Build, test, and release](docs/development.md)
- [Complete documentation index](docs/README.md)
- [0.10.0 release notes](docs/releases/0.10.0.md)

## Contributing and licence

Report the tool version, sample SHA-256, command line, and relevant report diagnostics. Describe expected and observed behavior. Do not place malware binaries in public issues; arrange sample sharing separately.

MIT; see [LICENSE](LICENSE). CILantro uses [dnlib](https://github.com/0xd4d/dnlib). It is independent of Eziriz, ConfuserEx, and other recovery tools, and is not endorsed by them.
