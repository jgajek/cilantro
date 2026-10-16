# CILantro

<p align="center">
  <img src="docs/assets/cilantro-flow-lockup.png" alt="CILantro Flow logo: a cilantro leaf with branching recovery paths above the CILantro wordmark" width="320">
</p>

Recover readable .NET assemblies and embedded payloads from supported **.NET Reactor and ConfuserEx** samples, without launching the sample or loading its code into the host CLR.

CILantro interprets the sample's own decoding and unpacking logic in a bounded model. That lets it recover encrypted methods and strings, reconstruct supported Reactor VM programs as ordinary CIL, unflatten protector control flow, resolve indirect calls, and remove attributable protector infrastructure. For an analyst, the result is a cleaned assembly to open in a decompiler, extracted stages with hashes and provenance, and an offline report explaining what was recovered and what needs review.

## Start with a sample

Download the Windows x64 or Linux x64 archive from [Releases](https://github.com/jgajek/cilantro/releases). Both contain the CLI and MCP server and run without a separately installed .NET runtime. Compare the archive's SHA-256 with `SHA256SUMS.txt` before unpacking.

From PowerShell in the unpacked tool directory:

```powershell
.\cilantro.exe C:\cases\sample.exe --recover-embedded --report-dir C:\cases\run-01 --output C:\cases\run-01\cleaned.exe --status
```

On Linux:

```sh
./cilantro /cases/sample.exe --recover-embedded --report-dir /cases/run-01 --output /cases/run-01/cleaned.exe --status
```

Follow **Open** in the summary to the recommended assembly and HTML report. Open the assembly in your .NET decompiler, then inspect the artifact tree and **Needs review**, **Remaining**, and **Validation**. A dropper's most useful output may be a cleaned child rather than the cleaned input.

The console opens with the Reveal banner and streams analysis phases and pass outcomes, followed by a result summary and artifact paths. Interactive terminals use green, cyan, amber and red to distinguish results, progress and review items. Use `--no-color` or `NO_COLOR` for plain text; redirected output is plain automatically. `--json` emits only the machine-readable run/error object.

Use a new output directory for each trial. The original input is preserved; extracted original bytes and cleaned child copies are distinct. Outputs remain malware artifacts: recovery does not make them safe to execute.

## What you get

| Analyst task | CILantro's contribution |
| --- | --- |
| Read protected application logic | Restored method bodies and strings; supported VM methods rebuilt into CIL; simpler control flow and explicit call targets |
| Get past the wrapper | Supported native bootstrap recovery and recursive managed-stage recovery, with parent-child provenance |
| Extract embedded content | Managed assemblies, supported resource entries and dependencies, with hashes and recorded extraction paths |
| Reduce decompiler noise | Protector-code/resource removal, recovered types, readable replacement names and late branch cleanup |
| Understand the result | Offline HTML report, change/rename maps, VM listings, remaining-work diagnostics and structural/reconstruction evidence |
| Integrate with a case pipeline | JSON stdout, status files, documented exit codes and a stdio MCP server |

CILantro does not identify a malware family, automatically decode every family's configuration, fetch downloaded stages, or recreate the original source project. Native payload extraction is distinct from native-code decompilation.

## Support and confidence

This tree is being prepared for **1.0.0**; see the [release preparation notes](docs/releases/1.0.0.md). The **0.10.6** full-unprotection completion decision applies to a frozen validation corpus: **43 roots accounted for**, including **28 undamaged captured Reactor-tagged samples**, with physical VM-removal checks covering **14 intact virtualized identities**. The corpus includes negative controls and cases using explicit generic recovery; these are not 43 independent protected malware families. Those measurements describe that validation build; the 1.0.0 release gates must be run before publishing.

Coverage includes real-world Reactor 6 samples, Reactor 7.5 source-built probes, and two pinned ConfuserEx samples. It depends on the protection implementation and options, not just a version label. Completion on that corpus is not a guarantee for a new file.

For each new case, read the result's qualifications. `Success` means the configured run succeeded; `Verified` means structural checks passed. Neither is a universal behavior or full-unprotection verdict. Application switches, required initialization calls and bundled libraries can legitimately survive cleanup. [Support and limitations](docs/compatibility.md) explains the distinction.

## Choose your workflow

- [First run and CLI options](docs/quick-start.md)
- [Investigate a dropper and its payloads](docs/analyst-workflows.md)
- [Choose the right artifact and interpret the report](docs/reading-the-output.md)
- [Resolve incomplete recovery and decompiler problems](docs/troubleshooting.md)
- [Use JSON, scripts or MCP](docs/agents.md)
- [Complete documentation index](docs/README.md)
- [0.10.6 release notes](docs/releases/0.10.6.md) and [current corpus status](docs/status-report.md)

## Report a recovery problem

Include the tool version, input SHA-256, command line, whether the input is original or already rewritten, and the affected method or child artifact. Attach relevant diagnostics after reviewing them for embedded secrets and case-sensitive information. Do not post malware binaries in public issues. See the [bug-report checklist](docs/troubleshooting.md#report-a-reproducible-problem).

Building from source requires the .NET 10 SDK; see [development](docs/development.md). CILantro is MIT-licensed; see [LICENSE](LICENSE). It uses [dnlib](https://github.com/0xd4d/dnlib) and is independent of Eziriz, ConfuserEx and other recovery tools.
