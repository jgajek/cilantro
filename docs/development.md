# Build and validate a change

Use this contributor guide to build a local CLI/MCP pair and choose checks for your change. Routine malware analysis uses the published executables; see the [quick start](quick-start.md).

## Build from source

Install the .NET 10 SDK, then run:

```text
dotnet restore Cilantro.slnx
dotnet build Cilantro.slnx -c Release --no-restore
dotnet test Cilantro.slnx -c Release --no-restore --no-build
dotnet run --project src/Cilantro.Cli -c Release --no-build -- --help
```

Release configuration matters for interpreter performance. For a short edit/test cycle, add `--filter "Cost!=High"` to the test command. For release validation, run the full available suite and account for sample-dependent skips. Use [corpus gates](corpus.md) and the [benign probe harness](../corpus/probes/README.md) for recovery changes.

For performance changes, use the [corpus timing and output comparison workflow](performance.md).

Do not execute malware to test the tool. Static recovery, report inspection, hashes, and decompiler checks can operate on the malware corpus; executable behavioral trials use the benign source-built probes.

## Publish locally

```text
dotnet publish src/Cilantro.Cli -c Release -r win-x64 -p:PublishSingleFile=true -o artifacts/publish/win-x64
dotnet publish src/Cilantro.Mcp -c Release -r win-x64 -p:PublishSingleFile=true -o artifacts/publish/win-x64
```

Use `linux-x64` or `linux-arm64` for Linux, and `osx-arm64` (Apple Silicon) or `osx-x64` (Intel) for macOS. The single-file property enables self-contained publishing in each project. Test `--version`, `--help`, an ordinary run, and JSON/error output from the published CLI on its target platform. Both executables belong in each release archive, with licence and documentation. The release workflow builds and smoke-tests each Linux/macOS archive on a native runner, including a benign probe recovery and MCP initialization.

## Write documentation for its reader

Analyst guides should start with a case question, explain how the protection hides the behavior, show the recovered code or artifact, and give a useful next step. Keep necessary scope qualifications together and link implementation rules, method identities and reproduction details from a reference appendix. Label captured output, reconstructed checkpoints and illustrative code accurately.

Contributor and automation pages should lead with the task they support, then preserve the exact commands, field names and checks needed to carry it out. Keep historical experiments out of current usage instructions.
