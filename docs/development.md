# Build, test, and release

## Build from source

Install the .NET 10 SDK, then run:

```text
dotnet restore Cilantro.slnx
dotnet build Cilantro.slnx -c Release --no-restore
dotnet test Cilantro.slnx -c Release --no-restore --no-build
dotnet run --project src/Cilantro.Cli -c Release --no-build -- --help
```

Release configuration matters for interpreter performance. For a short edit/test cycle, add `--filter "Cost!=High"` to the test command. For release validation, run the full available suite and account for sample-dependent skips. Use [corpus gates](corpus.md) and the [benign probe harness](../corpus/probes/README.md) for recovery changes.

Do not execute malware to test the tool. Static recovery, report inspection, hashes, and decompiler checks can operate on the malware corpus; executable behavioral trials use the benign source-built probes.

## Publish locally

```text
dotnet publish src/Cilantro.Cli -c Release -r win-x64 -p:PublishSingleFile=true -o artifacts/publish/win-x64
dotnet publish src/Cilantro.Mcp -c Release -r win-x64 -p:PublishSingleFile=true -o artifacts/publish/win-x64
```

Use `linux-x64` for the Linux archive. The single-file property enables self-contained publishing in each project. Test `--version`, `--help`, an ordinary run, and JSON/error output from the published CLI on its target platform. Both executables belong in each release archive, with licence and documentation.
