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

## Release checklist

1. Reconcile `Directory.Build.props`, `CilantroPipeline.Version`, and the intended tag. `ReleaseMetadataTests` checks compiled metadata against the reported version.
2. Update the release notes and current support/gap statement. Keep old experiments in history rather than presenting them as current guarantees.
3. Build and test. Record which private-sample checks and benign runtime trials actually ran, including skips and inconclusive reconstruction checks.
4. Inspect default, verbose, strict, JSON, incomplete, native-wrapper, and embedded-child reporting. Keep reconstruction disagreement visible even when output was emitted.
5. Verify documentation links and package contents. Include the current docs and schemas so README links work after extraction.
6. Commit the reviewed tree and create the matching version tag when ready to publish. The release workflow builds Windows/Linux archives and their SHA-256 checksums.
7. Review release notes and downloaded assets before recommending the release to analysts. Do not turn pipeline success into a complete-unprotection claim.

Preparing a release is separate from publishing it. Version 0.10.3 is a regular release with documented recovery limits. See [the release notes](releases/0.10.3.md).
