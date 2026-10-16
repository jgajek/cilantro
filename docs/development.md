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
2. Update the release notes and current support/gap statement. Describe the supported workflows and measured validation scope.
3. Build and test. Record which private-sample checks and benign runtime trials actually ran, including skips and inconclusive reconstruction checks.
4. Inspect default, verbose, strict, JSON, incomplete, native-wrapper, and embedded-child reporting. Keep reconstruction disagreement visible even when output was emitted.
5. Verify documentation links and package contents. Include the current docs and schemas so README links work after extraction.
6. Commit the reviewed tree and create the matching version tag when ready to publish. The release workflow builds Windows/Linux archives and their SHA-256 checksums.
7. Review release notes and downloaded assets before recommending the release to analysts. Do not turn pipeline success into a complete-unprotection claim.

Preparing a release is separate from publishing it. Source metadata now targets 1.0.0; this does not tag or publish a release. See the [1.0.0 preparation notes](releases/1.0.0.md).

## Preparing 1.0.0

Treat 1.0.0 as a release-readiness milestone, not a claim of universal deprotection. Before publishing:

- Validate the documented first-run commands against both packaged platforms, including spaces in paths and a fresh case directory.
- Check wrapper/child recommendations, partial recovery, generic recovery, analysis-only, strict mode, reviewed dependencies and long-run status behavior.
- Verify the CLI and MCP defaults are documented separately, and test JSON/error schemas and exit codes used by analyst integrations.
- Keep the frozen-corpus result explicit. State any additional samples or changed validation scope and measure the candidate build.
- Check all packaged documentation links. Ship the current analyst guides and reference material; local-only evidence files must not be presented as downloads.
- Review release notes and compatibility claims for an analyst who has never read implementation details. Run the release checklist above before tagging.

These are preparation checks, not a claim that the future 1.0.0 binaries have already passed them.
