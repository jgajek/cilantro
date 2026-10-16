# Corpus validation

This contributor reference describes the pinned fixtures and checks used to validate recovery. For an analyst case, start with [analyst workflows](analyst-workflows.md); for coverage and its limits, see [validation scope](status-report.md).

Manifests contain SHA-256 identities, protection expectations and assertions. Malware binaries are not distributed with the repository. Each gate checks its stated assertions; it does not establish exhaustive extraction or arbitrary behavior equivalence.

| Manifest | Scope |
| --- | --- |
| [Reactor 6](../corpus/reactor-6-nonvirt.manifest.json) | Real-world inputs, recovered stages, native wrappers and validation oracles |
| [Reactor 7.5](../corpus/reactor-7-static.manifest.json) | Source-built benign probes with pinned protected and unprotected identities |
| [ConfuserEx](../corpus/confuserex-1-static.manifest.json) | Two whole-section anti-tamper samples |

Read each manifest's expectations rather than inferring coverage from its filename.

## Run the static gates

Build the CLI and supply matching samples:

```text
dotnet build Cilantro.slnx -c Release
dotnet run --project src/Cilantro.Cli -c Release --no-build -- corpus run --manifest corpus/reactor-6-nonvirt.manifest.json --samples samples --output artifacts/corpus/reactor6
dotnet run --project src/Cilantro.Cli -c Release --no-build -- corpus run --manifest corpus/reactor-7-static.manifest.json --samples samples --output artifacts/corpus/reactor7
dotnet run --project src/Cilantro.Cli -c Release --no-build -- corpus run --manifest corpus/confuserex-1-static.manifest.json --samples samples --output artifacts/corpus/confuserex
```

Use isolated output directories. The runner validates identities and writes `corpus.outcomes.json`; missing inputs are distinct from failed assertions. Entries can select analysis-only or feature-specific policies. Passing a manifest does not test every combination of options.

`minimumRecoveredStringSites` gates the total of constant-folded and table/lookup-restored string sites. `minimumConstantStringSites` targets constant folding specifically. A replacement may retain an initialization call to preserve its effects; read pass diagnostics before treating a retained call as failed recovery.

## Reconstruction cleanup gates

The corpus runner disables reconstruction. Test ordinary CLI reconstruction separately with matching pinned inputs and declarations:

```powershell
New-Item -ItemType Directory -Force results | Out-Null
cilantro C:/cilantro-verify/samples/Qbjuef.exe --declarations corpus/reconstruction.declarations.json -o results/qbjuef-case --json > results/qbjuef-run.json
cilantro C:/cilantro-verify/samples/Mlfhntkcvb.payload.Lqcuzgc.dll --declarations corpus/reconstruction.declarations.json -o results/mlfhntkcvb-case --json > results/mlfhntkcvb-run.json
pwsh -NoProfile -File corpus/verify-reconstruction.ps1 -ReportDirectory results
pwsh -NoProfile -File corpus/verify-vm-removal.ps1 -RunPath results/qbjuef-run.json -ToolDirectory src/Cilantro.Cli/bin/Release/net10.0
```

The reconstruction gate checks pinned identities, structural verification, rebuilt methods/helpers, runtime removal, captured payload hashes and comparison evidence. Preserve raw disagreements alongside supplementary application-state evidence; do not turn a qualified comparison into full equivalence.

The physical-removal gate reads original and cleaned metadata, follows recorded renames and rejects retained VM declarations, unexplained missing reconstructed bodies or resources claimed removed but still present. A rebuilt body must survive with its marker and CIL body or have a narrowly attributed protector-retirement record. Unrelated deletion records cannot compensate for missing application code. This gate does not execute the sample.

Generated benign fixtures exercise preserved/renamed bodies, permitted protector retirement and refusal cases:

```powershell
pwsh -NoProfile -File corpus/test-rebuilt-retirement.ps1 -ToolDirectory src/Cilantro.Cli/bin/Release/net10.0
```

## Benign runtime probes

Use the [probe harness](../corpus/probes/README.md) for executable behavioral comparisons. Its source-built fixtures provide known input/output behavior and unprotected oracles. Do not substitute malware execution for these trials.

Compare return values, exceptions, persistent state, repeated calls and relevant payload bytes. Record framework, architecture, protection configuration and bounds. A passing probe checks that fixture and exercised behavior, not every possible program.

## Interpreting the measurements

Keep detection, recovery, structural verification, reconstruction observations, physical removal and artifact preservation separate. Their denominators differ; adding them into a single coverage percentage is misleading.

A dispatcher-shaped counter can include application logic. Original-byte recovery and reconstructed CIL have different evidence. An extracted native dependency is not a deprotected managed assembly. Read [support](compatibility.md), [VM reconstruction](devirtualization.md) and the actual reports when evaluating a case.

## Tests without private samples

Sample-dependent tests skip when the configured sample directory contains no managed binaries. A directory containing only some required fixtures is an incomplete corpus: missing identities should be reported, not silently treated as validation. `CILANTRO_SAMPLES` selects the sample directory.

Run the [development checks](development.md) and account for skips explicitly. Public-checkout unit tests do not replace private-fixture gates.
