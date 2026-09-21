# Corpus validation

Corpus manifests contain metadata, expected protection, SHA-256 identities, and assertions. Malware binaries are not distributed with the repository. A gate checks its stated assertions; it does not establish exhaustive extraction or behavioral equivalence.

| Manifest | Scope |
| --- | --- |
| [Reactor 6](../corpus/reactor-6-nonvirt.manifest.json) | Real-world samples, recovered stages, and validation oracles; includes an exploratory native wrapper |
| [Reactor 7.5](../corpus/reactor-7-static.manifest.json) | Pinned benign probes and related validation entries |
| [ConfuserEx](../corpus/confuserex-1-static.manifest.json) | Two whole-section anti-tamper samples |

The filenames are historical labels, not complete feature descriptions. In particular, Reactor validation also covers virtualized code and native extraction. Read each manifest's expectations rather than inferring them from its filename.

## Run the static gates

Build the CLI, then supply the directory containing the matching samples:

```text
dotnet build Cilantro.slnx -c Release
dotnet run --project src/Cilantro.Cli -c Release --no-build -- corpus run --manifest corpus/reactor-6-nonvirt.manifest.json --samples samples --output artifacts/corpus/reactor6
dotnet run --project src/Cilantro.Cli -c Release --no-build -- corpus run --manifest corpus/reactor-7-static.manifest.json --samples samples --output artifacts/corpus/reactor7
dotnet run --project src/Cilantro.Cli -c Release --no-build -- corpus run --manifest corpus/confuserex-1-static.manifest.json --samples samples --output artifacts/corpus/confuserex
```

Use isolated output directories. The runner validates sample identities and writes `corpus.outcomes.json`; missing required inputs are reported separately from failed assertions. Some entries use analysis-only or feature-specific policies, so passing the manifest is not identical to testing every sample with all default options.

## Reconstruction cleanup gates

The standard corpus runner disables reconstruction, so it cannot gate removal of an abandoned VM engine. For the pinned Qbjuef and Mlfhntkcvb payload inputs, also run ordinary reconstruction and check the resulting reports:

```powershell
New-Item -ItemType Directory -Force results | Out-Null
cilantro C:/cilantro-verify/samples/Qbjuef.exe --recover-embedded --declarations corpus/reconstruction.declarations.json --output results/Qbjuef.cleaned.exe --report-dir results --json > results/qbjuef-run.json
cilantro C:/cilantro-verify/samples/Mlfhntkcvb.payload.Lqcuzgc.dll --declarations corpus/reconstruction.declarations.json --output results/Mlfhntkcvb.cleaned.dll --report-dir results --json > results/mlfhntkcvb-run.json
pwsh -NoProfile -File corpus/verify-reconstruction.ps1 -ReportDirectory results
```

The opt-in 192-million-step allowance accommodates independent cold proofs for Mlfhntkcvb's 514 proxy initializers. The report gate checks pinned input identities, successful structural validation, reconstruction of the method and initialization helper, minimum runtime removal, expected payload hashes, and the helper's cold/repeat comparison evidence. It deliberately requires the full-state disagreement to remain visible alongside matching captured non-VM state. This script reads reports; it does not execute either sample or independently prove equivalence.

## Benign runtime probes

The [probe harness](../corpus/probes/README.md) builds benign programs for .NET Framework 4.8, .NET 8, and .NET 10, then uses an installed Reactor 7.5 console tool to protect strings/CFF, NecroBit-only, and full configurations. Nine protected configurations are compared with their unprotected oracles.

Only these repository-built benign programs are executed for runtime validation. Malware corpus work is static interpretation and decompilation. Record the exact protector command, input hashes, output hashes, and oracle results. Trial-protected outputs can expire, so later runtime trials may require fresh fixtures.

## Interpreting the measurements

| Check | Establishes |
| --- | --- |
| Unit/integration tests | The specific semantic and regression cases they assert |
| Corpus gates | Manifest expectations on pinned inputs |
| Output hash comparison | Reproducibility or a detected output change for that run |
| Successful decompilation | A tested decompiler accepted the emitted assembly |
| Runtime-oracle match | Selected behavior of a benign protected/cleaned program matched its source-built oracle |
| VM comparison | Agreement or disagreement within the reported paths, inputs, and modeled state |

Do not add these counts into a single coverage percentage. Preserve failures and inconclusive trials alongside passing results. The current pre-release baseline and known gaps are in [compatibility](compatibility.md); historical sample measurements are in [the archived corpus notes](history/pre-0.10/corpus.md).

## Tests without private samples

Run `dotnet test Cilantro.slnx -c Release`. Sample-dependent tests should report skips when their inputs are unavailable. Review the skip count: a green public CI run does not mean private-sample coverage ran. The fast development filter is `--filter "Cost!=High"`; use the full available suite for release validation.
