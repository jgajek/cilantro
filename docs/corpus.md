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

`minimumRecoveredStringSites` gates the sum of constant-folded and table/lookup-restored string sites. Use it when the recovery route can change while the required total stays fixed. `minimumConstantStringSites` remains available for assertions specific to constant folding. Exposing a literal can retain the original call when it is required to preserve initialization effects; the pass diagnostics identify that case.

## Reconstruction cleanup gates

The standard corpus runner disables reconstruction, so it cannot gate removal of an abandoned VM engine. For the pinned Qbjuef and Mlfhntkcvb payload inputs, also run ordinary reconstruction and check the resulting reports:

```powershell
New-Item -ItemType Directory -Force results | Out-Null
cilantro C:/cilantro-verify/samples/Qbjuef.exe --recover-embedded --declarations corpus/reconstruction.declarations.json --output results/Qbjuef.cleaned.exe --report-dir results --json > results/qbjuef-run.json
cilantro C:/cilantro-verify/samples/Mlfhntkcvb.payload.Lqcuzgc.dll --declarations corpus/reconstruction.declarations.json --output results/Mlfhntkcvb.cleaned.dll --report-dir results --json > results/mlfhntkcvb-run.json
pwsh -NoProfile -File corpus/verify-reconstruction.ps1 -ReportDirectory results
```

The opt-in 192-million-step allowance accommodates independent cold proofs for Mlfhntkcvb's 514 proxy initializers. The report gate checks pinned input identities, successful structural validation, reconstruction of the method and initialization helper, minimum runtime removal, expected payload hashes, and the helper's cold/repeat comparison evidence. It deliberately requires the full-state disagreement to remain visible alongside matching captured non-VM state. This script reads reports; it does not execute either sample or independently prove equivalence.

## Whole-corpus completion measurements

The manifest gates intentionally keep reconstruction and renaming disabled. To inventory what an analyst-facing recovery leaves behind, run the separate PowerShell 7 measurement harness with an isolated, fixed CLI build:

```powershell
pwsh -NoProfile -File corpus/measure-completion.ps1 -Cli artifacts/fixed-build/cilantro.dll -Samples C:/cilantro-verify/samples -Output C:/cilantro-verify/review-trials/completion -Concurrency 2
```

The harness verifies manifest input hashes, enables reconstruction and recursive recovery, preserves per-entry host/library/declaration settings, and applies a recorded step allowance (192 million by default). It uses normal emission even for exploratory entries, because this measurement asks what recovery actually produces. Original corpus assertions remain separate; the harness checks expected payload hashes but does not reinterpret existing output-hash or oracle-name gates after renaming. It never executes a sample. Use a fresh output directory and do not rebuild the CLI in place while measurements run.

`completion.runs.json` records every scheduled root, including failures. `completion.baseline.json` records each reported child and its depth, identity, structural verification, residual control-flow and VM metrics, reconstruction evidence, resources, payloads, blockers, and incomplete passes. `completion.baseline.csv` provides a compact comparison. Repeated content hashes retain each recovery context. Traversal-limited children remain explicit. Additional files outside the pinned manifests can be supplied with `-AdditionalInputs`; their observed hashes are recorded separately.

These are completion measurements, not completion verdicts. A dispatcher-shaped method can contain ordinary logic, an early blocker can be superseded by a later recovery pass, and unsupported extraction can mean either absent content or unresolved decoding. Inspect final cleanup and reconstruction evidence before classifying a residue. Rerun `summarize-completion.ps1 -Directory <output>` to regenerate summaries from the saved reports.

Compare two completed measurements with `compare-completion.ps1 -Before <baseline> -After <candidate> -Output <comparison.json>`. It matches assembly observations by root case, depth, and input hash, records missing/new observations, and compares verification, remaining dispatcher-shaped methods, VM coverage, and extracted payload hashes. The original root outcomes remain in the comparison, including failures that produced no assembly report.

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
