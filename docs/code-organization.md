# Code organization

| Location | Responsibility |
| --- | --- |
| `src/Cilantro.Cli/Program.cs` | Arguments, exit codes, JSON mode, and CLI entry point |
| `src/Cilantro.Cli/Explain.cs` | Human-readable console presentation |
| `src/Cilantro.Core/CilantroPipeline.cs` | Pass order, orchestration, verification, emission, and reporting |
| `src/Cilantro.Core/Pipeline/` | Options, planning, status, results, and bounded embedded recovery |
| `src/Cilantro.Core/Interpretation/` | Static machine, values, heap, modeled APIs, host facts, and evidence |
| `src/Cilantro.Core/Recovery/` | Body recovery, VM reading/rebuilding, cleanup, resources, and naming |
| `src/Cilantro.Core/Analysis/` | CFG, state, reachability, and dependency analyses |
| `src/Cilantro.Core/Passes/` | General transformations and control-flow cleanup |
| `src/Cilantro.Core/Native/` | Supported native-bootstrap extraction |
| `src/Cilantro.Core/Reporting/` | Report models, shared analyst summary, artifact prioritization, and HTML |
| `src/Cilantro.Core/Verification/` | Validation and mutation transactions |
| `src/Cilantro.Mcp/` | Stdio protocol, tool definitions, and background runs |
| `tests/Cilantro.Tests/` | Unit, integration, schema, and sample regression tests |

## Ownership rules

Use `InstructionMutationTransaction` for instruction edits, `BodyMutationTransaction` for a body, and `BodyMutationBatch` for related body changes. Capture before mutation and verify before committing. Dispose uncommitted transactions to restore bodies and discard pending change records. These transactions do not own arbitrary metadata/resource edits.

Preserve type-initialization timing, side effects, exception boundaries, stack behavior, and indirect references. Do not equate no direct callers with no uses. Loader-body effects are distinct from the containing type's automatic initialization. Numeric token consumers can require stable metadata identities even after visible call sites have been rewritten.

## Presentation and contracts

`AnalystSummary` supplies the console and HTML interpretation of a result. `AnalystArtifact` combines provenance and child results to recommend a starting artifact. `AnalystReport` escapes sample-derived text and renders offline HTML. Keep root/child validation qualifications visible in both surfaces.

`RunManifest` and `Reporting/ReportModels.cs` define JSON-facing records. Update the corresponding [schemas](../schema/README.md) and schema tests when their serialized shape changes. Human wording is not a machine contract.

## Validation

Add tests for semantic boundaries, rollback, and false-positive refusal, not just happy-path counters. Use the sample corpus for static regression and benign probes for executable comparisons. [Development](development.md) gives the build and validation commands.
