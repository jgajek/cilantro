# Code organization

`Cilantro.Core` separates the run coordinator from the data and passes it uses:

| Location | Responsibility |
| --- | --- |
| `CilantroPipeline.cs` | Default pass order, run orchestration, reporting and emission |
| `ArtifactContext.cs` | Loaded assembly, trusted libraries, facts, evidence and change records |
| `Pipeline/` | Pass contract, options/results and execution planning |
| `Reporting/ReportModels.cs` | Public report records |
| `Passes/`, `Recovery/`, `Strings/`, `Payload/`, `Proxy/` | Detection and recovery stages |
| `Verification/` | Assembly validation, identity/structure checks and mutation rollback |
| `Analysis/`, `Codec/` | Analysis and decoding helpers |

Types extracted from `CilantroPipeline.cs` retain their `Cilantro.Core` namespace and public
signatures. File placement does not require callers to change imports. Pass ordering remains in
`CilantroPipeline.CreateDefaultPasses`; dependencies and planner decisions still control execution.

## Mutation ownership

Use `InstructionMutationTransaction` for opcode/operand edits, `BodyMutationTransaction` for one
complete method body, and `BodyMutationBatch` for a rewrite spanning multiple bodies. Capture before
editing. A batch captures each method once, even when several call sites belong to that method.
Keep the batch in a `using` scope so an exception or early return restores every uncommitted body.

Verify the rewrite before calling `Commit`. Change records queued through `RecordChange` become
visible only on commit; rollback discards them. A batch owns body snapshots and pending records,
not changes to fields, resources or type declarations. Those need their own rollback handling.

Tests exercise commit, rollback, repeated capture, exception unwinding and the recovery passes
that use these transactions. Corpus gates and emitted output hashes check that structural
refactoring preserves sample results.
