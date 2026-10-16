# Automation and MCP

Use JSON for scripts and integrations. Human stdout is intended for analysts and may change wording or layout between releases.

## CLI contract

```text
cilantro sample.exe --json --status --recover-embedded --report-dir case-output --output case-output/cleaned.exe
```

An ordinary JSON run writes one object to stdout, without progress prose. Its `Schema` is `cilantro.run/1`; an error preventing a normal run uses `cilantro.error/1`. Read `Wrote` paths rather than constructing filenames. See the [schemas](../schema/README.md).

| Field | Interpretation |
| --- | --- |
| `Success` | Configured pipeline success, not complete unprotection |
| `Verified` | Structural verification, not equivalent behavior |
| `RebuiltMethods`, `LiftedPrograms` | VM reconstruction counts |
| `RebuiltCheck` | `agreed`, `disagreed`, or `notMade`; inspect detailed evidence and coverage |
| `Wrote` | Cleaned output, reports, listings, and optional embedded graph |
| `Payloads` | Extracted artifact identity, provenance, hashes, and paths |
| `Recovery` | Recovery and remaining-work counters |
| `Passes`, `Blockers`, `ContinuedPast` | Incomplete work and interpretation qualifications |
| `MoreToDeclare` | At least one blocker has a structured remedy; not automatic retry authorization |

An integration should not collapse these fields into a single green/red equivalence verdict. A successful structurally verified output can still have a reconstruction disagreement. Review child manifests from `Wrote.Embedded`, not just the root. A native wrapper's root `Wrote.Cleaned` can be null while its managed child has a cleaned output.

Exit codes are `0` for configured success, `1` for an unsuccessful pipeline result, and `2` for arguments/input/errors preventing a normal result. Error objects have their own shape. Keep stderr for diagnostics and stdout for the JSON parser.

## Capture a case from PowerShell

This example assumes `cilantro.exe` is on PATH and `case/run-01` is a new trial directory:

```powershell
New-Item -ItemType Directory -Path case/run-01 -Force | Out-Null
cilantro.exe sample.exe --json --status --recover-embedded `
  --report-dir case/run-01 --output case/run-01/cleaned.exe `
  > case/run-01/run.json 2> case/run-01/stderr.txt
$runExitCode = $LASTEXITCODE
$run = Get-Content case/run-01/run.json -Raw | ConvertFrom-Json
$run | Select-Object Schema, ToolVersion, Success, Verified, RebuiltCheck
$run.Wrote
```

Check `Schema` before reading run-specific fields; an error object is not a partially populated run object. Preserve `$runExitCode`, stderr and the raw JSON. Handle an empty/truncated file as a process or I/O failure rather than assuming recovery failed in a particular pass.

For embedded recovery, read the graph at `Wrote.Embedded`. Nodes with a `Run` need their own result review. `limited`, `failed`, `incomplete`, `extracted` and `preserved-reference` describe different outcomes; do not convert all discovered children into successful cleaned assemblies. A reviewed reference records its exact hash/source and has no new deprotection claim. Native extracted children can require separate analysis. The graph's `Complete` describes bounded traversal, not exhaustive discovery.

For batch work, give each input/trial its own output directory, preferably keyed by input hash and trial identifier. Keep the input hash, version, command, declarations and dependency hashes with each record. Do not execute cleaned outputs as part of a success check, and do not overwrite one trial while another still owns its status file.

## MCP setup

Release archives include `cilantro-mcp`, a stdio MCP server using the same recovery engine.

```json
{
  "mcpServers": {
    "cilantro": { "command": "C:/Tools/CILantro/cilantro-mcp.exe" }
  }
}
```

Use an absolute executable path appropriate to the installation. On Linux, the executable has no `.exe` suffix.

| Tool | Purpose |
| --- | --- |
| `unpack` | Run recovery and wait for the manifest |
| `start_unpack` | Start a background run and return its `statusPath` |
| `unpack_status` | Poll that path; a finished run includes `Run.Result` |
| `cancel_unpack` | Request cancellation of a run owned by this server |
| `next_declarations` | Prepare declarations from blockers and supplied answers |
| `read_output` | Read text outputs in bounded pages; extracted binaries are not returned |

For a potentially long run, call `start_unpack` with arguments such as:

```json
{
  "path": "C:/cases/sample.exe",
  "reportDir": "C:/cases/output",
  "recoverEmbedded": true,
  "devirtualize": true
}
```

MCP defaults VM reconstruction **off**, unlike the ordinary CLI. Set `devirtualize` explicitly when required. Poll every few seconds; do not submit duplicate runs into the same output directory. Background work survives a polling timeout but not server exit. Handle `finished`, `failed`, and `cancelled` as terminal phases, and inspect the status advice for stale runs. Cancellation is cooperative; do not assume a request has already stopped the current work.

## Declaration loop

Read `Blockers` and their structured `Remedy` fields. Supply established facts or justified call outcomes; a `Wants` placeholder is a question, not a value. `next_declarations` accepts the blockers path, optional existing declarations (`from`), supplied `answers`, and an optional output path (`into`). Review the resulting assertions before rerunning with them.

Stop when no justified new input remains or the remaining blockers lack remedies. Keep sample hashes, tool version, declarations/profile hashes, and output paths with the case. Use [declarations](declarations.md) for the contract.
