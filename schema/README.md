# JSON output contracts

Use `--json` and the paths in `Wrote` for automation. Do not parse human stdout or construct artifact paths from sample names.

| Schema | Output |
| --- | --- |
| [run.schema.json](run.schema.json) | Run manifest on stdout, `Schema: cilantro.run/1` |
| [error.schema.json](error.schema.json) | Error on stdout when no normal run result is available, `Schema: cilantro.error/1` |
| [analysis.schema.json](analysis.schema.json) | Detailed analysis report |
| [blockers.schema.json](blockers.schema.json) | Interpretation blockers and remedies |
| [config.schema.json](config.schema.json) | Recovered constants; not a general family-specific malware configuration |
| [status.schema.json](status.schema.json) | Progress and terminal state when status reporting is enabled |

Changes, rename maps, and embedded recovery graphs are additional outputs named by the manifest. The corpus [manifest schema](../corpus/schema/manifest.schema.json) describes a development input, not a recovery output.

`Success` is the configured pipeline outcome, `Verified` is structural verification, and `RebuiltCheck` is the bounded reconstruction comparison result. Read them independently and inspect child manifests when present. None is an exhaustive-unprotection flag.

## Compatibility

Check explicit schema identifiers where present and `ToolVersion` on reports. Required fields remain present, with nullable values represented as null. Consumers should tolerate additive fields and handle unfamiliar enum values conservatively. Repository schemas use `additionalProperties: false` to catch undocumented producer changes; an older schema may therefore reject a newer additive document.

Manifest fields are not removed, renamed, or reinterpreted within the same schema major version. Reports without an explicit schema identifier are tied to the documented tool version. Pin those readers and update their schema with the tool. The 0.4.0 rename from ReactorUnpack changed manifest tokens and default paths; current clients should use the `cilantro.*` identifiers.

See [automation and MCP](../docs/agents.md) for decisions, retries, and progress polling.
