# JSON output contracts

Use this reference when writing a consumer for CILantro results. Run with `--json`, check `Schema`, then follow the paths in `Wrote` to collect the report and artifacts. The console's English text is for case review.

| Schema | Output |
| --- | --- |
| [run.schema.json](run.schema.json) | Run manifest on stdout, `Schema: cilantro.run/1` |
| [error.schema.json](error.schema.json) | Error on stdout when no normal run result is available, `Schema: cilantro.error/1` |
| [analysis.schema.json](analysis.schema.json) | Detailed analysis report |
| [blockers.schema.json](blockers.schema.json) | Interpretation blockers and remedies |
| [config.schema.json](config.schema.json) | Recovered constants; not a general family-specific malware configuration |
| [status.schema.json](status.schema.json) | Progress and terminal state when status reporting is enabled |

Changes, rename maps, and embedded recovery graphs are additional outputs named by the manifest. The corpus [manifest schema](../corpus/schema/manifest.schema.json) describes a development input, not a recovery output.

Analysis reports expose Babel stream exports as `DecodedResources`, including source resource name/hash, decoded length/hash, decoder and written path. The adjacent `.babel-resources.json` index lists the same records. Data streams remain separate from extracted managed assembly artifacts.

`Success` is the configured pipeline outcome, `Verified` is structural verification, and `RebuiltCheck` is the bounded reconstruction comparison result. Read them independently and inspect child manifests when present. None is an exhaustive-unprotection flag.

## Compatibility

Check explicit schema identifiers where present and `ToolVersion` on reports. Required fields remain present, with nullable values represented as null. Consumers should tolerate additive fields and handle unfamiliar enum values conservatively. Repository schemas use `additionalProperties: false` to catch undocumented producer changes; an older schema may therefore reject a newer additive document.

Manifest fields are not removed, renamed, or reinterpreted within the same schema major version. Reports without an explicit schema identifier are tied to the documented tool version. Pin those readers and update their schema with the tool.

See [automation and MCP](../docs/agents.md) for decisions, retries, and progress polling.
