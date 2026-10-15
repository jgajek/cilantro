# Analyst quick start and CLI reference

## First run

Use a case directory with enough space for the input, recovered stages, and reports. The commands below assume `cilantro` is on PATH; use `.cilantro.exe` on Windows when launching it from the unpacked release directory.

```text
cilantro sample.exe --recover-embedded --report-dir case-output
```

1. Follow **Open** to the recommended assembly and HTML report.
2. Review **Needs review** if present. A reconstruction disagreement must be investigated before trusting that code.
3. Open the assembly in a decompiler. Use the artifact inventory to distinguish the wrapper, loaded assemblies, dependencies, and resource bundles.
4. Read **Remaining** and **Validation**. A readable assembly may still contain protected code or depend on recorded assumptions.

The recommendation follows extraction provenance. It is not a malware-family classification, and a loaded assembly is not necessarily the final payload.

## Common workflows

```text
cilantro sample.exe --output case-output/cleaned.exe --report-dir case-output
cilantro sample.exe --analyze-only --report-dir case-analysis
cilantro sample.exe --strict --report-dir case-strict
cilantro sample.exe --verbose
cilantro sample.exe --json --status
```

Analysis-only still interprets recovery paths and writes reports and extracted files. It suppresses cleaned assemblies, including child cleaned assemblies. Strict mode still recovers encrypted code; it changes how unknown behavior is handled and defaults renaming and reconstruction off. It does not prove complete recovery.

For supported native Reactor wrappers, the default run extracts the managed assembly and continues recovery automatically. The original extracted bytes remain available. Add `--recover-embedded` to follow further embedded stages as well. Traversal is bounded to depth 4, 32 artifacts, and 256 MiB of input bytes, with hash deduplication; limits are reported rather than silently treated as completion.

Ordinary recursive recovery permits verified generic cleanup of extracted children, even when their protector is unrecognized. The root input still requires a recognized protector unless `--generic-recovery` is supplied. Strict child recovery also requires that explicit option. Structural verification, other emission gates, `--fail-on-partial`, and analysis-only behavior still apply; the original extracted bytes are preserved.

## Options

| Option | Effect |
| --- | --- |
| `-o, --output PATH` | Choose the cleaned input path; on supported native wrappers, this is used for the managed stage |
| `--report-dir DIR` | Choose the directory for reports and extracted artifacts |
| `--recover-embedded` | Continue recovery into extracted managed assemblies |
| `--analyze-only` | Write analysis and extraction outputs without a cleaned assembly |
| `--strict` | Disable implicit host assumptions and permissive interpretation; default renaming and reconstruction off |
| `--generic-recovery` | Permit supported generic rewrites without a recognized protector; other emission checks still apply |
| `--keep-runtime` | Retain protector declarations otherwise eligible for removal |
| `--remove-runtime` | Enable conservative runtime removal; already the default |
| `--keep-names` | Disable readability renaming |
| `--rename` | Enable renaming, including in strict mode |
| `--no-devirtualize` | Keep VM-backed methods unreconstructed; disassembly/listings can still be produced |
| `--devirtualize` | Enable supported VM reconstruction, including in strict mode; default in ordinary CLI runs |
| `--fail-on-partial` | Make incomplete passes block successful recovery/emission; reports or extracted files may still exist |
| `--host-profile FILE` | Supply host facts for static interpretation |
| `--library FILE` | Supply a specific dependency for interpretation; repeatable, not a directory search path |
| `--declarations FILE` | Supply facts, libraries, budgets, pass exclusions, or declared call outcomes |
| `--allow-declared-calls` | Enable call assertions from declarations; they are not independently proven |
| `-v, --verbose` | Include technical details and per-pass diagnostics |
| `--json` | Write one run/error JSON object to stdout instead of the human summary |
| `--status` | Maintain a status JSON file beside the reports |
| `-h, --help` | Show command help |
| `--version` | Print the tool version |

See [declarations](declarations.md) for advanced controls. `corpus run` is a development command described in [corpus validation](corpus.md).

## When recovery stops short

Open the HTML report and the linked blockers JSON. A missing host fact may be supplied through a declaration; an unsupported instruction needs an implementation change. Raising budgets helps only when the relevant path stopped because of a budget. Repeating the same command will not resolve an unsupported operation.

For a long run, use `--status` or the asynchronous MCP tools. Large assemblies and VM analysis can take minutes. Use distinct output directories for concurrent or comparative runs.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The run met its configured success policy; partial recovery or unchecked reconstruction may remain |
| `1` | The pipeline ran but did not meet its success policy; reports and extracted artifacts may be available |
| `2` | Invalid arguments, unreadable/unsupported input, or an exception prevented a normal run result |

Scripts should read the JSON manifest, not parse the English summary. See [automation](agents.md).

## Preserving reviewed dependencies

With `--recover-embedded`, you can supply `--reviewed-dependencies references.json` to preserve extracted files that exactly match independently reviewed, unprotected dependency copies. This is an explicit trust declaration, not automatic protection detection. Unknown children still undergo normal recovery, and a failed parent remains failed.

The manifest is an array of records:

```json
[
  {
    "Sha256": "<64 hexadecimal characters>",
    "Path": "reference/library.dll",
    "Source": "Upstream release or immutable source URL reviewed by the analyst",
    "Classification": "unprotected-dependency"
  }
]
```

Reference paths are relative to the manifest. CILantro verifies the reference bytes against the declared SHA-256 before matching extracted bytes. Missing classifications, changed references and duplicate hashes fail validation. Reports label matches **Preserved reviewed dependency; bytes unchanged** and record the reference hash, path and source. No cleaned copy or deprotection is claimed for them. The option never downloads or executes a reference.
