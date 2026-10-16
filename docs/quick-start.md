# Analyst quick start and CLI reference

## Recover a sample

```text
cilantro sample.exe
```

That is the normal workflow. CILantro attempts to restore supported protected .NET code and strings, simplify control flow, rebuild supported VM-backed methods, assign readable names, remove proven protector helpers, and follow embedded managed assemblies. It interprets the file statically; it does not launch the sample or load its code into the host CLR.

Look at **OUTPUT** when the run finishes. It names the recommended assembly, offline HTML report, and case folder. Open the assembly in ILSpy or dnSpyEx. Read **NEEDS REVIEW**, **REMAINING**, and **VALIDATION** before relying on reconstructed code. For a dropper, the recommended file may be a child rather than the input.

Use `cilantro` when it is on PATH, `.\cilantro.exe` from an unpacked Windows build, or `./cilantro` on Linux. Quote paths containing spaces.

## Choose a workflow

| What you want | Command |
| --- | --- |
| Recover code and embedded stages | `cilantro sample.exe` |
| Keep a case in a chosen folder | `cilantro sample.exe -o case/run-01` |
| Get reports and extracted files without cleaned assemblies | `cilantro sample.exe --analyze-only` |
| Compare against a run without implicit machine assumptions | `cilantro sample.exe --strict` |
| See technical details when investigating a problem | `cilantro sample.exe -v` |
| Feed results to a script | `cilantro sample.exe --json -o case/run-01` |

## Where files go

Without `-o`, all files go into `sample.cilantro/` beside `sample.exe`. Repeating the command selects `sample.cilantro-2/`, then `-3/`, and so on. The original file is preserved.

`-o DIR` / `--output DIR` chooses one folder for the cleaned assembly, extracted originals, cleaned children, reports, VM listings, name maps and status file. It takes a **directory**, not a cleaned filename. The folder must be new or empty; an existing nonempty folder is rejected instead of mixing two trials. Parent directories are created as needed.

The cleaned input is normally `sample.cleaned.exe` (or `.dll` for a library) inside the case folder. A native wrapper may have no cleaned root; its managed stage and report appear in the child inventory. Copy actual paths from **OUTPUT**, the HTML report or the JSON `Wrote` fields rather than guessing them.

The status file is maintained automatically as `sample.status.json` in the case folder. It identifies the current pass and records the terminal outcome, including exceptions or cancellation. It is useful for watching a long run from another process. A stale file alone does not prove the process is still running.

Outputs remain analysis artifacts. Cleanup does not make a malware binary safe to execute.

## Common options

These are the options shown by `--help`.

| Option | What it means for your analysis |
| --- | --- |
| `-o, --output DIR` | Keep this trial's outputs together in a new/empty case folder. Use a different folder for each comparison. |
| `--analyze-only` | Perform analysis and supported extraction, writing reports and original extracted files. Do not emit cleaned root or child assemblies. This is not a quick header scan and can still take time. |
| `--strict` | Stop interpreting paths when needed behavior is unknown, instead of using implicit machine settings or stepping past unsupported calls. Keep obfuscated names and VM stubs unchanged. Supported original-method/string recovery still runs. This can recover less; it does not prove correctness. |
| `-v, --verbose` | Add detailed assumptions, blockers, reconstruction evidence and per-pass diagnostics to the final summary. Live phase/pass progress is already shown by default. |
| `--json` | Print one run/error JSON object instead of the banner, progress and English summary. Files and the status file are still written. Use this in scripts. |
| `--no-color` | Disable console colors. Also honored through `NO_COLOR`; redirection and `TERM=dumb` use plain text automatically. |
| `-h, --help` | Show the common workflows and these options. |
| `--help-all` | Also show specialist controls listed below. |
| `--version` | Print only the tool version. |

## Specialist controls

Use these to investigate a specific recovery problem. They are accepted normally, but kept out of the short help page.

| Option | When to use it and what changes |
| --- | --- |
| `--no-recursion` | Extract embedded files but do not clean further managed children. Supported native Reactor wrappers still unpack and continue into their directly recovered managed stage. Use this when examining a loader before following its payload chain. |
| `--keep-names` | Preserve obfuscated identifiers for comparison with original metadata, tokens or external notes. The usual readable replacement names are labels, not recovered source names. |
| `--keep-runtime` | Retain protector helper code instead of removing it. Here "runtime" means the protector's code, not your installed .NET runtime. Useful when investigating how protection works. |
| `--no-devirtualize` | Leave VM-backed method stubs in the cleaned assembly; supported bytecode listings are still written. Useful for comparing reconstruction with the original protected structure. |
| `--generic-recovery` | Explicitly request supported, structurally verified cleanup when no supported protector is recognized on the root input. It does not add support for unknown encryption or bypass failed verification. Ordinary recursive recovery already permits generic cleanup of extracted children; strict children need this explicit option. |
| `--fail-on-partial` | Treat incomplete/unsupported processing passes as failure and withhold cleaned output for that assembly. This may reject useful partial results; reports and extracted files can still exist. A strict completeness policy for automation, not a correctness proof. |
| `--library FILE` | Supply a specific managed dependency so its methods can be read by the static interpreter. Repeat for several DLLs. This does not execute the dependency or automatically search a directory. |
| `--host-profile FILE` | Supply facts about the Windows environment the sample expects, such as paths or machine settings. Use facts justified for the case; a profile and declarations with host facts cannot both be supplied. |
| `--declarations FILE` | Supply recorded host facts, managed dependencies, interpretation budgets, passes to skip or proposed call answers in one JSON file. See [declarations](declarations.md). Use the exact keys from the blocker report. |
| `--allow-declared-calls` | With `--declarations`, allow its asserted answers for calls the interpreter cannot model. Review these assertions first: a wrong answer can change the recovered path. Other declaration fields do not need this flag. |
| `--reviewed-dependencies FILE` | Preserve extracted DLLs matching exact hashes of independently reviewed, unprotected reference copies. Records the review provenance. Does not download or execute references, and cannot be used with `--no-recursion`. See the manifest below. |

For a filename starting with `-`, use `--` before the input. Path options also accept `--output=DIR` syntax.

## Reading progress and results

Human runs start with the Reveal text banner and show each target, phase and pass. `OK`, `PARTIAL`, `UNSUPPORTED`, `FAILED` and `SKIP` distinguish pass outcomes. Counts restart for each child; timings are not completion estimates. A skipped pass is not a successful pass.

Colors separate progress/artifact paths (cyan), results (green), review items (amber) and failures (red). On Windows, CILantro enables virtual-terminal processing for classic Command Prompt; if the host cannot enable it, output falls back to plain text.

A green completed run means configured pipeline success. It does not establish complete unprotection or equivalent program behavior. Reconstruction disagreements remain visible. Read the [output guide](reading-the-output.md), [payload workflow](analyst-workflows.md), and [troubleshooting](troubleshooting.md) for interpreting the result.

Recursive recovery is bounded to depth 4, 32 artifacts and 256 MiB of aggregate input bytes, with hash deduplication. These are traversal limits, not a guarantee that every possible embedded file was found. Downloaded stages are not fetched.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The run met its configured success policy; partial recovery or unchecked reconstruction may remain. |
| `1` | The pipeline ran but did not meet its success policy; inspect available reports and artifacts. |
| `2` | Arguments, input or an exception prevented a normal run result. |

Scripts should read the [JSON contract](agents.md), not parse the English summary. `corpus run` remains a developer command documented in [corpus validation](corpus.md); its `--output` also selects a directory.

## Migrating earlier commands

Before 1.0, selecting a case often required several switches. The same intent is now:

```text
cilantro sample.exe -o case/run-01
```

- Remove `--recover-embedded`, `--status` and `--remove-runtime`: those behaviors are automatic.
- Remove `--rename` and `--devirtualize`: ordinary recovery enables both. Strict mode deliberately disables them, with no positive CLI overrides. Core/MCP callers retain their separate options.
- Replace `--report-dir DIR --output DIR/cleaned.exe` with `-o DIR`. A cleaned filename is no longer the meaning of `--output`.
- Use `--no-recursion` when you explicitly want the former nonrecursive workflow.
- Removed switches produce an error explaining the replacement; they are not silently ignored.

## Preserving reviewed dependencies

Supply `--reviewed-dependencies references.json` only when you independently reviewed the referenced bytes as unprotected dependencies. This is an explicit trust declaration. Unknown children still undergo recovery, and a failed parent remains failed.

```json
[
  {
    "Sha256": "<64 hexadecimal characters>",
    "Path": "reference/library.dll",
    "Source": "Immutable upstream release/source reviewed by the analyst",
    "Classification": "unprotected-dependency"
  }
]
```

Reference paths are relative to the manifest. CILantro checks their bytes against the declared SHA-256. Changed references, missing classifications and duplicate hashes fail validation. Reports label matches **Preserved reviewed dependency; bytes unchanged**. No cleaned copy or deprotection is claimed for them.

## Install

Use the Windows x64 or Linux x64 archive from [Releases](https://github.com/jgajek/cilantro/releases). Published archives include self-contained `cilantro` and `cilantro-mcp`; no separate runtime is needed. Compare the archive SHA-256 with its published `SHA256SUMS.txt`, unpack it, and check `--version` and `--help`. A framework-dependent local development build requires .NET 10.
