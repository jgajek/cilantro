# Reading the output

Start by answering three questions: **which file should I inspect, was that file recovered successfully, and what qualifications apply to its code?** The root result alone is not enough for a multi-stage sample.

## Read the console summary

| Section | Analyst action |
| --- | --- |
| Result | Establish whether recovery emitted a cleaned file, completed analysis only, or stopped short. |
| Output | Follow the recommended assembly, HTML report and case-folder paths. |
| Needs review | Investigate material failures and reconstruction disagreements, including child findings. |
| Artifacts | Identify the wrapper, loaded assemblies, dependencies, native files and resource bundles. |
| Next | Use the suggestion as a starting point, checking the actual artifact role. |
| What changed in the input | Read the changes to this input; do not interpret them as totals for all children. |
| Remaining | Review unresolved bodies/strings, unsupported work, residual patterns and assumptions. |
| Validation | Separate structural checks from bounded reconstruction comparisons. |

Use `--verbose` for pass diagnostics and technical counters. The HTML report exposes more detail in expandable sections. For scripts, use `--json` and documented fields rather than parsing these English headings.

## Choose the right file

| Artifact | What it is | How to use it |
| --- | --- | --- |
| Cleaned input | Transformed copy of the file supplied to CILantro | Inspect wrapper/application logic; it may not contain the final payload. |
| Extracted original | Recovered bytes before a child cleanup run | Retain as evidence and use for an independent child trial. |
| Cleaned child | Separate recovery result for an extracted managed assembly | Often the most useful file for payload code; check its own result. |
| Restored resource bundle | A container whose resources were restored to a parent | Inspect the resources; do not assume it is an executable stage. |
| Bundled dependency | A library extracted from a dependency resource | Check role and identity before calling it malware payload code. |
| Native-wrapper stage | Managed bytes extracted from a supported native bootstrap | Follow the stage's managed recovery output and report. |
| Preserved reviewed dependency | Exact hash match to an explicitly supplied reference | Bytes are preserved; this is not a new deprotection claim. |

The recommendation favors an assembly observed at a load operation over a resource bundle. This is provenance-based triage, not family attribution or proof of a final stage. Follow the parent-child graph and hashes; a deduplicated child can have several parents.

A root `Wrote.Cleaned` can be null while a native wrapper's managed child has an output. Conversely, a cleaned root does not guarantee that every child was cleaned. A graph's `Complete` value describes its bounded processing, not exhaustive discovery of all possible embedded content.

If a child was left at a traversal limit, retain the extracted bytes and inspect its diagnostic. If it is native, CILantro's managed cleanup may not apply. For a supported managed bootstrap, the wrapper can be reassembled with the recovered child; use the recorded result rather than assuming this for every wrapper shape.

## Interpret validation without losing useful results

| Signal | Interpretation | What it does not prove |
| --- | --- | --- |
| Cleaned file written | Emission policy allowed an output | Every protection recognized or removed |
| `Success: true` | Configured pipeline success | Universal behavior equivalence or complete child recovery |
| `Verified: true` | Structural checks passed | Correctness for every runtime input |
| `RebuiltCheck: agreed` | Bounded reconstruction observations matched | All possible VM paths, hosts or callbacks |
| `RebuiltCheck: disagreed` | At least one captured observation differed | That every rebuilt method is wrong, or that the difference is harmless |
| `RebuiltCheck: notMade` / inconclusive detail | Comparison did not establish agreement | Agreement by default |
| Extracted SHA-256 | Identity of a particular recovered byte sequence | Malware family, intent or completeness |

The report can retain raw full-state reconstruction disagreement even when supplementary application-contract checks explain differences in removed protector state. Read the coverage and the reason. The corpus completion decision permits deliberate protector-metadata removal; that is not permission to dismiss an unrelated application's state difference.

Methods marked `[RebuiltFromReading]` came from supported VM reconstruction rather than decrypted original bodies. Some rebuilt protector-only bodies can later be removed, so a marker count alone does not measure missing application code. The [VM guide](devirtualization.md) explains the detailed evidence.

## Understand residual code and warnings

- **Switches:** ordinary application decisions and async/iterator state machines are legitimate. A dispatcher-shaped count is a review cue, not a removal target.
- **Small methods:** a method returning zero or null can be real application behavior. A stub heuristic needs original-body evidence.
- **Resources:** payloads, dependencies and application data may remain. Entropy alone does not identify an encrypted protector table.
- **Calls beside recovered literals:** a call may be retained to preserve initialization, exceptions or other effects even when its return value is known.
- **Replacement names:** useful labels are not the original source names. Use `NAME.renames.json` for correspondence.
- **Verifier/decompiler warnings:** inspect the affected method. Unsafe code and unusual valid CIL can trigger diagnostics; a warning is neither automatic proof of failed recovery nor safe to ignore wholesale.

String counters usually describe sites/uses rather than distinct strings. Some simplification counters accumulate across passes. `HostProfile` records consulted host facts; `ContinuedPast` records unsupported calls passed during permissive interpretation. These qualifications matter even with structural success.

Blocker records describe stops encountered during recovery. Some become irrelevant after a later successful route or retirement of the owning protector code. Correlate them with the final artifact and pass result instead of treating every historical event as an unresolved application failure.

## Keep the useful outputs

Read paths from `Wrote`; the following names are typical, not a naming contract.

| File or directory | Purpose |
| --- | --- |
| `NAME.report.html` | Offline report with artifact links and detailed evidence |
| `NAME.analysis.json` | Recovery/protection analysis, passes and verification |
| `NAME.changes.json` | Changes and affected locations |
| `NAME.blockers.json` | Interpretation stops and available remedies |
| `NAME.renames.json` | Original-to-replacement names, when produced |
| `NAME.config.json` | Recovered constants, when available; not a general malware configuration decoder |
| `NAME.embedded.json` | Child nodes, links, hashes, statuses and run manifests |
| `NAME.status.json` | Automatic CLI progress and terminal state; opt-in for core callers |
| `NAME.virtualized/` | VM programs and lifted IL listings, when produced |
| Extracted files and cleaned assemblies | Original recovered bytes and transformed analysis copies |

Keep reports with their referenced artifacts so links remain useful. Reports and recovered constants can contain sensitive case data. Neither a readable output nor a successful report makes the sample safe to run.

Continue with [analyst workflows](analyst-workflows.md) for payload investigation, [troubleshooting](troubleshooting.md) for incomplete work, or [automation](agents.md) for machine decisions.
