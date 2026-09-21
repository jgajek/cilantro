# Reading the output

The summary answers four questions: what was written, which file to inspect, what changed, and what remains uncertain. Start with the HTML report when the input contains more than one assembly.

## The summary

| Section | How to use it |
| --- | --- |
| Result | Whether a cleaned assembly was written, analysis completed, or recovery stopped short |
| Open | Recommended artifact and report paths |
| Needs review | Material failures or reconstruction disagreements, including those in child assemblies |
| Artifacts | Where extracted files came from and whether they were cleaned |
| Next | Suggested next step based on the available outputs |
| What changed in the input | Recovery performed on the input assembly, not an aggregate over all children |
| Remaining | Unrecovered bodies or strings, residual patterns, unsupported work, and assumptions |
| Validation | Structural verification and the scope of reconstruction comparisons |

The console keeps detailed counters, comparison traces, and pass diagnostics behind `--verbose`. The HTML report provides these in expandable sections. Output paths and suggested commands remain copyable.

## Which assembly should I open?

The recommended artifact is selected from how it was recovered. An assembly observed at an assembly-load operation takes priority over a resource bundle. This is a useful starting point, not proof that it is the final payload.

| Artifact | Meaning |
| --- | --- |
| Cleaned input | A transformed copy of the file supplied to the tool |
| Extracted original | The exact recovered bytes before child cleanup |
| Cleaned child | A separate recovery run on an extracted managed assembly |
| Restored resource bundle | A container whose resources were restored to its parent; not automatically a payload |
| Bundled dependency | A library extracted from a dependency resource, such as Costura |
| Native-wrapper stage | Managed bytes extracted from the supported native bootstrap, followed by managed recovery |

The parent-child inventory records provenance and hashes. Deduplicated children can have more than one parent. A traversal limit means a file was discovered but not processed further; it does not make that file clean.

## What the verdict does and does not establish

**Cleaned assembly written** means an output file was emitted under the configured policy. **Structural checks passed** means the tool accepted the assembly structure and the invariants its verifier checks. Neither establishes complete unprotection or behavioral equivalence.

VM reconstruction has a separate verdict:

- **Agreed:** bounded comparisons matched for the exercised paths and observed results. Coverage still matters.
- **Disagreed:** at least one comparison differed. This may concern method behavior, exceptions, state, or payload extraction. Inspect the detailed evidence; do not assume the difference is harmless.
- **Not made / inconclusive:** the comparison could not establish agreement, for example because a path was not exercised or state could not be modeled.

A payload-hash match alone does not prove every reconstructed method. Controlled method trials likewise cover their listed inputs and initial states, not all possible behavior. Methods reconstructed from VM instructions carry `[RebuiltFromReading]` to distinguish them from decrypted original bodies.

## Remaining code and counters

String counts refer to uses/call sites, not unique strings. Some method simplification counts accumulate across passes. Dispatcher-like patterns can include ordinary switches; zero is not a general correctness target. No detected leftovers means none were recorded by supported checks, not that every protection was recognized.

Protector code may remain because reflection, numeric metadata tokens, initialization side effects, or indirect calls prevent safe removal. Unreachable application/library code is not automatically protector code. Replacement names describe known structure or provide stable placeholders; original names may no longer exist.

`HostProfile` records facts consulted during interpretation and whether they were stated or assumed. `ContinuedPast` records unsupported calls the default mode continued past. These qualifications can matter even when structural verification passed.

## Files on disk

Paths in the manifest are authoritative. Files are usually named after the input in the report directory.

| Output | Contents |
| --- | --- |
| `NAME.report.html` | Offline analyst report, artifact links, and expandable diagnostics |
| `NAME.analysis.json` | Protection, recovery counters, evidence, resources, passes, and verification |
| `NAME.changes.json` | Recorded edits and their locations |
| `NAME.blockers.json` | Interpretation stops, assumptions, and available remedies |
| `NAME.renames.json` | Original-to-replacement symbol names, when produced |
| `NAME.config.json` | Recovered constants, when available; not a general malware-family configuration decoder |
| `NAME.embedded.json` | Recovery graph and child manifests, when traversal is performed |
| `NAME.status.json` | Progress when requested with `--status` |
| `NAME.virtualized/` | VM listings and lifted IL, when produced |
| Payload/extraction directories | Recovered original assemblies and dependencies |

No extracted assembly does not prove no embedded payload exists. An unsupported extraction path may leave content behind, and downloaded stages are not fetched. Read [compatibility](compatibility.md) for the current limits and [automation](agents.md) for machine-readable decisions.
