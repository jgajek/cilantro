# Analysis performance

On Windows 10.0.26300 with 22 logical processors, .NET SDK 10.0.402 and runtime 10.0.13,
the optimized corpus midpoint is **457.73 s versus 1,131.56 s** for the original build:
**59.5% less wall time, or 2.47 times as fast**. All 24 corpus cases pass, all 110 detailed
reports/listings match, and all 2,931 tests pass. Measurements were completed on 2026-10-18.

Measure Release builds against the hash-pinned corpus. The corpus runner's policy disables
renaming and VM reconstruction; it still reads VM programs and follows the native wrapper's
managed child. These measurements describe that policy, rather than every CLI option.

Dispatcher path recovery and control-flow completion process independent method bodies with at most four workers,
bounded by the available processor count. Small modules stay sequential. Workers retain the
same per-method rewrite order, round limits, verification and rollback; change records are
published in original method order. Account for this concurrency when running several CLI
instances together. The historical timings above predate this change.

## Full WMS recovery: 2026-11-20

### Second optimization round

A fresh serial pair reduced full analysis from **1,668.898 s (27m49s) to 1,467.791 s
(24m28s)**: **12.1% less wall time**, saving 3m21s. The baseline was the verified build
from the first round below. This is one paired measurement, not a repeated median. Both runs
used the same Windows/runtime/server-GC configuration, input, declaration, 11 installer libraries,
renaming, VM reconstruction, child recovery and all 136 pass decisions. No profiling, builds or
test jobs competed with either timed run.

| Pass | Baseline | Candidate |
| --- | ---: | ---: |
| Control-flow completion | 42.526 s | 9.669 s |
| Control-flow recompletion | 18.288 s | 6.154 s |
| Control-flow helper completion | 34.904 s | 16.491 s |
| Dispatcher paths | 201.765 s | 158.381 s |
| Dispatcher paths completion | 192.497 s | 151.635 s |
| Dispatcher effects completion | 146.356 s | 190.321 s |
| Control-flow finalization | 81.087 s | 71.891 s |

The changes avoid unused structural descriptions in internal rollback transactions, reuse the
current dispatcher's graph and stack proof before any edits, and run standalone control-flow
completion with at most four independent method workers. All proof limits, rewrite ordering within
a method, verification and restoration state are retained; reports publish in original method order.

The root cleaned DLL is byte-for-byte identical to the baseline and the previous verified output
(`3f27462181f524e0878f8b929b5fe13a06ccf245684a4383525ecc78e9507246`). All 10 detailed
reports/listings and seven additional artifacts match after timing/path normalization, including
the child cleaned DLL, extracted payload, rename map, HTML and embedded report. Independent
ILVerify reports zero findings and no unreadable bodies. The focused Windows suite passes
303 tests with one skip, including failed-rewrite restoration, capture-time fingerprints and
serial/parallel behavior and report equivalence across repeated invocations.
The full Linux suite passes **3,672 tests with 147 skipped and zero failures** (28m35s).
All 704 production and test source files match between Linux and Windows after line-ending
normalization, and the benchmarked Windows source hashes remain unchanged.

Individual stages varied, including a slower effect-preserving dispatcher completion and changes
in stages whose implementation was unchanged. The total is the observed improvement; it does not
establish a uniform per-pass improvement. Evidence and pinned source/binary manifests are under
`C:/cilantro-verify/wms-performance-round2`. Existing application runtime proof limits are unchanged.

### First optimization round

A serial baseline/candidate pair on the managed WMS child
(`9e76d2c69d058e209da12460dba98c5947a6d65b78aec310b69438fad1e8608e`) reduced full
analysis wall time from **1,756.529 s (29m17s) to 1,540.794 s (25m41s)**: **12.3% less
wall time**, saving 3m36s. This is one paired measurement, not a repeated median. Both runs
ran on Windows 10.0.26300 with 22 logical processors, .NET runtime 10.0.15 and the same
server-GC configuration (SDK 10.0.404 recorded). Both used the 11 installer libraries, the same
256-million-step declaration, renaming and VM reconstruction, all 136 pass decisions and
recursive child analysis. No profiling or test jobs competed with the timed analyses.

| Pass | Baseline | Candidate |
| --- | ---: | ---: |
| Type restoration | 44.694 s | 2.719 s |
| Dispatcher paths | 208.610 s | 150.070 s |
| Dispatcher paths completion | 184.654 s | 147.128 s |
| Dispatcher effects completion | 209.564 s | 142.114 s |
| Control-flow finalization | 148.429 s | 104.244 s |

All 10 detailed JSON reports/VM listings match after pass-duration and output-path normalization.
Seven additional artifacts also match: the rename map, both HTML reports, embedded-run report,
root and child cleaned assemblies, and extracted payload. The HTML case-folder label and
embedded pass durations receive the corresponding path/timing normalization. The cleaned WMS
SHA-256 is unchanged from the previous independently verified recovery:
`3f27462181f524e0878f8b929b5fe13a06ccf245684a4383525ecc78e9507246`.
Independent ILVerify again reports **zero findings and zero unreadable bodies**. These output
checks preserve the existing proof limits; they do not establish full GUI/COM behavioral equivalence.

The final source build has zero warnings/errors. The focused Windows suite passes **362 tests**
with one skipped; the full Linux suite passes **3,666 tests**, with **147 skipped and zero failures**.
The Linux checkout matches the Windows production and test sources exactly. Tests include nested
and open-ended exception regions, edits between block/region queries, and addressed-field named
uses and indirect writers changed between inference invocations.

Raw timings, pinned build/input manifests, comparison results and verification evidence are kept
under `C:/cilantro-verify/wms-performance-20261120`. Some unchanged stages varied between runs;
the total wall time above is the measured improvement, rather than a sum of selected pass savings.

## Earlier WMS emission measurement

The managed WMS child (`9e76d2c69d058e209da12460dba98c5947a6d65b78aec310b69438fad1e8608e`)
completed all 136 pass decisions and recursive child recovery in **1,271.248 s (21m11s)** on
2026-11-19, with CLI success and structural verification passing. This local run used
`--no-devirtualize --keep-names`, the 11 matching installer libraries and a 128-million-step
declaration; no passes or emission gates were bypassed. Missing LumiSoft metadata had previously
blocked proxy initialization, so the libraries are part of the reproduction inputs.

The output restored 25,361 bodies, 194,451 proxy calls and all 24,780 protected string sites.
Two emission runs produced the same cleaned-file SHA-256:
`69e04e403949b7a2e83517ceabb4ed3586c541b189b6d2e6eeeba6ae093d1aa7`.
The first run exposed a subsequent child-library inheritance failure; the confirmation includes
that fix. Evidence, dependency hashes, declarations and commands are retained locally under
`C:/cilantro-verify/wms-investigation/emission-results.txt`.

This is a local reproduction, not an isolated paired speedup measurement. VM reconstruction
was disabled, the integrity verdict remains partial, and independent ILVerify still reports
type errors, including existing erased-signature helper errors exposed in callers by inlining.
Cleaned emission and structural verification do not establish full IL verifiability or complete
runtime deprotection. The non-high-cost regression suite passes 3,475 tests, with 116 skipped.

Release validation also compared the complete Reactor 6 corpus outcomes against the original
1.0.6 binary: all normalized outcomes matched. Both builds exposed an outdated mutation ceiling
for `mlfhntkcvb-payload` (20,134 observed versus 20,132 pinned). The ceiling now reflects that
unchanged baseline; both cleaned outputs hash to
`c01d24a8c9357a295494ae85208817e66707191760fe6f5f4db40b08ddf7af4a`.

## Reproduce

Build the versions into separate directories so a running benchmark never loads a mixture of builds:

```powershell
dotnet build src/Cilantro.Cli -c Release -o artifacts/performance/candidate-bin
pwsh -NoProfile -File corpus/measure-performance.ps1 `
  -Tool artifacts/performance/candidate-bin/cilantro.dll `
  -Samples C:/cilantro-verify/samples `
  -Output artifacts/performance/candidate -Repeats 3
python corpus/compare-performance.py artifacts/performance/before/1 artifacts/performance/candidate/1
```

Use a fresh output directory. `runs.csv` records monotonic wall time, process exit codes and
pass/fail/missing counts for each manifest and repetition. `passes.csv` records every pass's
duration, status, mutation count and input hash, including embedded child analyses. Pass times
overlap across samples, so their sum is work attributed to artifacts, not corpus wall time.
Missing samples or failing expectations stop the measurement instead of becoming faster results.

The comparator checks corpus outcomes (including cleaned output hashes and oracle comparisons),
analysis reports, change records and blocker reports. It ignores pass durations and substitutes
output-directory prefixes; recovery metrics, evidence, verification results and payload hashes
must still match. Keep raw reports with the CSV files.

VM program listings and lifted IL are also compared in full. `environment.json` records binary
hashes, SDK/runtime inventory, OS, processor count and explicit GC overrides.

Run final timing comparisons without profiling or competing test runs. Sampling traces locate
bottlenecks but include GC pauses and blocked thread time; they are not hardware CPU counters.

## Bottlenecks addressed

- **Type lookup during interpretation and VM probing.** Repeated `ModuleDef.Find` calls walked
  all declarations. A scoped dnlib index now covers each interpreter execution and the read-only
  VM disassembly pass. Nested scopes preserve the caller's setting; disposal invalidates an index
  introduced by the scope before later metadata changes.
- **Method resolution and virtual dispatch.** Repeated calls resolved the same operands and
  searched the receiver's methods again. Execution-local caches retain successful and unsuccessful
  resolution, with virtual dispatch keyed by operand, receiver type and module. Execution
  boundaries clear them so callers can change metadata between warm runs.
- **Built-in intrinsic selection.** Native/framework matchers repeatedly resolved and classified
  the same methods. Their selections are cached during one execution. Explicit custom registries
  keep dynamic selection, and modeled generated modules bypass metadata-dependent caches.
- **Dispatcher candidate scans.** A round computed every plan but committed only the first.
  It now stops at that first plan, and computes unaliased integer locals once per round.
- **Exception-region allocation.** Repeated CFG construction allocated a membership list for
  every instruction and checked every clause each time. Membership now changes only at clause
  boundaries; instructions within an interval share an immutable snapshot in original clause order.
- **Graphs built for narrower queries.** Branch threading and branch-convergence checks now
  build exception membership without constructing blocks and edges. Discarded-value analysis
  partitions blocks without adjacency. Both paths retain all original clause boundaries;
  membership queries are rebuilt after edits, and methods without clauses need no region map.
- **Addressed-field inference.** Each type-restoration invocation indexes named uses, type
  handles, member references and addressed-field uses once. Its read-only inference phase
  shares method graphs, while every indirect writer is still proved against the current
  inferred types. The index and graphs are discarded before the next pass invocation.
- **Snapshot fingerprints.** Structural snapshots still freeze their representation before
  edits, but compute its SHA-256 only when a caller requests the fingerprint. Rollback and
  structural comparisons retain the original captured state.
- **Rollback-only rewrites.** Dispatcher paths, effectful dispatcher paths and control-flow
  completion capture the same restoration state without constructing a structural description.
  The public transaction and snapshot APIs retain their capture-time description and fingerprint.
- **Dispatcher fallback analyses.** Known-store analysis reuses the current round's graph and
  successful stack verification. Both were computed before any body edits; neither survives
  a rewrite or another round. Other callers still build and verify their own analysis.
- **Control-flow completion workers.** Standalone completion uses the same method-local
  cleanup already called from dispatcher workers, with at most four workers. Bodies are loaded
  before dispatch; reports and accumulated facts are published in original method order after
  all workers finish. Modules with fewer than 64 nonempty methods remain sequential.
- **Provenance after saturation.** Arithmetic and literal tracking now returns the same budget
  node immediately when the graph is full, avoiding discarded location and parent work.
- **Condition folding.** The backward producer search runs only for conditional instructions.
  Argument operands use dnlib's maintained parameter index instead of repeatedly searching its list.
- **Constant-local proofs after proxy recovery.** Local reads, stores and address escapes are
  indexed in one instruction scan. Straight-line store/read intervals without alternate entries
  use that index; other layouts retain the reachability proof from method and exception roots.
  Those proofs share instruction positions and use a set of reads instead of rescanning lists.
- **Unused dataflow state.** Constant folding tracks only integer locals that have reads,
  avoiding copies of dead temporary values at every control-flow block. Store-map queries
  retain all eligible locals, including unread stores used by dispatcher recovery.
- **Interpreter frame defaults.** Scalar local defaults are copied once per execution instead
  of repeatedly reading dnlib's locked local list on every helper call. Modeled dynamic modules
  bypass caches whose metadata could change during execution.
- **VM trial snapshots.** Snapshot entries are value types, array/list element paths are reused
  within a trial group, and later snapshots reserve the previous size. Every element and its
  value is still observed and restored; the path-cache cap only bounds retained text.

Bounds, candidate order, independent recovery trials, verification and rollback policies are
preserved. Timing improvements do not come from reducing recovery coverage or work budgets.

## Garbage collection

The CLI and MCP hosts enable server GC. An isolated pinned `probe-net48-full` comparison on
the same optimized build ran workstation/server, then server/workstation, with no competing
analysis or test jobs:

| GC mode | First run | Second run | Median |
| --- | ---: | ---: | ---: |
| Workstation | 103.03 s | 106.29 s | 104.66 s |
| Server | 58.97 s | 59.13 s | 59.05 s |

That is a 43.6% wall-time reduction. Both modes passed the pinned corpus gate and produced
identical reports and VM listings. The repeat pair used 109 CPU seconds and 1,291 MB peak
working set for workstation GC, versus 173 CPU seconds and 1,633 MB for server GC. Lower wall
time therefore trades additional CPU and memory; runtime GC overrides remain available.

A further four-heap server-GC trial took 55.16 s, only 6.6% below the default server-GC median.
It passed the same gate but did not meet the requested 25% improvement threshold, so no fixed
heap count is shipped. [.NET runtime overrides take precedence over app defaults](https://learn.microsoft.com/en-us/dotnet/core/compatibility/deployment/9.0/envvar-precedence);
for example, `DOTNET_gcServer=0` selects workstation GC on this .NET 10 tool.

## Validation and stopping criterion

The original build took 171.29 s on the same isolated `probe-net48-full` fixture. The
optimized server-GC median of 59.05 s reduces that latency by 65.5% (2.90 times as fast).
All eight detailed reports/listings matched between those builds, and between the GC variants,
after the comparator's timing/path normalization.

The final Release build passed all 2,931 tests, with zero failures or skips. Tests ran from
`C:/cilantro-verify/performance-checkout`, using samples and temporary directories beneath
`C:/cilantro-verify`, including synthetic assembly generation previously blocked by Defender.
No Defender configuration changes were needed.

The preserved original build at `81d6a80` ran once; the optimized working tree ran twice.
These runs were uncontended, used the same samples and runtime, and passed all 24 cases:

| Manifest | Cases | Original | Final run 1 | Final run 2 | Final median | Reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ConfuserEx | 2 | 44.58 s | 30.45 s | 26.31 s | 28.38 s | 36.4% |
| Reactor 6 | 13 | 662.46 s | 317.63 s | 296.45 s | 307.04 s | 53.7% |
| Reactor 7 | 9 | 424.51 s | 128.44 s | 116.18 s | 122.31 s | 71.2% |
| Total | 24 | 1,131.56 s | 476.52 s | 438.94 s | 457.73 s | 59.5% |

All 110 detailed reports/listings matched the original build in each repeat. Raw results
and environment metadata are retained under `C:/cilantro-verify/performance-benchmarks/final`
and `C:/cilantro-verify/performance-benchmarks/final-original`. Neither run set a GC environment
override: they used each build's shipped defaults. The isolated GC comparison above separates
the runtime configuration effect from the other implementation changes.

Largest pass totals in final run 1 (including child analyses):

| Pass | Attributed elapsed time |
| --- | ---: |
| VM disassembly | 230.19 s |
| Method body recovery | 105.72 s |
| Loader call elision | 91.13 s |
| Resource restoration | 62.38 s |
| Dispatcher paths | 55.07 s |

These totals overlap under the corpus runner's existing four-sample concurrency. The native
wrapper's managed child illustrates where the improvement occurred (clean original run versus
final run 1):

| Child pass | Original | Optimized | Reduction |
| --- | ---: | ---: | ---: |
| VM disassembly | 148.22 s | 14.60 s | 90.1% |
| Method body recovery | 166.32 s | 63.90 s | 61.6% |
| Resource restoration | 89.26 s | 32.60 s | 63.5% |
| Dispatcher paths | 31.31 s | 20.89 s | 33.3% |

Original exploratory corpus runs included profiling and competing development jobs; the
final original-build rerun supplies the uncontended comparison above.

Regression coverage includes metadata edits between warm executions, virtual receiver types,
custom registries that change selection, emitted-module edits during execution, saturated
provenance and nested/open-ended exception regions.

The final test-host sampling trace still attributes substantial work to interpretation,
loader-state proof and assembly verification. One sampled virtual-implementation search
accounted for about 17% of attributed Core stack time: even eliminating that search entirely
would fall short of a 25% total reduction in that interval. Loader-state proof and independent
VM trials retain their full execution and verification requirements. Sharing mutable state
between independent trials or reducing budgets was excluded because it changes correctness.
The additional heap-count experiment gave only 6.6%; no further measured change met the
25% threshold. This is a profile-based stopping point for this corpus and machine, not a
claim that every workload or future implementation is optimal.
