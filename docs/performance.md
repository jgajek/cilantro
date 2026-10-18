# Analysis performance

On Windows 10.0.26300 with 22 logical processors, .NET SDK 10.0.402 and runtime 10.0.13,
the optimized corpus midpoint is **457.73 s versus 1,131.56 s** for the original build:
**59.5% less wall time, or 2.47 times as fast**. All 24 corpus cases pass, all 110 detailed
reports/listings match, and all 2,931 tests pass. Measurements were completed on 2026-10-18.

Measure Release builds against the hash-pinned corpus. The corpus runner's policy disables
renaming and VM reconstruction; it still reads VM programs and follows the native wrapper's
managed child. These measurements describe that policy, rather than every CLI option.

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
- **Provenance after saturation.** Arithmetic and literal tracking now returns the same budget
  node immediately when the graph is full, avoiding discarded location and parent work.
- **Condition folding.** The backward producer search runs only for conditional instructions.
  Argument operands use dnlib's maintained parameter index instead of repeatedly searching its list.
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
