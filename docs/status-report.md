# CILantro — full-corpus unprotection status at 0.10.5

Updated **2026-10-05 (America/Toronto)**, incorporating targeted trials recorded through **2026-10-05 UTC**. The published 0.10.3 baseline was frozen **2026-09-29 02:31:48 UTC** (2026-09-28 22:31:48 Toronto time). It contains **44 distinct root hashes**, **118 assembly observations**, and **85 unique assembly input hashes** across **52 trial records**; repeated trials and child contexts are not additional unique samples. All **29 of 29** hashes in the baseline `protector:reactor` Vault query were tested, including `5bbe36d3191e…` (`WindowsManagement.managed.exe`). The Vault inventory has not been refreshed since that query.

The **baseline** root classification remains **29 success / 15 incomplete** in the per-input matrix. Three incomplete entries are intentional unprotected negative controls. This matrix has not been regenerated with the fixes below, and its selection retains original long-path trials rather than substituting successful short-path follow-ups. “Success” means the configured pipeline completed its allowed output, not complete unprotection. Do not infer a new corpus-wide success count from targeted fixes.

## Item #1 closed — VM removal verified for all 14 intact inputs

Full unprotection requires **physical removal of VM machinery**, with application logic retained as readable CIL and payloads preserved. The previous bounded-reconstruction closure was incorrect and has been withdrawn.

The frozen current run under `artifacts/progress-closure/vm-removal-final/` completed:

- **14/14 intact virtualized inputs** emit verified assemblies with **zero retained identified VM types**. All **14 VM data resources** are removed. This covers all three known virtualized child hashes as well as directly submitted samples.
- All **28 reconstructed methods/programs** remain as CIL. All 14 assemblies disassemble and decompile with ILSpy (exit 0); this is not a warning-free-source claim.
- **36,036 surviving methods** have unchanged bodies, locals and exception handlers, compared with the prior output using recorded rename maps. Retained field data, resources and entry points match; only declared VM resources were removed.
- **15/15 benign runtime comparisons**, **24/24 captured payload observations** and **1,294 selected regression tests** pass. Malware trials remain static interpretation.
- The native stage loses **2,992 obsolete types and 12,726 methods**: 786 VM methods, 11,772 recovered proxy methods, 130 recorded inlined forwarders and 38 reviewed Reactor support methods. All **32,752 surviving methods** are unchanged. Its **80/80 ordered resolver outcomes** match the preceding output, including loaded bytes and repeat-call identity. Coupled startup still matches captured application state and native writes.

Native C# decompilation has zero decompilation failures; unknown-result warnings decrease from 572 to 478. Residual warnings and the broad native trial's two artificial pre-initialization differences remain visible. The raw full-state gate is not overwritten. The earlier method-trial totals remain 38 agreed / 138 disagreed / 34 inconclusive; bounded application-contract matches and deliberately removed protector state are assessed separately.

The scope contains **15 unique VM-bearing input hashes**, not 14. The previously rewritten NETReactorSlayer `Lqcuzgc` (`c76290907b62…`) still has stale/missing VM token targets, rebuilds no methods and fails the physical-removal gate. Its intact original (`81cf796c987d…`) now has a verified VM-free output. The two files share their MVID and seven retained resource hashes. `artifacts/vm-removal/lqcuzgc-recovery-from-original.json` records that available recovery path and its output; it does **not** claim to repair the rewritten file in place or preserve hypothetical changes unique to that file.

**Item #1 is closed under the accepted criterion:** fully handle the 14 intact virtualized inputs, preserving application logic and payloads while removing the VM machinery. Inputs damaged by other tools may be rejected or retained as partial analysis with an explicit warning; repairing them is not required for closure. The CLI and HTML report warn that incomplete VM reconstruction is not full unprotection and recommend the intact original. The damaged Lqcuzgc copy remains a recorded unsupported input, not a successful reconstruction. This closure does not assert completion of the other corpus work below.

Cleanup now removes isolated, positively identified VM/proxy types even when unrelated application reflection prevents precise general reachability. Live `member.Module.ResolveMethod(member.MetadataToken)` round trips no longer block metadata compaction; unexplained numeric-token consumers still do. VM-only resources are removed with application/payload exclusions and recorded hashes.

The accepted closure decision is recorded in `artifacts/vm-removal/closure-0.10.4.json`. The per-input measurement remains in `artifacts/vm-removal/assessment.json`, where the damaged input is still a failed direct recovery. Independent emitted checks, surviving-code comparisons, the native deletion review, final resolver trials and source/build hashes are in that directory. `corpus/verify-vm-removal.ps1` passes all 14 new intact outputs and rejects both the earlier native output and the damaged copy. The native deletion review explicitly accounts for the 38 support methods not classified by the automatic audit.

Earlier bounded reconstruction evidence remains in `artifacts/progress-closure/array-final/`, `array-final-evidence.json` and `resolver-proof-comparison.json`. The original-versus-final positive resolver proof required a separately recorded 1.2-billion-step bound; production limits were not raised. The original's extra resource-only satellite has zero methods; all 47 streams survive byte-for-byte, and its full image remains an extracted artifact. The SharpZipLib image remains `c287e9b07a8251828f35914364c89a37db606b0c1d64457f9eb8fa2258f0dee3`.

These finite checks do not prove arbitrary computed reflection, other hosts/inputs/requesters/preloaded assemblies or unvisited later calls. This targeted sweep does not refresh the 44-root release matrix or the 29-sample Vault query.

## Application unflattening — dispatcher and opaque-guard sweeps complete

The post-0.10.4 work now covers **all 85 baseline hashes**: **83 intact managed inputs** have strictly written outputs, the native bootstrap is accounted for by its separately recovered managed stage, and the previously accepted damaged Lqcuzgc exclusion remains explicit. The Vault inventory has not been refreshed. This is a post-recovery control-flow sweep, not a new end-to-end root success matrix.

The sweep removes **2,724 switches** (3,657 → 933) and **17,453 instructions**. It handles stack-carried state, conditional incoming dispatcher edges, shared state stores, duplicated-null guards and longer nested arithmetic dispatchers. Late constant-helper discovery revisits callers independently of metadata order, preserving helper calls and type-initialization effects. The native resource initializer's protector switches and the remaining nested arithmetic dispatchers found in intact Lqcuzgc/Uescfpvjk are removed.

The two earlier closure obligations are resolved:

- **Emission and missing-output coverage:** all 83 managed outputs pass strict dnlib writing. The backward stack discard and dead exclusive exception-end defects in `mc.dll` are fixed; moving an exclusive end across deleted instructions preserves every surviving instruction's exception-region membership. The raw historical logger needs the existing one-attribute metadata repair before writing. The additional 21 managed entries include unprotected controls, dependencies and resource-only assemblies; they were inspected, not dismissed solely by their protector label.
- **Residual switch review:** all **933 switches in 821 methods** have a recorded functional role and selector evidence. These include parser tags, enum dispatch, dictionary-based string switches, async/iterator state, argument-emission loops, metadata-table selection and lexical casing state. Application switches remain. The earlier 220-candidate inventory was insufficient: it missed arithmetic selectors, so it is superseded by this all-switch review.

Validation preserves **65,008 method identities**, all retained resource bytes and entry points, with no increase in per-method stack diagnostics. All **14 VM-free outputs** decompile; their final hashes match the decompiled artifacts. All **15 benign runtime comparisons**, **62 focused tests** and **1,295 selected regression tests** pass. Qbjuef and intact Lqcuzgc also complete fresh end-to-end static pipeline runs. These checks do not assert that all decompiled source is warning-free or establish arbitrary malware runtime equivalence. No malware was executed.

**The identified opaque-guard remainder is now closed under the accepted protector-metadata cleanup contract.** The native managed stage (`83ba5d833eba…`) loses all **62,470 application guard-field reads across 15,918 methods**, and the **100 protector integer fields** and their assignments are physically removed. No reads of those fields remain. `Stub.HeavensGate.Execute64` now decompiles into ordinary application control flow with its register-selection switch intact. This round removes another **76,469 CIL instructions**; all **933 application switches remain**, including the same switch count in every original method.

The new pass derives literals from the reconstructed initializer's complete straight-line construction, rather than a captured snapshot. It requires the identified Reactor state-field family, a reconstructed initializer, a pure object constructor, one confined initialization call chain, and direct reads from the same singleton. Additional writers, address-taking, escaping references, explicit reflective handles/names, and unexplained reachable numeric-token consumers refuse cleanup. The original publication and initializer prefix/suffix remain. A small `EnsureProtectorInitialized` helper preserves type-initialization and null-check exceptions, including recursive entry before publication; successful checks are only coalesced along proven normal-flow paths. Exception-handler entries do not inherit successful checks from a throwing path.

**Reflection boundary:** this is removal of positively identified protector metadata, using the already accepted permission to remove that metadata. Arbitrary computed reflection over the removed guard pool is not preserved or claimed impossible. The general `FieldWriteSafety` reflective-write refusal is unchanged; unrelated application reflection remains. `--keep-runtime` disables this cleanup. This is not a general theorem that private fields cannot be modified reflectively.

Final validation: **83/83 strict writes and preservation checks**, all **65,008 original method identities**, retained resources and entry points preserved, no increased per-method stack diagnostics, and one declared initialization helper added. **82 outputs are byte-identical** to the preceding sweep; only the native stage changes. Its complete ILSpy decompilation succeeds, and the other 13 VM-free decompilation results and benign runtime results remain bound to unchanged bytes. **14/14 VM-removal checks**, **81 focused tests** (including 19 new guard-completion cases), and **1,295 selected regression tests** pass. Repeating guard completion and control-flow finalization produces no further changes on all 83 outputs. These finite checks do not establish arbitrary malware runtime equivalence. No malware was executed.

The identified dispatcher/opaque-guard work is complete for this frozen managed-output set under that contract. This does not close the separate extraction, native-code recovery, damaged-input or baseline-matrix refresh obligations below.

Frozen evidence is under `artifacts/unflatten-0.10.4/`: `summary-final.json` binds all 83 inputs and outputs by hash; `switch-review.json` records the 933 selector classifications; `verification-final.jsonl` records preservation checks; `census-final.jsonl` records the guard remainder. `Program.cs`, `audit.csproj` and `finish-review.ps1` retain the local audit tooling. `settled-final.jsonl` records a repeated production-finalization check; no additional rewrite or round-bound exhaustion is observed. Trial outputs are under `C:/cilantro-verify/review-trials/unflatten-0.10.4-final/`. These are local evidence files; samples and cleaned assemblies are not committed.

The subsequent guard-removal evidence is `guard-final-summary.json`, `guard-hashes.json`, `guard-final-verification.jsonl`, `guard-final-census.jsonl`, `guard-final-settled.jsonl`, `guard-final-identity.jsonl`, and `guard-final-vm-verification.json`. `guard-current-build.jsonl` records the final build reproducing all 83 output hashes, with identity/structure gates passing under the declared changes. The preceding evidence remains historical and is not overwritten. Current outputs are under `C:/cilantro-verify/review-trials/opaque-guards-final/`; `guard-final-native.cs` is the complete static decompilation of the changed native managed stage.

## Progress since the baseline

These changes are included in the 0.10.4 release, following the 0.10.3 baseline `b2af319995e0f5a05fecc9a45426538673d63f61`. No malware was executed. The latest selected local regression suite passed **1,294 tests**.

| Item | Current status | Evidence and boundary |
| --- | --- | --- |
| Windows long-path reloads | Reproduced blocker fixed | All three rYOxGYwkD/Jdclyzspurl chain assemblies verify, including 282-character child paths; emitted hashes match the short-path baseline. The released executable fails a separate 277-character-path trial that the fixed executable passes. Baseline affected 33 child observations across ten root cases; all ten have not been rerun. |
| Historical logger's invalid attribute | Reproduced defect fixed | One attribute with a missing constructor is removed and logged; invalid constructors are now rejected by verification. ILSpy changes from exit 70 to exit 0. Valid external attributes are preserved. This does not repair arbitrary metadata damage. |
| Native Costura extraction | Fixed for observed resources | Both `costura32.vgeko.dll` and `costura64.vgeko.dll` are extracted; malformed siblings no longer discard successful extractions. Costura resources are no longer misreported as encrypted Reactor bundles. |
| Nested application resource PEs | Observed gap closed | Two more DLLs are extracted from named byte-array entries in `VGeko.Properties.Resources.resources`. Managed and native PE extraction also supports stream entries without deserializing custom objects. |
| UPX layers | Four observed DLLs unpacked | Optional `corpus/unpack-native-dependencies.ps1` preserves inputs and records hashes, timeouts and PE checks. All four outputs are native x86/x64 images with no CLR metadata. This is a separate helper, not automatic CLI unpacking or proof of native deprotection. |

VGeko now yields **16 dependencies**, with **13 recovered managed nodes** (parent plus twelve dependencies) and **four native extracted-only nodes**. The chain deliberately remains incomplete. All twelve previously extracted managed payload hashes are retained. The new resource-entry pass was checked separately on all 44 baseline root inputs: all 43 managed inputs passed; the native WindowsManagement wrapper is outside its input type. This was not a full end-to-end corpus rerun.

## Scope and interpretation

This sweep uses the published Windows x64 CILantro 0.10.3 executable from commit `b2af319995e0f5a05fecc9a45426538673d63f61`. It schedules **44 distinct root hashes**: all 24 non-oracle-tier entries in the three pinned corpus manifests, plus 20 additional hashes from Malware Vault. The manifests include three intentional unprotected negative controls. The Vault query returned **29/29** `protector:reactor` hashes with an exact total, no truncation and no next page; nine already appear in the pinned manifests. Three Reactor 7.5 unprotected oracle-tier files serve as references rather than recovery targets.

All 16 Vault samples absent from the local sample directory were downloaded and SHA-256 checked. Samples and recovered binaries remain in `C:/cilantro-verify`. No sample was executed in the host CLR. Recovery uses bounded static interpretation, reconstruction, recursive extraction and metadata inspection. The standard measurement budget is 192 million interpreter steps, preserving each manifest entry's declarations, host profile and library settings. This is a high-budget recovery measurement, not the default-budget experience or a fresh runtime-equivalence test.

Root hashes, extracted child hashes and repeated recovery contexts are reported separately. A tagged hash may be a native wrapper, an extracted stage, an already deobfuscated artifact, or an input whose tag is not corroborated by CILantro's detector. These are not interchangeable independent protected programs.

`Success` means the configured pipeline emitted an output (or completed its allowed analysis); structural verification does not establish full unprotection. Residual switch candidates are heuristic method counts, not confirmed protector dispatchers. Unsupported passes can mean absent features. Unwalked VM operations can be in paths the recovered graph marks unreachable. Cold-state disagreement and missing extraction evidence remain limitations even when output is readable.

## Confirmed findings from the expanded set

### Native embedded content in VGeko

The new `d6072175…` input identifies its managed module as `VGeko.exe`. Baseline recovery recognizes no supported protector, emits no parent cleaned assembly, and extracts 12 Costura managed dependencies. A separate `--generic-recovery --recover-embedded` trial emits verified output and reports all 13 parent/child nodes as recovered. The baseline failure is therefore partly an option/detection boundary.

`Mbsumkxdegf.exe` (`5e10c356…`) emits a verified assembly with zero unresolved detected strings or method stubs and 329 runtime types removed. Its reconstruction comparison remains disagreed, 14 VM operations are not walked, and payload extraction is partial after one managed load. This is representative of the larger Reactor dropper class: readable, structurally valid output with bounded but incomplete semantic and extraction evidence.

The follow-up implementation extracts the two raw native Costura PEs and the `grpc_csharp_ext_x86` / `grpc_csharp_ext_x64` entries inside `VGeko.Properties.Resources.resources`. All four unpack successfully with UPX 5.2.1, remain native, and expose no managed stage to continue into. The erroneous encrypted-resource diagnosis is gone. The two managed dispatcher candidates are async `MoveNext` methods, not established Reactor flattening. Native semantics/deprotection and arbitrary encrypted or serialized resource content remain outside this completed extraction evidence.

| Native resource/entry | Packed bytes | Unpacked bytes | Unpacked SHA-256 |
| --- | ---: | ---: | --- |
| `costura32.vgeko.dll` | 2,206,208 | 6,159,360 | `1e100cab80e67e584be5210c9fc933f1ec192959d76f323d7d4a168df33a7704` |
| `costura64.vgeko.dll` | 2,380,800 | 6,341,120 | `738c2253706b6a8a569f84dfa63f080e7defdd21dffaa80dda0089939ba7ff16` |
| `grpc_csharp_ext_x86` | 2,460,952 | 9,986,840 | `43a874c85d666408024b213108f7949e0bad9412889d801f325d251105335cca` |
| `grpc_csharp_ext_x64` | 3,557,144 | 12,684,568 | `84a809da5d42ea7091e83d0c3e5c18696bc4c857be490e7ef17a361eeba83254` |

### Reconstruction agreement and application behavior

The acceptance contract permits deliberate removal of protector metadata while preserving
application behavior and payload bytes. Full-state equality is therefore reported separately:
the original VM populates interpreter caches which reconstructed CIL does not need. A VM-owned
label alone is insufficient to exclude those caches from application observations.

The current comparison checks independent cold calls, each side's own repeated call, retained
first-call return values and arguments, module-initialized calls, and coupled startup with all
reconstructed bodies/callers installed before initialization. Resolver callbacks run in order;
each response is snapshotted immediately and its objects remain reachable for later alias checks.
The comparison includes modeled native memory and write history, domain registrations, application
statics and metadata handles. Unsupported work remains inconclusive. Unknown host facts are
not invented to turn a fixture green.

The final-module audit resolves original field tokens after cleanup and records removed,
retained and unresolved roots separately. On the ten non-native malware inputs, completed
fixtures match captured application state, no modeled VM sharing or escaped VM handles was
found, and differing roots are confirmed removed. The identified pure VM-wrapper debugger
throw is counted separately only after independent guarded comparisons and confirmed removal.
These findings are finite path evidence, not universal equivalence for arbitrary inputs.

All 28 recovered programs in the final frozen 14-input sweep decode their 61,700 operations.
No branch target remains inferred after handler-backed branch/switch trials. The 126 operations
not walked by the recovered graph are explicitly classified unreachable in that graph; this
classification remains dependent on the recovered semantics. The three source-built benign
Reactor probes also pass all 15 runtime-oracle checks after removal of their exact generated
trial-expiry guard. Malware is never executed in the host CLR.

The native WindowsManagement managed stage completed the final coupled-startup sweep.
Earlier callback comparison stopped at Costura's `AppDomain.GetAssemblies`; the new
explicit inventory fixture and assembly-identity models address that concrete unsupported path.
Its two pre-initialization stress differences include native loader writes. Those artificial
fixtures cannot substitute for coupled application startup, which now matches captured
application state and native writes. Normal external entry follows module initialization;
calls made from within the initializer are included in the coupled trial.

A metadata-only audit of the emitted native stage finds a non-public, 46-type VM-engine
subtree with no outside explicit references through IL, signatures, attributes, constraints,
overrides, exported types or exception clauses. Its metadata is nevertheless retained because
of numeric-token consumers. The reported dnlib importer obtains both module and token from a
supplied `MethodBase`; that site alone does not demonstrate discovery of VM cache state.
Neither this inspection nor the explicit-reference audit excludes arbitrary numeric/string
reflection or external callers. The raw reconstruction verdict remains unchanged.

Evidence lives in `artifacts/progress-closure/`: `array-final-evidence.json` is the final
frozen sweep; `array-final/startup-review.json` retains coupled-startup diagnostics;
`stub-final-engine-boundary.json`, `stub-engine-name-references.json`,
`stub-costura-boundary.json` and `stub-token-consumer.il.txt` record the native metadata
review. The Costura closure includes 17 methods, including field-owner initializers,
and references no VM-engine members. The current selected regression passes 1,281 tests.
Earlier builds and the archived `status-before-final-assessment.md` remain historical
evidence, not the latest closure decision.

### Extraction completeness and code removal

Small Reactor payloads such as Frzfqnvunjz, Ggdzylx and Msfhjjpkive recover their detected strings and show no unresolved method stubs. Some startup/decoder paths still stop at tamper guards or unknown state, and extraction paths request registry facts. Reflection prevents deletion of all apparently unused methods. For Dradg, the unpacker captures the managed payload before a later `Assembly.GetType` operation is denied. This demonstrates recovery of that payload, not exhaustive exploration of every later startup path.

### Remaining switches and decompiler readability

The fresh high-budget Lqcuzgc output has 22 IL switches in 15 methods, one dispatcher-shaped method, and 672 unreachable instructions. This differs from the release note's earlier default-run measurement; the settings and artifacts should not be conflated. Metadata and ILSpy inspection identify the candidate as an `IAsyncStateMachine.MoveNext` method whose switch restores awaiters and resumes suspended work. Reason.PAC's sole candidate is also `MoveNext`. These hits do not justify deleting their switches. Restoring decompiler recognition of async methods, improving names, and simplifying proven redundant initialization scaffolding remain worthwhile readability work.

The direct Uescfpvjk run emits verified output with zero detected unresolved strings or stubs, one dispatcher candidate, ten unwalked VM operations, 564 removed runtime types, 557 retained unreachable instructions and an overall reconstruction disagreement. Similar family structure does not make its counts interchangeable with Lqcuzgc.

### Windows output paths

Baseline recursive runs failed to reopen serialized children under long hash-based report paths (`Could not open file ... Error: 00000003`). Verification and corpus oracle comparison now read files through managed I/O before loading dnlib metadata. The fixed long-path chain and executable comparison are described above. Valid, changed, corrupt and missing files are covered by regression checks. The old baseline failures remain recorded until a fresh corpus sweep replaces them.

### Separate reconstruction cleanup gate

The fresh Qbjuef cleanup gate passes with 200 removed types. The Mlf/Lqcuzgc gate fails its 564-type minimum at 561, with no other gate diagnostics. This is a real outstanding assertion in the current validation suite; the standard corpus-gate result must not be used to imply that it passes. See `cleanup-gates/outcomes.json`.

### Previously rewritten inputs

`Lqcuzgc_NETReactorSlayer.dll` (`c76290907b62…`) emits structurally verified output but retains 172 unresolved detected string uses, 41 dispatcher candidates, 648 unread VM operations, 2,510 unwalked operations and one VM stack disagreement; no method is rebuilt and no runtime types are removed. The Vault records it as a partial NETReactorSlayer 6.4.0 cleanup whose method/string decryption failed. Its seven retained resources are byte-identical to the original, while its concrete method-body count is 1,126 versus 2,510. Recovery explicitly fails to resolve VM-referenced token `0x06000672`. This supports a stale-token/removed-metadata diagnosis. It needs provenance-aware repair or reprocessing of its available original (`81cf796c…`), not an assumption that it is another intact Reactor variant.

`rsEngine.Loggers.Application.deobfuscated.dll` (`c3267e21deab…`) is a historical CILantro-produced artifact according to Vault lineage, derived from protected parent `aa942c1e1071…`. The baseline generic output was reported verified but failed ILSpy with exit 70. The precise defect was one field attribute referencing method row zero with no value blob. Sanitization now removes that unusable attribute before IL transforms, logs the removal, and verification rejects remaining null constructor references. Fresh generic output verifies and decompiles with ILSpy exit 0. A metadata-only scan of 44 baseline inputs and 75 retained output paths found this invalid-constructor case only in the historical logger; 118 files were readable as managed metadata, with the native wrapper excluded. The fresh protected-parent recovery already passed ILSpy. Broader metadata damage remains a separate problem.

### Decompiler warnings and dependency context

Successful decompilation is checked separately from process exit and warning-free source. Some outputs contain ILSpy type-resolution warnings around external types such as SQLite. The rsDatabase and Reason.PAC reference oracles also produce such warnings under this dependency context (46 and four respectively), so these are not automatically newly introduced invalid IL. Missing dependencies, metadata limitations and residual obfuscation need separate diagnosis. No malware runtime-equivalence test was performed.

## What remains to establish full unprotection

1. **Closed: VM removal for all 14 intact virtualized inputs.** Reconstructed application CIL, physical VM removal, disassembly, captured payloads and the stated behavioral checks pass. Damaged third-party rewrites are explicitly outside the repair obligation and must produce a warning or error; they are not counted as successfully unprotected.
2. **Complete the remaining extraction and native-analysis evidence.** VGeko's four observed native PEs are now extracted and unpacked; native deprotection is not established. Serialized objects, encrypted entries and arbitrary nested archives are not exhaustively recovered. Registry-dependent and denied-reflection continuations remain unknown. Keep captured-payload evidence distinct from proof that a startup path has been exhausted.
3. **Extend metadata validation beyond the fixed constructor defect.** The historical logger's null constructor case is closed. Arbitrary attribute blobs, other invalid metadata references, and damaged rewritten inputs still need case-specific validation; do not generalize this repair into complete metadata recovery.
4. **Optional: repair rewritten-input provenance.** The damaged NETReactorSlayer Lqcuzgc copy is unsupported and produces an incomplete-reconstruction warning. Its intact original is available and recovers successfully. Automatic provenance matching or repair would be an additional capability, not a condition for closing item #1.
5. **Finish targeted cleanup/readability work.** The identified dispatcher and native opaque-guard work above is complete for the frozen managed-output set under the protector-metadata cleanup contract. Retained initialization helpers preserve effects and exceptions. The Mlf 561-versus-564 cleanup gate, exception-boundary presentation, async recognition and naming remain separate cleanup/readability investigations; they are not evidence of an outstanding identified opaque guard.
6. **Refresh corpus-wide evidence after the fixes.** Rerun the expanded measurement with a frozen current build before changing the 29/15 root matrix. Check all ten formerly path-affected root cases, retain generic-recovery policy distinctions, and keep native extracted/unpacked status separate from full recovery. The observed path failure and native-resource misclassification are fixed, but their corpus-wide effect is not yet measured.

These are corpus-specific completion criteria, not a claim that arbitrary-program behavioral equivalence can be proved by this sweep. No percentage of "fully unprotected" samples is inferred from green structural checks.

## Evidence files

- `vault-inventory.json`: complete tag-query snapshot and hashes.
- `local-inventory.json`: SHA-256 inventory of the local sample directory.
- `outcomes.json`: completed root outcomes, including failures.
- `observations.json` / `observations.csv`: per-assembly contexts, recovery residue, evidence and report locations.
- `vault-coverage.json`: one row per tagged hash, matched to root and child observations.
- `vgeko-resources.json`: metadata-only native-resource and switch classification.
- `generic-vgeko-run.json`: separately labeled generic-recovery follow-up.
- `output-inspection.jsonl`: metadata-only inspection of emitted outputs.

Full per-case reports reside under `C:/cilantro-verify/review-trials/status-0.10.3-standard` and `C:/cilantro-verify/review-trials/status-0.10.3-vault`.

### Post-baseline evidence (repository-relative paths)

- `artifacts/progress-long-path/`: failing released executable versus fixed executable trial, three-node chain, exact output-hash comparison, and regression results.
- `artifacts/progress-metadata/`: repaired logger run, ILSpy output, 119-file metadata scan and regression results.
- `artifacts/progress-costura/vgeko-verified.json`: fourteen-dependency trial and corrected resource classification.
- `artifacts/progress-upx/`: official UPX asset checksum, initial unpacking trials and helper negative checks.
- `artifacts/progress-resource-entries/vgeko-run.json`: latest sixteen-dependency run.
- `artifacts/progress-resource-entries/corpus-scan.jsonl`: resource-entry pass over all 44 baseline inputs.
- `artifacts/progress-resource-entries/native-unpacking.json`: hashes and structural checks for all four unpacked DLLs.
- `artifacts/progress-resource-entries/regression/`: resource-entry suite, 1,216 passing tests.

Latest extracted artifacts are under `C:/cilantro-verify/review-trials/progress-resource-entries/`;
all four unpacked native images are under `C:/cilantro-verify/review-trials/progress-resource-entries-unpacked/`.
This report is maintained in `artifacts/status-0.10.3/status-report.md` and mirrored to
`C:/cilantro-verify/review-trials/status-0.10.3/status-report.md`. The per-input baseline matrix
and raw observations are intentionally unchanged.
