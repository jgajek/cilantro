# CILantro - full-corpus unprotection status

## Fresh Vault additions: observed readability gaps closed

The 2026-10-15 live `protector:reactor` inventory contains **31 hashes**, two more than the frozen inventory below: `Byalsx.exe` (`3f07fba4541728fb35be7d260114b768caa0402a62ef911b5a48afe28a41ece9`) and its embedded `Lkukzk.dll` (`bfcbbc824a4de6202ff9a008625210e25ad0bd45beb483a502d1208b14d0094f`). The frozen-corpus completion decision does **not** establish full unprotection of these additions.

The initial 0.10.6 trial exposed residual nested XOR-driven dispatcher logic, constant-condition clutter, and layered string-decoder calls despite a zero remaining-dispatcher counter. **The current unreleased source fixes those three observed gaps.** Generic branch-edge specialization and multi-local path recovery remove all five residual state switches; the seven application switches retain their method identities and case counts. A bounded literal string/key decoder pass resolves all 319 calls across the two decoder layers, preserving initialization triggers, persistent application state and fresh string allocation. Constant-condition clutter is gone. All five payload resource hashes are preserved.

Fresh recursive recovery from Byalsx with the final build succeeds across all three managed nodes. Both extracted payload hashes are unchanged, the recursively cleaned Lkukzk matches the standalone result, and the independent VM-retirement gate passes. The payload has zero ILVerify findings; repeat guard/control-flow cleanup makes zero changes throughout the chain. All 2,858 fast tests pass, including new tests for merged boolean selectors, pure multi-local paths, initialization order, array-mutation refusal and fresh string identity.

Authoritative local evidence for this update is `artifacts/payload-gaps-verified/report.md`, `chain-check.json`, `chain-physical.jsonl`, `vm-removal.json`, `release-payload-preservation.json` and `release-payload-source-check.json`. Outputs are under `C:/cilantro-verify/review-trials/payload-gaps-release-check`. The earlier `artifacts/vault-refresh-2026-10-15` evidence remains the before-state. Protector attribution of the additional layer is not established; the fixes use code structure rather than sample names or protector labels. Initialization-only helper references are deliberately preserved. This closes the three observed gaps, rather than making an unrestricted claim about every possible protection or rerunning the old 43-root sweep.

## Frozen 0.10.6 release checkpoint

Latest checkpoint: **2026-10-15**, 0.10.6 release checkpoint. **The full-unprotection goal is complete for the agreed frozen undamaged corpus.** All original-input recovery and final audits are finished. No recovery or validation job remains running, and no further full sweep is required for this state.

Scope remains **43 roots**, including all **28 undamaged hashes** in the captured 29-sample Vault `protector:reactor` inventory. The sole excluded damaged NETReactorSlayer rewrite is `c76290907b62922234be97bf7248fae44af35b2b9186c0cca6bc50b0ad36f065`. This is a corpus-specific completion decision, not a fresh Vault inventory or a guarantee for unseen samples.

| Requirement | Final evidence and result |
| --- | --- |
| Complete original-input coverage | 43/43 complete: 37 ordinary recoveries, three declared negative controls, three successful same-build explicit generic recoveries. |
| Physically remove VM machinery | Independent gate passes all 18 contexts covering all 14 intact virtualized identities; reconstructed application methods and retired protector bodies are accounted for. |
| Remove Reactor code, guards, resolvers and protection resources | 104 managed outputs inspected, all structurally verified; zero identified retained VM/proxy/string-resolver/guard/integrity/trial/dead-prefix candidates. All final heuristic hits have explicit application/payload dispositions. |
| Preserve application logic and switches | Existing reconstruction, surviving-body and switch checks retained. Latest type repairs change only proven casts and branch widths; caller and metadata checks pass. Final repeat-cleanup review finds no additional dispatcher or guard removal. |
| Preserve and recover payload chains | Preservation passes all 43 roots, with no missing required identities or captured payloads. All 12 occurrences of four reviewed SQLite dependencies preserve their bytes. Native-wrapper recovery continues through the managed stage; all three entry paths produce identical stage bytes. |
| Resolve native dependencies | VGeko dependencies are identified as Go application libraries. Native gRPC executable sections/import bindings match the pinned upstream package after recorded UPX unpacking. These are payload dependencies, not remaining Reactor machinery. |
| Regression validation | 2,852 fast tests pass; final restriction passes 20 focused tests; all 100 saved-context replays pass. Current final output hashes were rechecked against the physical audit before closure. |

**Final candidate dispositions:** the four stub-shaped observations are the original application zero-return methods `ReadUInt64` (three copies) and `EmptyList.Count`. The 27 retained classified resources are managed/native application payloads. None requires deletion for Reactor removal.

**Optional polish, not an unprotection blocker:** one resource-manager method, present in three identical stage outputs, contains 13 discarded integer constants. A diagnostic cleanup changes exactly those 26 instructions to no-ops; every other instruction and branch-target index is identical, and the method contains no switch. This is harmless dead-instruction cleanup, not VM machinery, opaque guards or remaining dispatcher logic. The 135 IL-verifier findings in the large stage are likewise not protection counts; reconstruction evidence and benign unsafe-C# controls are recorded separately. Completion does not claim arbitrary whole-program equivalence or zero decompiler warnings.

The local authoritative decision is `artifacts/il-review/reference-lookup-closure.json`. Detailed trial artifacts are retained in the analysis workspace, not shipped in this repository or release. This page is the public evidence summary. Supporting files under `artifacts/il-review` are `reference-lookup-scope.json`, `reference-lookup-root-dispositions.json`, `reference-lookup-preservation.json`, `reference-lookup-original-nodes.json`, `reference-lookup-vm-retirement.json`, `reference-lookup-physical.jsonl`, and `reference-lookup-finalization-disposition.json`. The earlier `reference-lookup-closure-inventory.json` intentionally records only inventory completion; the final decision adds reviewed candidate dispositions and output-hash verification.

The contract preserves actual corpus application/payload behavior and readable recovered CIL, permits deliberate protector-metadata removal, and retains application switch statements. It does not cover arbitrary external/reflection callers. This completion checkpoint is included in release 0.10.6.

## Historical evidence

The [investigation log](history/unprotection-0.10.6.md) preserves intermediate builds and diagnostics. Its open-gap statements and counts are historical and do not override this completion summary.
