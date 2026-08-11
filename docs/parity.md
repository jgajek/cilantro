# Parity with NETReactorSlayer

This matrix maps ReactorUnpack's passes onto the sixteen stages that
NETReactorSlayer ships under `NETReactorSlayer.Core/Stages/`. It records what is
implemented, where ReactorUnpack is stronger or weaker, and what remains a
deliberate, fail-closed boundary. Everything here is static: no protected
assembly is executed, and every mutating pass rolls back unless structural
verification passes.

Two stages, `ControlFlowDeobfuscator` and `TypesRestorer`, are de4dot-derived
GPL code in Slayer. ReactorUnpack re-derives both from its own CFG and use-site
dataflow primitives rather than porting them.

## Stage-by-stage matrix

| # | Slayer stage | ReactorUnpack pass | Status |
|---|--------------|--------------------|--------|
| 1 | `MethodDecrypter` | `method-body-recovery` | Parity. Static JIT-hook body recovery with write-log identity checks and per-body verification. |
| 2 | `AntiTamper` / `AntiManipulationPatcher` | `antitamper-neutralization` | Parity. Removes only the proven integrity/verification subtree and guarded failure paths, using the static machine's RSA and hashing models. |
| 3 | `AntiTamper` strong name | `antitamper-neutralization` | Parity. The strong-name verdict is proven through the same modeled verification before any edit. |
| 4 | `AntiDebugger` | `antitamper-neutralization` | Partial. Debugger-probe sites are neutralized only where the value provably feeds a Reactor termination path. |
| 5 | `BooleanDecrypter` | `boolean-recovery` | Parity by construction. Detects the `bool(int32)` resolver, proves each offset, and interprets the real resolver to fold sites. No corpus sample exercises it yet. |
| 6 | `StringDecrypter` | `string-table-recovery` + `string-recovery` | Stronger. Table capture and site rewriting are separate, all-or-nothing, and offset-proven through the provenance graph. |
| 7 | `TokenDeobfuscator` | `token-recovery` | Parity by construction. Rewrites constant-fed `Module.Resolve*` proxies to direct `ldtoken`, validating every decoded token first. No corpus sample exercises it yet. |
| 8 | `ProxyCallFixer` | `delegate-proxy-analysis` | Stronger. Bijective field-to-target validation; the stream codec is derived structurally rather than by hash. |
| 9 | `TypesRestorer` | `type-restoration` | Weaker/conservative, clean-room. Promotes non-public `object` fields only when every writer agrees; no public-API signature changes. |
| 10 | `MethodInliner` | `method-inlining` | Parity. Redirects proven single-call pass-through forwarders with stack-neutrality proof and full-body rollback. |
| 11 | `AssemblyResolver` (payload dumping) | `payload-extraction` | Parity. Bounded, strictly framed managed-metadata extraction; the `Assembly.Load` sink is never invoked. |
| 12 | `ResourceResolver` (reattach) | `resource-restoration` | Partial. Decrypts the encrypted managed bundle and records recovered bytes; reattachment and hook removal remain fail-closed pending proof. |
| 13 | `CosturaDumper` | `costura-extraction` | Parity. Extracts `costura.*.dll(.compressed)` assemblies into the payload writer. |
| 14 | `ControlFlowDeobfuscator` | `dispatcher-deobfuscation` + `control-flow-completion` | Clean-room. Proves dispatcher edges, folds constant branches, and deletes all unreachable code with EH regions preserved and per-method verification. |
| 15 | `Cleaner` | `runtime-cleanup` (opt-in `--remove-runtime`) | Opt-in, conservative. Deletes only delegate-proxy types proven dead by a fixed-point reference scan, gated by `RewritePolicy.CanRemoveRuntime`. |
| 16 | `SymbolRenamer` | `symbol-renaming` (opt-in `--rename`) | Opt-in, conservative. Deterministically renames only non-public, structurally proven generated names; declares any public-API delta to the identity gate. |
| — | `NativeUnpacker` / QuickLZ | `metadata-preflight` (`NativePackDetector`) | Deferred. Native-packed input is detected and reported unsupported with a specific diagnostic rather than mis-processed. |

## Where ReactorUnpack is intentionally different

- **Fail-closed everywhere.** Any pass that cannot prove its transform preserves
  behavior makes no edit. Partial or unsupported recovery blocks emit by default.
- **Static only.** There is no dynamic execution, so protections that only reveal
  themselves at runtime (native stubs, VM lifting) are boundaries, not features.
- **Identity is policy-aware, not bypassed.** Cleanup and renaming declare the
  exact removals, additions, and renames they perform; the verification gate still
  fails on anything undeclared.

## Corpus coverage gaps

The corpus proves method-body recovery, proxy fixing, string recovery,
anti-tamper neutralization, control-flow completion, and payload extraction on
real samples. Boolean protection, token proxies, encrypted-resource
reattachment, Costura packaging, and native packing are implemented and unit
tested but not yet represented by a real corpus sample; the manifest schema and
runner already carry the gates (`minimumBooleansRecovered`,
`minimumTokensRestored`, `minimumResourcesRestored`,
`maximumRemainingSwitchDispatchers`, `maximumUnreachableInstructions`,
`expectUnsupportedReason`) so those samples can be added without code changes.
