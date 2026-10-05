# Corpus validation

Corpus manifests contain metadata, expected protection, SHA-256 identities, and assertions. Malware binaries are not distributed with the repository. A gate checks its stated assertions; it does not establish exhaustive extraction or behavioral equivalence.

| Manifest | Scope |
| --- | --- |
| [Reactor 6](../corpus/reactor-6-nonvirt.manifest.json) | Real-world samples, recovered stages, and validation oracles; includes an exploratory native wrapper |
| [Reactor 7.5](../corpus/reactor-7-static.manifest.json) | Pinned benign probes and related validation entries |
| [ConfuserEx](../corpus/confuserex-1-static.manifest.json) | Two whole-section anti-tamper samples |

The filenames are historical labels, not complete feature descriptions. In particular, Reactor validation also covers virtualized code and native extraction. Read each manifest's expectations rather than inferring them from its filename.

## Run the static gates

Build the CLI, then supply the directory containing the matching samples:

```text
dotnet build Cilantro.slnx -c Release
dotnet run --project src/Cilantro.Cli -c Release --no-build -- corpus run --manifest corpus/reactor-6-nonvirt.manifest.json --samples samples --output artifacts/corpus/reactor6
dotnet run --project src/Cilantro.Cli -c Release --no-build -- corpus run --manifest corpus/reactor-7-static.manifest.json --samples samples --output artifacts/corpus/reactor7
dotnet run --project src/Cilantro.Cli -c Release --no-build -- corpus run --manifest corpus/confuserex-1-static.manifest.json --samples samples --output artifacts/corpus/confuserex
```

Use isolated output directories. The runner validates sample identities and writes `corpus.outcomes.json`; missing required inputs are reported separately from failed assertions. Some entries use analysis-only or feature-specific policies, so passing the manifest is not identical to testing every sample with all default options.

`minimumRecoveredStringSites` gates the sum of constant-folded and table/lookup-restored string sites. Use it when the recovery route can change while the required total stays fixed. `minimumConstantStringSites` remains available for assertions specific to constant folding. Exposing a literal can retain the original call when it is required to preserve initialization effects; the pass diagnostics identify that case.

## Reconstruction cleanup gates

The final `reconstruction-state-audit` pass follows cleanup and renaming. When differential
trials identify differing static fields, it reports whether their owners and explicit IL
references survive, alongside reflection sites requiring target/escape analysis. It uses
independent non-VM snapshots to avoid treating VM-induced graph-numbering shifts as changed
application fields. Removed roots alone do not establish observational equivalence, and
this audit never upgrades a reconstruction disagreement to agreement.

Repeat-call validation includes both a common original-method warm-up and independent
warm-ups using each side's selected body. The latter catches startup differences that
the common warm-up can hide. First-call results and arguments remain in the comparison
graph across the second call, preserving their mutations and aliases. Failed warm-ups
and unsupported registrations remain inconclusive; matching bounded calls do not prove
arbitrary later-call or callback behavior. Unresolved original field tokens are reported
separately from fields confirmed removed.

The supplementary `reconstruction-application-contract` evidence uses a narrower,
explicit contract: preserve application behavior and recovered payloads while allowing
deliberate protector-metadata removal. It checks captured returns/exceptions, arguments,
retained first-call references, application static state and modeled host effects.
Differing VM caches qualify only when their fields are confirmed removed with no surviving
explicit references, no shared captured objects and no escaped VM metadata handles.
Resolver registration alone does not establish callback behavior. Inconclusive fixtures
and payload coverage are reported separately; a bounded match does not establish every
input or external callback. The original full-state verdict remains visible.

When initial captured application state matches, resolver trials exercise the module's
declared assembly/resource names and a missing name, using null and home-assembly
requesters. They preserve subscription order and compare both pre-callback state and
each response before a later callback can overwrite it. Returned objects remain captured
to check aliases across requests. Unsupported callbacks, VM-state escapes and exhausted
limits remain inconclusive. This covers the recorded requests, not arbitrary names or
external requesting assemblies. Work is capped at 64 names per event and 512 handler
invocations, within the shared interpreter budget.

Resolver fixtures explicitly close their assembly inventory over the home assembly and
loads observed by that machine. `AppDomain.GetAssemblies()` outside this declared test
world remains unknown; an observed-load list is not assumed to enumerate a real host.
Byte-array loads retain their assembly identity and supplied symbol bytes without loading
them into the host CLR. The fixtures do not establish behavior with other preloaded assemblies.

Assembly display-name parsing preserves the target Framework's observed wildcard-version
behavior: an all-65535 version is unspecified on .NET Framework, whereas .NET 8/10 reject
it. Mixed sentinel versions also retain the Framework version object's components even
when its display name omits them. Source-built probes check those differences on all three
runtimes. Unmodeled legacy wildcard syntax remains unknown; a host-parser exception alone
must not be counted as the protected sample's exception. Other modeled constructor failures
retain their exception type and argument information.

Coupled-startup trials also install all reconstructed bodies and rewritten callers before
the rebuilt side's module initialization. Separate single-body trials cannot establish
the behavior of interacting replacements when their companions still use original bodies.

A debugger-only throw is attributed separately only for the exact identified VM-wrapper
guard, with matching remaining application state and confirmed removal of the guard.
Other exceptions and earlier application-state changes are not waived. Branch validation
also tests previously inferred destinations against a calibrated interpreter position;
switch validation covers every table entry and four out-of-range selectors. Unreachable
code is still a classification of the recovered graph, not a universal semantics proof.

The 2026-10-05 reconstruction review covers all 14 reconstructed inputs from the frozen
44-root baseline. All 14 outputs verify; all 28 programs decode their 61,700 operations
without unread operations or inferred targets. The 126 unwalked operations are classified
unreachable in the recovered graph. All 15 source-built benign runtime checks pass, and
all 24 captured baseline payload observations retain their bytes. These counts do not
refresh the full baseline or the Malware Vault inventory.

The native stage also passes a separate original-versus-final resolver comparison:
80 ordered request outcomes match, including loaded-image bytes and repeat-call identity.
The original encrypted-resource path needs a larger bound than the 192-million-step
fixture: an explicitly recorded 1.2-billion-step per-request trial completes it without
changing production defaults. Its extra assembly load is a resource-only protector
satellite with no methods; all 47 streams are preserved in the emitted module and the
satellite image is retained as an artifact. Raw load counts and earlier budget failures
remain recorded. Together with coupled startup and the metadata-boundary review, this
supports the bounded reconstruction checks under the stated contract. It does not
close full unprotection: that requires physical removal of the VM machinery from
the cleaned assembly while retaining readable application CIL and payloads.
It does not make the broad native machine gate agree or prove behavior for arbitrary
computed reflection, inputs, hosts, requesters or later calls.

A subsequent physical-removal sweep on 2026-10-05 verifies all 14 intact virtualized
inputs, including the three known virtualized child hashes: no identified VM types
remain, 14 VM data resources are removed, and all 28 reconstructed CIL bodies survive.
All outputs pass ILSpy disassembly/decompilation, 15 benign runtime comparisons and
24 captured payload checks. The selected suite passes 1,294 tests. Using the recorded
rename maps, all 36,036 surviving method bodies, locals and exception handlers match
the preceding output. The native stage loses 2,992 obsolete types and 12,726 methods;
its 80 ordered resolver outcomes still match. Additional deleted support methods are
reviewed separately from automatically identified VM/proxy declarations.

This closes the VM-removal item under the accepted criterion: all 14 intact inputs
must be handled; inputs damaged by other tools may be unsupported with a warning or
error. The fifteenth VM-bearing hash is a rewritten NETReactorSlayer Lqcuzgc copy with
stale/missing token targets. It still fails direct VM removal and receives an explicit
incomplete-reconstruction warning; its intact original produces a verified VM-free
assembly. Repair of the damaged copy is not required for closure. See the
[status report](status-report.md) for the remaining corpus work. Current local evidence
is in `artifacts/vm-removal/`; neither the full 44-root matrix nor the Vault inventory
has been refreshed.

The standard corpus runner disables reconstruction, so it cannot gate removal of an abandoned VM engine. For the pinned Qbjuef and Mlfhntkcvb payload inputs, also run ordinary reconstruction and check the resulting reports:

```powershell
New-Item -ItemType Directory -Force results | Out-Null
cilantro C:/cilantro-verify/samples/Qbjuef.exe --recover-embedded --declarations corpus/reconstruction.declarations.json --output results/Qbjuef.cleaned.exe --report-dir results --json > results/qbjuef-run.json
cilantro C:/cilantro-verify/samples/Mlfhntkcvb.payload.Lqcuzgc.dll --declarations corpus/reconstruction.declarations.json --output results/Mlfhntkcvb.cleaned.dll --report-dir results --json > results/mlfhntkcvb-run.json
pwsh -NoProfile -File corpus/verify-reconstruction.ps1 -ReportDirectory results
```

Reconstruction trials and removal counts do not establish that the VM is absent.
Check the emitted metadata against the original engine declarations as a separate gate:

```powershell
pwsh -NoProfile -File corpus/verify-vm-removal.ps1 -RunPath results/qbjuef-run.json -ToolDirectory src/Cilantro.Cli/bin/Release/net10.0
```

This gate reads the original and cleaned files as metadata, follows the recorded renames,
and rejects retained VM types, missing reconstructed CIL bodies, or VM resources claimed
removed but still present. It also checks input hashes and requires structural verification.
It does not execute the sample, prove application behavior, or replace disassembly and
payload-preservation checks. A successfully emitted partial recovery can fail this gate.

The opt-in 192-million-step allowance accommodates independent cold proofs for Mlfhntkcvb's 514 proxy initializers. The report gate checks pinned input identities, successful structural validation, reconstruction of the method and initialization helper, minimum runtime removal, expected payload hashes, and the helper's cold/repeat comparison evidence. It deliberately requires the full-state disagreement to remain visible alongside matching captured non-VM state. This script reads reports; it does not execute either sample or independently prove equivalence.

## Whole-corpus completion measurements

### Progress after 0.10.3: nested Windows outputs

The expanded 0.10.3 measurement recorded 33 child reload failures (27 distinct child input
hashes) across ten root cases. These were filesystem failures, not evidence of invalid
recovered IL: the Windows executable's native dnlib file mapping rejected long paths.
Verification and oracle comparison now read bytes through managed file I/O before loading
metadata, as input recovery already does.

On 2026-10-04, the `5a752718780f024627df50674cc1fb940dfdb87dd03af3ecebcf0d872adf3009`
chain recovered and verified its parent and both children, with child output paths of 282
characters. All three emitted files matched the SHA-256 hashes of the successful 0.10.3
short-path trial. A separate executable comparison reproduced the released version's reload
failure at a 277-character output path; the fixed Windows executable accepted the same child.
The selected local regression suite passed 1,209 tests, including deep-path validation of
valid, changed, corrupt, and missing files.

This closes the reproduced filesystem blocker without weakening verification. It does not
establish that all ten affected root cases now complete: the entire expanded corpus has not
been rerun with this fix. The parent chain's reconstruction comparison still reports
`disagreed`; semantic equivalence, native embedded content, and damaged metadata remain
separate gaps. Local trial evidence is stored under `artifacts/progress-long-path/`.

### Progress after 0.10.3: damaged custom attributes

The historical logger input
`c3267e21deab927413d7b4ed62ac183b6b2ea106bfaed268711ed183a25e981c` contained one
field custom attribute whose constructor referred to method row zero, with no value blob.
Generic recovery previously emitted it as verified, but ILSpy exited with code 70. This was
damage already present in the supplied historical output, not a demonstrated defect in
fresh recovery of its protected parent.

Metadata sanitization now removes attributes with invalid constructor references and records
each removal, without trying to infer the missing attribute. Valid external constructor
references remain intact even when their assemblies are unavailable. Sanitization runs after
method-body recovery and before IL transforms, so damaged input attributes do not cause
unrelated body rewrites to roll back. Verification also rejects remaining null constructor
references, including after serialization.

On 2026-10-04, the logger emitted verified output with exactly one attribute removed and
ILSpy decompiled it successfully (exit 0). The selected local suite passed 1,211 tests. A
metadata-only scan of 44 baseline inputs and 75 retained output paths found this defect only
in the historical logger: 118 files were readable as managed metadata; the remaining input
was the native WindowsManagement wrapper. These are file observations, not unique assembly
hashes or fresh end-to-end corpus runs. Evidence is under `artifacts/progress-metadata/`.

This fixes the reproduced invalid-constructor case, not arbitrary malformed attribute blobs
or the separate token-reconstruction problem in previously rewritten Lqcuzgc.

### Progress after 0.10.3: native Costura dependencies

Costura extraction now recognizes `costura32.*` and `costura64.*` DLL resources as well
as `costura.*`, including bounded DEFLATE compression. Native PE headers and section file
bounds are checked before extraction. Native dependencies are distinguished from managed
assemblies in payload provenance and recursive recovery; their nodes remain extracted-only,
with an explicit native-unpacking limitation. One malformed dependency no longer discards
successful sibling extractions.

The 2026-10-04 VGeko trial (`d6072175…`) extracted **14 dependencies**, up from 12:
all twelve previous managed payload hashes were retained, plus these native images:

| Resource | Bytes | SHA-256 |
| --- | ---: | --- |
| `costura32.vgeko.dll` | 2,206,208 | `e2fbd8c7a6c1fe384a1cac6104c31130d86778493e7c9b2dd00dde0f56d3fd20` |
| `costura64.vgeko.dll` | 2,380,800 | `03f90fe787769eed15fe02822a7349550e095c81a4c71af447469f8f9a27b679` |

Both images have UPX section markers. The parent and twelve managed dependencies still
verify; the two native nodes keep the overall chain incomplete. Validated Costura images
are classified before resolver heuristics, and other Costura-named content is left
unclassified instead of being guessed to be Reactor encryption. VGeko no longer reports
a nonexistent encrypted managed-resource bundle.

The selected local suite passed **1,214 tests**, including compressed native extraction,
preservation of valid siblings after malformed input, and truthful recursive native status.
Evidence is under `artifacts/progress-costura/`, with the final trial in
`vgeko-verified.json`. UPX unpacking, native deprotection, and examination of native content
inside application `.resources` containers remain open; extraction alone does not close
those gaps. The full corpus has not been rerun for this change.

### Progress after 0.10.3: UPX follow-up for native dependencies

The two VGeko native dependencies were statically unpacked on 2026-10-04 with
[UPX 5.2.1](https://github.com/upx/upx/releases/tag/v5.2.1), downloaded from the official
release and checked against its published asset digest. Neither DLL was executed.

| Output | Architecture | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `costura32.vgeko.dll` | x86 | 6,159,360 | `1e100cab80e67e584be5210c9fc933f1ec192959d76f323d7d4a168df33a7704` |
| `costura64.vgeko.dll` | x64 | 6,341,120 | `738c2253706b6a8a569f84dfa63f080e7defdd21dffaa80dda0089939ba7ff16` |

Both outputs have normal native PE sections and no CLR metadata. UPX unpacking therefore
exposes native code, not another managed stage for CILantro to recover. The original packed
files remain intact. This closes unpacking for these two observed inputs, while native
deprotection and nested application-resource inspection remain unproven.

Use the optional helper with a CILantro JSON run manifest and an explicitly supplied UPX tool:

```powershell
pwsh -NoProfile -File corpus/unpack-native-dependencies.ps1 -Run results/run.json -Upx C:/Tools/upx.exe -Output results/native-unpacked
```

This is a separate workflow, not automatic CLI unpacking or a bundled UPX dependency.
The helper checks recorded source hashes, uses a new output directory, limits each UPX
invocation to 30 seconds by default, validates output PE section bounds and architecture,
and records source/output/tool hashes and diagnostics in `native-unpacking.json`.
Already-unpacked files are skipped. Failed or unvalidated results are not reported as
unpacked. If an output exposes managed metadata, the report directs the analyst to run
CILantro on it; it does not silently execute or recover it.

Validation reproduced both output hashes, rejected a deliberately mismatched source hash,
and left already-unpacked inputs unchanged. Trial evidence is under
`artifacts/progress-upx/`; unpacked DLLs and the report are stored under
`C:/cilantro-verify/review-trials/progress-upx-verified/`. The existing whole-corpus baseline
is unchanged; this was a targeted static trial.

### Progress after 0.10.3: payloads inside application resource containers

The `resource-entry-extraction` pass now reads named byte-array and stream entries from
embedded `.resources` containers and extracts validated managed or native PE images.
It reads raw resource data rather than deserializing resource objects, retains the original
container, and records the container/key plus source and payload hashes. Container size,
entry count, and total extracted bytes are bounded; malformed PE-like entries remain
explicit diagnostics. Managed outputs participate in recursive recovery, while native
outputs retain the extracted-only status described above.

The 2026-10-04 VGeko trial recovered two additional payloads from
`VGeko.Properties.Resources.resources`, bringing its extracted count to **16**:

| Entry | Packed bytes | Packed SHA-256 |
| --- | ---: | --- |
| `grpc_csharp_ext_x64` | 3,557,144 | `8425bd25adcc77e917ff5e9a0a039cf7cf4e7d2688157329545baf6041e4b7eb` |
| `grpc_csharp_ext_x86` | 2,460,952 | `a54a2dca767bcd8157a0eaf591ea11525f0ce0d9421c3277d42e8b6a615c2e28` |

Both also unpacked successfully with the UPX helper: x64 to 12,684,568 bytes
(`84a809da5d42ea7091e83d0c3e5c18696bc4c857be490e7ef17a361eeba83254`) and x86 to
9,986,840 bytes (`43a874c85d666408024b213108f7949e0bad9412889d801f325d251105335cca`).
Neither exposes CLR metadata. The recovery chain has thirteen recovered managed nodes and
four native extracted-only nodes; it remains incomplete with respect to native deprotection.

The selected regression suite passed **1,216 tests**, including raw stream/byte-array
recovery, malformed input reporting, preservation of existing payloads, and exclusion of
custom serialized objects. Running this pass alone across all 44 baseline root inputs
succeeded on all 43 managed inputs and identified the two VGeko additions; the native
WindowsManagement wrapper is outside the pass's input type. This is not a full pipeline
rerun of all inputs. Evidence is under `artifacts/progress-resource-entries/`, including
`corpus-scan.jsonl`, `vgeko-run.json`, and `native-unpacking.json`.

This closes the observed raw PE entries in VGeko's application resources. It does not claim
exhaustive recovery from serialized objects, encrypted entries, or arbitrary nested archives.

The manifest gates intentionally keep reconstruction and renaming disabled. To inventory what an analyst-facing recovery leaves behind, run the separate PowerShell 7 measurement harness with an isolated, fixed CLI build:

```powershell
pwsh -NoProfile -File corpus/measure-completion.ps1 -Cli artifacts/fixed-build/cilantro.dll -Samples C:/cilantro-verify/samples -Output C:/cilantro-verify/review-trials/completion -Concurrency 2
```

The harness verifies manifest input hashes, enables reconstruction and recursive recovery, preserves per-entry host/library/declaration settings, and applies a recorded step allowance (192 million by default). It uses normal emission even for exploratory entries, because this measurement asks what recovery actually produces. Original corpus assertions remain separate; the harness checks expected payload hashes but does not reinterpret existing output-hash or oracle-name gates after renaming. It never executes a sample. Use a fresh output directory and do not rebuild the CLI in place while measurements run.

`completion.runs.json` records every scheduled root, including failures. `completion.baseline.json` records each reported child and its depth, identity, structural verification, residual control-flow and VM metrics, reconstruction evidence, resources, payloads, blockers, and incomplete passes. `completion.baseline.csv` provides a compact comparison. Repeated content hashes retain each recovery context. Traversal-limited children remain explicit. Additional files outside the pinned manifests can be supplied with `-AdditionalInputs`; their observed hashes are recorded separately.

These are completion measurements, not completion verdicts. A dispatcher-shaped method can contain ordinary logic, an early blocker can be superseded by a later recovery pass, and unsupported extraction can mean either absent content or unresolved decoding. Inspect final cleanup and reconstruction evidence before classifying a residue. Rerun `summarize-completion.ps1 -Directory <output>` to regenerate summaries from the saved reports.

Compare two completed measurements with `compare-completion.ps1 -Before <baseline> -After <candidate> -Output <comparison.json>`. It matches assembly observations by root case, depth, and input hash, records missing/new observations, and compares verification, remaining dispatcher-shaped methods, VM coverage, and extracted payload hashes. The original root outcomes remain in the comparison, including failures that produced no assembly report.

## Benign runtime probes

The [probe harness](../corpus/probes/README.md) builds benign programs for .NET Framework 4.8, .NET 8, and .NET 10, then uses an installed Reactor 7.5 console tool to protect strings/CFF, NecroBit-only, and full configurations. Nine protected configurations are compared with their unprotected oracles.

Only these repository-built benign programs are executed for runtime validation. Malware corpus work is static interpretation and decompilation. Record the exact protector command, input hashes, output hashes, and oracle results. Trial-protected originals can expire, so later trials of those originals may require fresh fixtures.

After completed method recovery, runtime cleanup can remove the identified generated
Reactor trial-expiry guard. Recognition requires its exact exception message, global
static helper shape, clock arithmetic and a restricted instruction/call set; ordinary
application date checks and helpers with side effects remain. `--keep-runtime` preserves
the guard. Static bootstrap handling alone is insufficient: an expired guard retained in
the emitted module initializer can prevent otherwise recovered benign code from starting.

## Interpreting the measurements

| Check | Establishes |
| --- | --- |
| Unit/integration tests | The specific semantic and regression cases they assert |
| Corpus gates | Manifest expectations on pinned inputs |
| Output hash comparison | Reproducibility or a detected output change for that run |
| Successful decompilation | A tested decompiler accepted the emitted assembly |
| Runtime-oracle match | Selected behavior of a benign protected/cleaned program matched its source-built oracle |
| VM comparison | Agreement or disagreement within the reported paths, inputs, and modeled state |

Do not add these counts into a single coverage percentage. Preserve failures and inconclusive trials alongside passing results. The current pre-release baseline and known gaps are in [compatibility](compatibility.md); historical sample measurements are in [the archived corpus notes](history/pre-0.10/corpus.md).

## Tests without private samples

Run `dotnet test Cilantro.slnx -c Release`. Sample-dependent tests should report skips when their inputs are unavailable. Review the skip count: a green public CI run does not mean private-sample coverage ran. The fast development filter is `--filter "Cost!=High"`; use the full available suite for release validation.
