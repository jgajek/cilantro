# Check recovery against a known program (Windows)

For external/password method-code captures, build `BabelCodeSources/BabelCodeSources.csproj` and run `babel-code-sources.ps1 -Stage Protect` with a fresh `-Output` and process-local `BABEL_LICENSE`. It requires exactly one encrypted method per capture and refuses to overwrite protected inputs. The fixed probe password is public test data, unrelated to the evaluation license. Use Recover and Verify stages with the same output/recovery directory. External recovery forwards its `.eil` file through `--babel-code-source`; cleaned outputs do not receive the companion. Manifest accepts `-ManifestProfile password` or `external` and packages inputs under `babel-12-password` or `babel-12-external` in `CILANTRO_BABEL12_SAMPLES`. Add `-Combined` consistently to capture/test the string/resource/proxy/flow combinations; their packages have a `-combined` suffix. Manifest records the external data hash and requires a recovered body, zero encrypted stubs and oracle resource parity.

For Babel metadata/control-flow captures, build BabelProbe in the verification checkout, then run `babel-hardening.ps1` with Protect, Recover, Verify and Manifest stages in that order. Use a fresh output directory and set `BABEL_LICENSE` only in the Protect process. The nine captures cover legacy reflection level 4, disassembly suppression, their string/resource combination and all six control-flow options; the manifest packages inputs under `babel-12-hardening` using the existing `CILANTRO_BABEL12_SAMPLES` root. Only the repository-built benign probe is executed for behavior checks.

For signed/renamed embedding, use `new-embedding-test-key.ps1 -Output C:/cilantro-verify/babel/embedding-identities/test-only.snk` to generate a disposable signing key outside the repository. Rebuild `BabelEmbedding/App/App.csproj` in the verification checkout with `-p:SignAssembly=true -p:AssemblyOriginatorKeyFile=<absolute-test-key-path> -p:BaseOutputPath=bin/signed/`. The key is unrelated to `BABEL_LICENSE` and is never packaged. Run `babel-embedding.ps1` Protect/Recover/Manifest/Verify with `-Profiles renamed,signed-renamed,signed-combined -CorpusProfile babel-12-embedding-identities`, a fresh `-Output` and the same `-RecoveryDirectory`. Pass `-SigningKey` to Protect and Recover. Recovery forwards it to `--signing-key`, which re-signs matching cleaned hosts and recursively cleaned dependencies. The identity corpus pins nine captures and separate signed/unsigned oracles; source/protected/cleaned executions, public-key identities, application resources and output signatures are checked independently.

`BabelEmbedding/App/App.csproj` and `babel-embedding.ps1` exercise executable dependency embedding on net48/net8.0/net10.0. Build in the verification checkout, then use Protect, Recover, Manifest and Verify stages with a fresh `-Output` directory and the process-local `BABEL_LICENSE` convention below. Pass the same `-RecoveryDirectory` to Recover, Manifest and Verify. Twelve captures cover single, multiple, combined and nested bundles. Manifest packages three oracles, pins direct dependency hashes and requires retirement of each identified dependency bundle. The recursive corpus tests independently pin the extracted nested leaf and require deployment of the verified cleaned child. Verify compares source/protected/cleaned hosts and records the emitted dependency hashes. Protected inputs keep embedded DLLs absent; cleaned hosts run with ordinary DLLs emitted by recovery. Only the single profile's unembedded leaf is copied by the harness. Use a fresh `-RecoveryDirectory` for another recovery; protection refuses existing captures.

For Dotfuscator Professional 7.9 managed/native-key strings and control flow, use
`dotfuscator.ps1`; see the [Dotfuscator corpus workflow](../../docs/corpus.md#dotfuscator-probes).
For encrypted `.resources`, build `DotfuscatorResources/DotfuscatorResources.csproj`
and use `dotfuscator-resources.ps1 -Stage All` with the activated trial.
The Reactor workflow below uses `verify.ps1`.

Use `DotfuscatorChecks/DotfuscatorChecks.csproj` with `dotfuscator-checks.ps1
-Matrix Basic -Stage All` for the reviewed debugging/integrity checks.
Use `-Matrix Mixed` in a fresh output directory for checks combined with high
control flow, renaming and managed v1/native-key v2 strings.

For Babel 12, build `BabelProbe/BabelProbe.csproj` in the verification checkout
and run `babel.ps1 -Stage All`. Set the floating user key in the process-only
`BABEL_LICENSE` environment variable first, and release the Desktop app's seat.
The harness requests and releases the floating seat with each CLI process,
redacts the key from process output, and records only protection options and
tool/input hashes. `-Stage Manifest` packages a completed capture and pins its
measured partial-recovery baseline, including restored method bodies and removed
check calls for code/check configurations.
Resource configurations also gate restored resource bundles and original resource
bytes; reviewed resource-only satellite hooks are removed after complete validation.
The current trial excludes stream string encryption; unavailable options are
recorded separately. Behavioral parity does
not assert that every protection was removed.

Use these contributor probes to check whether a recovery change preserves observable behavior. Build a benign program, protect it with Reactor, recover it with CILantro, then compare the original, protected and cleaned results.

The programs are built from the source in `Probe`. Their
`--recovery-self-test` entry point prints seven arithmetic/branch results and three
catch/finally results, including the final contents of a mutated byte array.

Run these contributor commands from a source checkout with the .NET 10 SDK.

Build CILantro and the three probe targets, then use an installed Reactor console
edition (a trial is sufficient):

```powershell
dotnet build src/Cilantro.Cli/Cilantro.Cli.csproj -c Release
dotnet build corpus/probes/Probe/Probe.csproj -c Release
pwsh -NoProfile -File corpus/probes/verify.ps1 -Stage Protect
pwsh -NoProfile -File corpus/probes/verify.ps1 -Stage Recover
pwsh -NoProfile -File corpus/probes/verify.ps1 -Stage Verify -RunProtected
```

Use `-Reactor` to specify the console executable and `-Output` to choose a trial
directory. The default output is
`C:/cilantro-verify/review-trials/reactor75-ground-truth`; the existing pinned
corpus and manifests are not overwritten. `-Only net48-necrobit` restricts a run.
`-Stage All` combines the three stages after building. Verification executes the
benign oracle and cleaned builds; `-RunProtected` additionally checks the freshly
protected builds. Each execution has a 30-second timeout.

The matrix covers net48, net8.0 and net10.0, each with strings/CFF, NecroBit-only,
and full protection. Each fixture records the protector command, protector hash,
oracle hash, protected hash, recovery report and process stdout/stderr. Verification
checks input hashes and writes `ground-truth.outcomes.json`; a cleaned/oracle
mismatch produces a nonzero verification exit code. `ProtectedMatched` separately
records whether the protected program matched its oracle when requested.

A successful CILantro run and structural verification are separate from a matching
execution. Keep failures in the results: they are precisely what these probes are
intended to expose. These ten cases cover the named methods and inputs, not all
possible program behavior or every virtualized handler. The trial protector says
its outputs expire after 14 days; regenerate them for later execution trials.

The [Babel method-shape corpus](../babel-12-methods.manifest.json) uses `BabelMethodProbe` and `babel-methods.ps1` to capture reference receivers, struct/generic-method producer controls, generic owners and by-reference methods. Its manifest pins instance, byref, generic-owner and mixed recovery, plus zero-image producer controls. See [corpus validation](../../docs/corpus.md) for reproduction and the recorded producer writeback difference.

`DotfuscatorResourceTypes` and `dotfuscator-resource-types.ps1` capture mixed string, byte-array and primitive resources on three frameworks. Build the probe and CLI in the verification checkout before running the harness. `GenerateResources.ps1` emits standard primitive resource codes without object serialization. Verification requires protected/cleaned equality and records the producer's conversion of non-string primitive entries into text byte arrays; source resource parity is deliberately not required for these captures.

`DotfuscatorSatelliteResources` and `dotfuscator-satellite-resources.ps1` capture neutral resources and French/Canadian French satellite DLLs. The harness pins all companion hashes and checks culture fallback and cache reload against the source build. Build and run from the verification checkout; use `-RecoveryDirectory` for a fresh recovery destination. CILantro writes restored satellites in culture directories beside the cleaned main assembly, lists them in the JSON/HTML reports, and refuses to overwrite differing companion files. All three resource harnesses accept `-RecoveryDirectory` for fresh output folders. The reviewed manager/reader family is removed after direct ResourceManager rebinding only when no surviving type references or literal type-name reflection require it.

`dotfuscator-resource-interactions.ps1` protects that localized probe with high control flow, renaming and managed/native string encryption. It pins satellite and native/environment companions, supports `-Only` selections and fresh `-RecoveryDirectory` values, and compares all three program variants. The v2 configuration excludes the producer-broken array-return accessor from string encryption; its resource byte array stays encrypted. See the resource-combination provenance for the retained all-method producer controls.

`DotfuscatorResourceContracts` and `dotfuscator-resource-contracts.ps1` exercise distinct satellite versions and satellite-only neutral fallback. Build both layouts before protection:

```powershell
foreach ($layout in @('contract','satellite-only')) {
 dotnet build corpus/probes/DotfuscatorResourceContracts/DotfuscatorResourceContracts.csproj -c Release "-p:ResourceLayout=$layout" "-p:BaseOutputPath=bin/$layout/" "-p:BaseIntermediateOutputPath=obj/$layout/"
}
```

Run these commands in the verification checkout. The harness supports the same Protect/Manifest/Recover/Verify stages, `-Only` selections and fresh `-RecoveryDirectory` values. Main version 2 selects version-1 culture assemblies; the satellite-only variant explicitly selects French as its neutral satellite and has no embedded resource container.

`BabelMethodCaller` is an unprotected caller fixture for normal, aliased and throwing byref calls and fifteen generic argument cases. Build it for all three frameworks before `babel-methods.ps1 -Stage Verify` includes byref captures. Verification preserves protected byref copyback behavior. Generic verification requires source/cleaned equality and records the .NET 4.8 private enum/struct producer failures separately.

`BabelGenericProbe` and `babel-generics.ps1` add independent captures for inherited generic owners, static state, class/struct/new constraints and static methods. Build the project for all three frameworks in the verification checkout, and use the same process-local `BABEL_LICENSE` convention for `-Stage Protect`. `-Stage Manifest` packages all eighteen captures with measured recovery and oracle-resource gates. Use `-Stage Recover` and `-Stage Verify` with `-Only '*-open-owner','*-static-state','*-class-constraint','*-struct-constraint','*-new-constraint','*-static-method'` for all eighteen supported selections, or omit `-Only`. Build `BabelGenericCaller` for all frameworks before verification; it checks both struct-selection branches with nine value types and generic construction with nine value/reference cases, including nullable results, constructor effects and constructor exceptions. Static mode also checks twelve value/reference cases for argument order, null/default inputs and reference identity. Inherited mode tests twelve types on three receiver shapes, including reordered generic parameters, shadow fields and an overridden virtual method. Static-state mode checks twelve types, arbitrary counter values, per-type state isolation, one-time initialization and sticky initializer failures. The [generic-owner manifest](../babel-12-generics.manifest.json) and provenance distinguish producer behavior from recovery support.
`BabelHierarchyProbe`, `BabelHierarchyCaller` and `babel-hierarchy.ps1` extend the generic-owner corpus with three-level inheritance, reordered type arguments and `Storage<List<T>>` bases. Build both projects for net48/net8.0/net10.0 in the verification checkout, then use Protect/Manifest/Recover/Verify stages and the process-local `BABEL_LICENSE` convention. Nine captures recover one body each. The caller checks thirteen value/reference arguments, arbitrary static counter seeds, multiple instances and reference identity; deep mode also checks a derived receiver, for 156 three-way cases. Protection refuses existing captures; use a fresh `-RecoveryDirectory` when recovering again.
`dotfuscator.ps1 -Architecture x86 -StringEncryptionVersion 2 -V2ExcludeArrayMethod` adds the reviewed Windows x86 native-key profile. Rebuild the benign Probe with `-t:Rebuild -p:PlatformTarget=x86 -p:BaseOutputPath=bin/x86/` first; the harness rejects stale AnyCPU inputs. Use `-Only net48-strings,net48-combined,net48-renamed,net8.0-strings,net8.0-combined,net8.0-renamed` and a fresh output directory. Build/protect in the verification checkout. Verification uses the installed x86 .NET host for CoreCLR and the required-x86 executable for Framework. The separate manifest packages only the x86 native companion, preserves signed per-input environments, and uses distinct oracle filenames.
`dotfuscator.ps1 -Platform Linux -StringEncryptionVersion 2 -V2ExcludeArrayMethod` captures the Linux x64 native-key profile for net8.0/net10.0. Build the Probe and CLI in the Windows verification checkout, then run Protect/Manifest/Recover/Verify with a fresh output directory. Only Linux native companions are packaged. Verify invokes the chosen `-WslDistribution` (default Ubuntu-24.04) and `-LinuxDotnet` (default /mnt/c/cilantro-verify/dotnet-linux-x64/dotnet); install the matching Linux .NET runtimes locally first. All three variants execute through that same Linux host. Windows drive paths are converted to WSL mount paths explicitly. Source, protected and cleaned input hashes remain bound to their fixture records.
`dotfuscator.ps1 -Platform Linux -Architecture arm64 -StringEncryptionVersion 2 -V2ExcludeArrayMethod` captures explicitly ARM64-targeted .NET 8/.NET 10 inputs. Build the probe with `-t:Rebuild -p:PlatformTarget=arm64 -p:BaseOutputPath=bin/arm64/` first; the harness checks the actual PE machine. The ARM64 Verify path uses `-LinuxEmulator` (local qemu-aarch64-static), `-LinuxSysroot` (extracted ARM64 libc, C++ and OpenSSL libraries) and `-LinuxDotnet` (ARM64 runtimes). Defaults point under C:/cilantro-verify. All dependencies can be downloaded and extracted there without installing Ubuntu system packages. Runtime verification is under emulation, not physical ARM64 hardware. Only the reviewed linux-arm64 native companion is packaged.

`DotfuscatorSignatures` and `dotfuscator-signatures.ps1` add native-key v2 signature coverage. Build the probe and CLI in the verification checkout, then run Protect/Manifest/Recover/Verify with a fresh `-Output`. The six captures span net48/net8.0/net10.0. `all-signatures` keeps producer-corrupted pointer/ranked-array cases (and CoreCLR function pointers) as protected-behavior controls; `renamed-reviewed` leaves those methods unencrypted and applies renaming plus high control flow to the remaining 17 sites. Verification checks all protected/cleaned outputs and requires source equivalence for the renamed profiles. `-Only` accepts wildcard selections and `-RecoveryDirectory` selects a fresh cleaned destination. The manifest uses the existing `CILANTRO_DOTFUSCATOR_V2_SAMPLES` package root.

`dotfuscator-macos.ps1` packages the reviewed macOS x64/ARM64 native companions from an existing protected/recovered `dotfuscator-signatures.ps1` corpus. Its Package/Manifest/Recover/Compare stages preserve signed environments and compare cleaned bytes with the source corpus's default Windows recovery. Each architecture gets a separate manifest, and packaged native directories contain only that dylib. No macOS runtime execution is performed or claimed. Use a fresh `-Output` for Package and a fresh `-RecoveryDirectory` for another recovery.
