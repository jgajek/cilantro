# Build and validate a change

Use this contributor guide to build a local CLI/MCP pair and choose checks for your change. Routine malware analysis uses the published executables; see the [quick start](quick-start.md).

## Build from source

Install the .NET 10 SDK, then run:

```text
dotnet restore Cilantro.slnx
dotnet build Cilantro.slnx -c Release --no-restore
dotnet test Cilantro.slnx -c Release --no-restore --no-build
dotnet run --project src/Cilantro.Cli -c Release --no-build -- --help
```

Release configuration matters for interpreter performance. For a short edit/test cycle, add `--filter "Cost!=High"` to the test command. For release validation, run the full available suite and account for sample-dependent skips. Use [corpus gates](corpus.md) and the [benign probe harness](../corpus/probes/README.md) for recovery changes.

For performance changes, use the [corpus timing and output comparison workflow](performance.md).

Do not execute malware to test the tool. Static recovery, report inspection, hashes, and decompiler checks can operate on the malware corpus; executable behavioral trials use the benign source-built probes.

Cleanup must preserve public parameterless constructors required by surviving generic `new()` constraints, even when no `newobj` names the constructor. Include its initialization and body dependencies in reachability. Unknown external generic definitions are handled conservatively rather than depending on locally installed libraries. Optional cold-initializer cleanup proofs fail closed: a refused proof retains its candidate and records `cold-initializer-proof-refused` evidence; it does not add a recovery blocker. Actual recovery interpretation still records its own stops.

Field stack typing follows closed field-copy chains only after proving every writer of each source. Unknown writers, conflicting types, address escapes and unseeded cycles refuse recovery. Array and reference field signatures can also be restored for internal fields with no friend assemblies when every address reaches an exact typed local consumer whose body is checked for reads, exact typed/null writes and closed forwarding; argument positions include the instance receiver. Public fields retain the stricter private-owner requirement.

Mixed field, local and parameter cycles require an independent concrete seed and agreement from every writer, caller and parameter reassignment. Local spills require initialized locals and no address uses; parameter origins are recomputed from current IL. Exports and unseen callers through friend assemblies veto the proof. Loads through declared managed references use the pointee type. A closed field proved to contain only null may take a reference stack type from its consumer, because the cast preserves null. Generic forwarding preserves a proposed body template only when every closed instantiation agrees with the concrete seed and every open caller independently supplies the exact bound template.

Embedded COM interfaces have a separate narrow address rule: an abstract runtime/internal-call method may establish `System.Array` only through an explicit output-only `SAFEARRAY` marshaling contract. Input/output references and ordinary external byrefs remain unsupported. Direct field writers must already supply arrays or null. This metadata proof neither invokes COM nor establishes that the required COM server is installed.

An exact .NET Framework `ComponentResourceManager(Type)` construction uses the supplied type for resource identity, rather than exposing its methods. Recognition checks framework assembly identity, signatures and alternate entries. On such an otherwise unexposed owner, parameter typing can exclude an uncalled non-public forwarding helper only after checking all method references, metadata aliases, names, exports and friend assemblies. Its body and signature remain intact; `typing-uncalled-resource-forwarder` records the omitted caller. See Microsoft's [component resource manager](https://github.com/microsoft/referencesource/blob/main/System/compmod/system/componentmodel/ComponentResourceManager.cs) and [resource manager constructor](https://github.com/microsoft/referencesource/blob/main/mscorlib/system/resources/resourcemanager.cs) implementations.

Unreferenced internal static methods on unexposed owners can likewise be excluded from caller inputs when names, handles, metadata aliases, attributes, accessors, exports and friend assemblies cannot supply a caller. `typing-uncalled-internal-method` records this exclusion; the method's body and signature remain intact.

## Publish locally

```text
dotnet publish src/Cilantro.Cli -c Release -r win-x64 -p:PublishSingleFile=true -o artifacts/publish/win-x64
dotnet publish src/Cilantro.Mcp -c Release -r win-x64 -p:PublishSingleFile=true -o artifacts/publish/win-x64
```

Use `linux-x64` or `linux-arm64` for Linux, and `osx-arm64` (Apple Silicon) or `osx-x64` (Intel) for macOS. The single-file property enables self-contained publishing in each project. Test `--version`, `--help`, an ordinary run, and JSON/error output from the published CLI on its target platform. Both executables belong in each release archive, with licence and documentation. The release workflow builds and smoke-tests each Linux/macOS archive on a native runner, including a benign probe recovery and MCP initialization.

## Write documentation for its reader

Analyst guides should start with a case question, explain how the protection hides the behavior, show the recovered code or artifact, and give a useful next step. Keep necessary scope qualifications together and link implementation rules, method identities and reproduction details from a reference appendix. Label captured output, reconstructed checkpoints and illustrative code accurately.

Contributor and automation pages should lead with the task they support, then preserve the exact commands, field names and checks needed to carry it out. Keep historical experiments out of current usage instructions.
