# ReactorUnpack

ReactorUnpack is a clean-room, static-first .NET Reactor analysis and
deobfuscation tool. It treats protected assemblies as untrusted data and never
loads them into the CLR for execution.

The compatibility engine is capability-driven and validated against a
hash-verified, tiered .NET Reactor 6 corpus. The reusable pipeline currently:

- performs a raw metadata preflight before dnlib mutation;
- plans explicit preflight, analysis, original-byte recovery, IL-transform, and
  verify/emit phases;
- interprets loader IL in a bounded deterministic machine with synthetic PE,
  resource, stream, crypto, and native-write models;
- detects delegate-runtime and JIT-hook Reactor 6 generations structurally;
- classifies protected resources from consumer behavior;
- derives proxy stream constants by decoded-token validation;
- neutralizes 1,341 proven-unreachable invalid-call prefixes;
- folds proven constant predicates and transactionally rewrites strictly
  qualified EH-aware dispatchers;
- statically decodes, inflates, and validates the embedded resource assembly;
- decodes and validates all 279 proxy bindings;
- restores 2,643 direct `call`/`callvirt` sites;
- restores structurally proven string call sites;
- catalogs Reactor method stubs, validates deterministic virtual-PE write logs,
  and refuses incomplete body grafts;
- preserves metadata tokens and refuses output when recovery is incomplete; and
- emits structured analysis and change reports.

The implementation is independent of
[NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) and does not
include de4dot or other GPL-derived code.

## Build

The repository targets .NET 10:

```bash
dotnet restore ReactorUnpack.slnx
dotnet build ReactorUnpack.slnx
dotnet test ReactorUnpack.slnx
```

If the host has no SDK, the workspace-local installation used during
development is available as `.dotnet/dotnet`.

## Usage

Analyze without emitting a transformed binary:

```bash
dotnet run --project src/ReactorUnpack.Cli -- \
  samples/embedded_dotnet_Mlfhntkcvb.exe \
  --analyze-only --report-dir artifacts
```

Emit only when every pass and verification gate succeeds:

```bash
dotnet run --project src/ReactorUnpack.Cli -- \
  samples/embedded_dotnet_Mlfhntkcvb.exe \
  --fail-on-partial --report-dir artifacts \
  --output artifacts/Mlfhntkcvb.cleaned.exe
```

Run the complete local corpus with deterministic normalized outcomes:

```bash
dotnet run --project src/ReactorUnpack.Cli -- corpus run \
  --manifest corpus/reactor-6-nonvirt.manifest.json \
  --samples samples \
  --output artifacts/corpus
```

For each input, ReactorUnpack writes:

- `<sample>.analysis.json` — evidence, resource inventory, pass status, and
  verification results;
- `<sample>.changes.json` — every IL transformation with token and offset; and
- `<sample>.payloads/*.dll` — verified managed payloads recovered without CLR
  loading; and
- `<sample>.cleaned.exe` — emitted only after verification.

## Safety and scope

ReactorUnpack does not execute protected code. Inputs remain immutable, output
is written atomically, and unknown formats are reported as unsupported instead
of being guessed. Payload stages are bounded and accepted only after framing,
compression, cryptographic, and managed-metadata invariants. Public API,
resources, token sets, entry point, strong-name state, branches, exception
regions, stacks, and an independent reload are checked before emission.
Method edits use full-body rollback covering locals and EH state. Reactor helper types and
resources remain until complete use-site analysis proves removal safe.

See [docs/compatibility.md](docs/compatibility.md) for capability coverage and
[docs/corpus.md](docs/corpus.md) for corpus provenance and reproducible checks.
