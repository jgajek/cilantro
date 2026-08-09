# ReactorUnpack

ReactorUnpack is a clean-room, static-first .NET Reactor analysis and
deobfuscation tool. It treats protected assemblies as untrusted data and never
loads them into the CLR for execution.

The initial compatibility profile targets the two supplied .NET Reactor 6
fixtures. The reusable pipeline currently:

- fingerprints Reactor runtime and delegate-proxy structures;
- neutralizes 1,341 proven-unreachable invalid-call prefixes;
- catalogs initialized data and encrypted resources;
- statically decodes, inflates, and validates the embedded resource assembly;
- decodes and validates all 279 proxy bindings;
- restores 2,643 direct `call`/`callvirt` sites;
- restores the two protected string call sites used by the fixtures;
- preserves metadata tokens and refuses output when verification fails; and
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
of being guessed. Payload decoding is bounded and accepted only after stream
hash, output hash, managed metadata, and assembly identity checks. Reactor
helper types and resources remain in the cleaned host until destructive removal
can be proven behaviorally equivalent.

See [docs/compatibility.md](docs/compatibility.md) for exact fixture coverage
and remaining work.
