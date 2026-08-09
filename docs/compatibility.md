# Compatibility and provenance

## Corpus and support contract

The manifest at `corpus/reactor-6-nonvirt.manifest.json` contains nine
SHA-256-pinned entries:

- two `profiled` full-recovery fixtures;
- three `detected` JIT-hook/method-stub samples;
- one `exploratory` control-flow/proxy sample; and
- three deobfuscated validation oracles used as negative controls.

The three oracle assemblies are never implementation inputs. After recovery,
they are compared by assembly identity, entry-point kind, normalized method
signatures, public API sets, and resource sets. Binaries remain ignored under
`samples/`.

The batch runner verifies each input hash before analysis. `profiled` and
`detected` entries must emit deterministic verified output; `exploratory`
entries remain analysis-only; negative controls must receive no destructive
edits. Recovery expectations include restored-body counts, remaining-stub
limits, string-site coverage, mutation limits, and optional oracle parity.

```bash
dotnet run --project src/ReactorUnpack.Cli -- corpus run
```

The full-recovery profile was derived independently from:

- `ad0c3182b18b5d7ba8771d830f4d51b4ada7e26f8d05223f4379e6312aba65fa`
- `c405398fc582e33bbbd37222b7360a6cfdc526146622141503de1ccf9de6174a`

Both are x86 .NET Framework 4 assemblies protected by the same .NET Reactor 6
runtime generation. Detection uses structural evidence rather than randomized
names:

- 279 `MulticastDelegate` proxy types;
- 1,341 methods with a branch over an unreachable invalid call;
- a resource-backed method-token resolver;
- dynamic-method and delegate-construction APIs; and
- malformed decoy metadata references.

## Implemented formats

### Recovery trust boundary

The pipeline is divided into preflight, analysis, original-byte recovery,
IL-transform, and verify/emit phases. A JIT-hook artifact cannot enter any
downstream mutating pass until complete method restoration is proven.
`PeImageView` validates PE32/PE32+ sections, maps RVAs without treating virtual
zero-fill as file data, and constructs a bounded loader-style image.

The bounded CIL machine models concrete values, objects, arrays, managed and
synthetic native pointers, static/instance fields, branches, switches, and
single-level deterministic finally flow. Framework calls are deny-by-default.
Allowlisted models cover resources, streams/readers, encoding, hashing,
decompression, symmetric crypto, synthetic module/process metadata, Marshal
operations, and virtual memory writes. Unknown branches, unmodeled calls,
symbolic writes, malformed ranges, and exhausted budgets stop recovery.

Every method mutation has a full-body transaction. Instructions, branch
operands, locals, max-stack settings, and exception handlers are restored
together on rollback.

### Dispatcher recovery

An EH-aware basic-block graph distinguishes raw switches from qualified Reactor
dispatchers. Rewrites require a unique state local, complete incoming-edge
accounting, concrete transitions, legal EH-region edges, and valid stack
analysis before and after mutation. Ambiguous methods are preserved.

### Invalid-call prefix

The normalizer recognizes only the proven entry sequence
`branch instruction[2]; call unreachable; instruction[2]`. Both instructions
are replaced with `nop`, preserving branch and exception-handler references.
Operand validation is performed on reachable instructions.

### Proxy map generation R6-2026-A

The 2,232-byte resource is decoded as a stateful little-endian UInt32 stream.
The result must match its profile hash and contain exactly 279 eight-byte
records:

```text
uint32 fieldToken
uint32 encodedTarget

targetToken = encodedTarget & 0x3fffffff
callvirt    = (encodedTarget & 0x40000000) != 0
```

Every field and target token is resolved before any edit. A valid use site is
the adjacent pair `ldsfld mappedField; call staticAdapter`. It is rewritten to
`nop; call|callvirt target`, preserving stack behavior and instruction
identity. Each fixture has 2,643 validated sites.

The generic strategy locates a resource whose length equals eight bytes per
proxy field, extracts candidate stream constants from the token-resolver IL,
and accepts a pair only when every decoded field and method token resolves and
the mapping is bijective. This derives Qbjuef's 146-record generation
(`A=0x64875CD0`, `D=0x7511923A`) without its input hash. Known hashes remain only
as regression fallbacks.

### Embedded resource assembly

The protected host's `ResourceResolve` path consumes the large, high-entropy
resource and eventually passes decompressed bytes to `Assembly.Load(byte[])`.
ReactorUnpack models that load as a capture sink and never invokes it.

For the supported fixtures, extraction:

1. selects the resource by SHA-256 rather than its randomized name or ordinal;
2. applies the profiled eight-word keyed stream transform with unchecked
   UInt32 arithmetic;
3. verifies the decoded raw-DEFLATE stream hash;
4. inflates it with a 256 MiB output limit;
5. verifies output length and SHA-256; and
6. parses the result with dnlib and verifies its assembly identity.

Recovered resource-only assemblies:

- `f94b00a2-0086-4424-b9df-e76ba48d2dee.dll`, 485,376 bytes,
  SHA-256 `7fa1a9d74dad14fd686ad7b2e794111d1093de3fefe97c51d1908e44586d04de`;
- `cf07e290-4799-450f-969c-80255a1a4f0c.dll`, 86,528 bytes,
  SHA-256 `1db4e9c40d83bb790b89963888fd9a112b1d2467f7194dc55b6c35e14e443429`.

Each resource assembly contains one terminal `.resources` v2 ByteArray record.
The extractor locates that record with strict framing and hash checks without
deserializing resource objects. It then reproduces the application's legacy
TripleDES-CBC/PKCS7 stage, validates a little-endian output-length prefix,
bounded-decompresses the following GZip stream, and parses the final bytes as
managed metadata. It never reproduces the application's final
`Assembly.Load`/reflection invocation.

Final managed payloads:

- `Lqcuzgc.dll`, 858,112 bytes, SHA-256
  `81cf796c987dbffeb950e38d7e4bc01e85bec2ef4b5a9750d9642843f8460c2a`;
- `Ptnifif.dll`, 154,112 bytes, SHA-256
  `e4e746f968a3ec89027484ab233d3d38c7778458a898d30f31bb74a2c97059d2`.

### Protected strings

The fixtures use a virtualized initializer for a UTF-16LE record table. The
resolver consumes an absolute byte offset and performs a caller check. The two
proven direct uses are restored statically with a stack-neutral
`pop; ldstr value` substitution:

- encrypted payload resource name; and
- `"Load "`, subsequently trimmed by the original code.

The resolver is never invoked.

For generic inputs, table capture and call-site rewriting are separate passes.
A table must be unique and strictly length-framed UTF-16, and every reachable
resolver use must have a proven offset. Replacements are atomic across the
assembly; one unresolved use causes zero string edits.

## Verification gates

Before emission, the tool checks:

- all branch and switch targets belong to their method;
- exception-region boundaries belong to their method;
- no reachable call has an invalid operand;
- public API, resource names, entry point, and strong-name state are preserved;
- every pass is complete (partial and unsupported recovery always block output);
- the emitted file reloads and passes the same structural verification.

The writer preserves metadata tokens and writes atomically. End-to-end tests
also assert deterministic binary output, entry-point preservation, fixture
hashes, pass counts, and independent dnlib reload.

## Fail-closed capability boundaries

- JIT-hook writes that do not deterministically target every catalogued stub;
- Reactor VM instructions or exception paths outside the bounded model;
- non-unique or incompletely referenced VM-backed string tables;
- code-virtualization lifting;
- destructive removal of runtime/proxy types and encrypted resources;
- renaming; and
- dynamic execution of protected assemblies.

The JIT-hook generation is detected through duplicate raw metadata rows,
hundreds of `NoInlining` default-return stubs, high-entropy patch resources,
large switch dispatchers, `clrjit` references, and runtime-module pointer
access. The recovery pass repeats interpretation, validates write-log identity,
restricts writes to catalogued method-prefix windows, reparses restored bodies
by unchanged MethodDef token, and requires all stubs to pass branch/stack/EH
verification. Any unmet condition preserves every body and refuses output.

## Generic analysis components

- Raw `BSJB`/tables-stream preflight records duplicate Module/Assembly rows,
  invalid stream bounds, and zero sorted masks before mutation.
- Resource roles are inferred from consumers such as `ResolveMethod`,
  `GetManifestResourceStream`, `Assembly.Load`, and `string(int32)` resolvers.
- Bounded integer evaluation handles constant arithmetic, shifts, and bitwise
  operations; constant array discovery recovers FieldRVA and IL-built material.
- Conservative CFG reachability, exception roots, dispatcher detection, and
  evaluation-stack analysis are bounded and diagnostic.
- Payload stage gates require strict terminal ByteArray framing, bounded
  decompression, `MZ`/CLR metadata, and independent managed parsing.
- Mutations have rollback support; destructive cleanup requires complete
  recovery, no remaining use sites, and at least 0.95 confidence.

Unsupported mechanisms remain intact and are reported. This is safer than
claiming broad Reactor 6/7 compatibility or emitting a partially damaged file.

## Clean-room boundary

Behavioral specifications came from the supplied binaries and independently
authored tests. No source or binaries from NETReactorSlayer or de4dot are used.
The project depends on dnlib under its MIT license.
