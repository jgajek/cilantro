# Compatibility and provenance

## Supported fixture profile

The first profile was derived independently from these authorized samples:

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

Per-build stream constants are selected only after the original resource and
decoded payload hashes match. Unknown profiles are not decoded.

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

## Verification gates

Before emission, the tool checks:

- all branch and switch targets belong to their method;
- no reachable call has an invalid operand;
- all required passes succeeded when `--fail-on-partial` is used; and
- the emitted file reloads and passes the same structural verification.

The writer preserves metadata tokens and writes atomically. End-to-end tests
also assert deterministic binary output, entry-point preservation, fixture
hashes, pass counts, and independent dnlib reload.

## Intentionally unsupported

- generalized extraction of stream constants from arbitrary Reactor builds;
- generic interpretation of Reactor's virtualized string initializer;
- method/native-code decryption and anti-tamper patch maps;
- code-virtualization lifting;
- destructive removal of runtime/proxy types and encrypted resources;
- renaming; and
- dynamic execution of protected assemblies.

Unsupported mechanisms remain intact and are reported. This is safer than
claiming broad Reactor 6/7 compatibility or emitting a partially damaged file.

## Clean-room boundary

Behavioral specifications came from the supplied binaries and independently
authored tests. No source or binaries from NETReactorSlayer or de4dot are used.
The project depends on dnlib under its MIT license.
