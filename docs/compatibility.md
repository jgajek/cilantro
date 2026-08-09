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

- generalized extraction of proxy stream constants from arbitrary Reactor
  builds;
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
