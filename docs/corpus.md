# Reactor 6 corpus

The committed manifest contains metadata only. Malware and oracle binaries are
stored in the authorized Malware Vault and downloaded into the ignored
`samples/` directory. Every local file is SHA-256 verified before analysis.

Protected and exploratory samples:

- `ad0c3182b18b5d7ba8771d830f4d51b4ada7e26f8d05223f4379e6312aba65fa`
  (`profiled`, `embedded_dotnet_Mlfhntkcvb.exe`)
- `c405398fc582e33bbbd37222b7360a6cfdc526146622141503de1ccf9de6174a`
  (`profiled`, `embedded_dotnet_Qafcakg.exe`)
- `c8fab65dedd9c62a35cfab7e318225c42cc838d57fe0a1f072b195a1a779523b`
  (`exploratory`, `Qbjuef.exe`)
- `8266fb6626cb3ad88b3cb7d5d5542a530b38230445af7ff76d102f8c49129b16`
  (`detected`, `Reason.PAC.dll`)
- `15931d5e8c20547c24c851dcb2e29b747699e8b81b925c46c2245269c93d1c91`
  (`detected`, `rsServiceController.dll`)
- `be4044e81a4db3af715af05a0c34ebcc7ca909b42469e6b79ea15bbbf68f0c0b`
  (`detected`, `rsDatabase.protected.dll`)
- `e4e746f968a3ec89027484ab233d3d38c7778458a898d30f31bb74a2c97059d2`
  (`profiled`, `Qafcakg.payload.Ptnifif.dll`)
- `81cf796c987dbffeb950e38d7e4bc01e85bec2ef4b5a9750d9642843f8460c2a`
  (`exploratory`, `Mlfhntkcvb.payload.Lqcuzgc.dll`)

The last two are the assemblies the first two carry. Both are protected by
Reactor in turn, so recovering the outer sample only reaches the next wrapper,
and they are in the corpus in their own right for that reason.

They are protected in two different ways, and each is held to what it reaches.
`Ptnifif` is a JIT-hook build: all 313 of its protected bodies come back, no
stub is left, and its own payload does not, because the paths that would produce
it call into `user32` and then build an assembly with `Reflection.Emit` — one is
outside the runtime the machine models and the other is code that does not exist
until it runs. `Lqcuzgc` is a virtualizing build whose string decryption and
payload unpacking are both inside the virtual machine, so what is locked for it
is the reading of that machine: every operation but a handful written as IL, the
walk reaching all but the dead blocks, and the depths agreeing everywhere. Its
strings and its payload are not recovered, and both are declined in the report
rather than guessed at. Nothing in the virtual machine runs far enough to
produce them: the program checks its own file against a signature it carries,
and under interpretation that check throws before the decryption it guards.

Validation-only deobfuscated counterparts:

- `82d2b678896ebb388c4ef9ea877e898d1ac2907d956deec4035faddda847dec0`
- `6cdf18c01fe19595d44022a587b3ecca978962013e78f006fdfb299aadbe33d9`
- `482100ea3682a84991de0e02dcce449ecd4bea6495999c1a05c95dd37facbd3d`

The counterparts are negative controls and structural oracles. They are not
used to derive algorithms, constants, keys, names, or output bytes.

Reproduce the normalized corpus result:

```bash
dotnet run --project src/ReactorUnpack.Cli -- corpus run \
  --manifest corpus/reactor-6-nonvirt.manifest.json \
  --samples samples \
  --output artifacts/corpus
```

The command returns nonzero for a missing or mismatched file, an unexpected
detection/capability result, a failed pass, or a required sample that cannot
emit verified output. Manifest gates can additionally require exact restored
body counts, zero remaining stubs, complete string-site coverage, bounded
mutation counts, a regression-locked output hash, and normalized oracle parity.

`detected` ReasonLabs entries are release candidates rather than
analysis-only fixtures. They pass only when all protected application bodies
are restored and verified. Qbjuef remains exploratory until its complete
string/proxy use set is accounted for; refusal without edits is an acceptable
exploratory outcome.
