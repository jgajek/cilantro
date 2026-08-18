# Corpus

There is one manifest per protector, and both contain metadata only. Malware and
oracle binaries are stored in the authorized Malware Vault and downloaded into
the ignored `samples/` directory. Every local file is SHA-256 verified before
analysis.

| Manifest | Covers |
| --- | --- |
| `corpus/reactor-6-nonvirt.manifest.json` | .NET Reactor 6, both generations, eleven samples |
| `corpus/confuserex-1-static.manifest.json` | ConfuserEx 1.0.0, whole-section anti-tamper, two samples |

Each sample names the protector it is expected to be identified as, so a change
that made one detector claim the other's samples would fail rather than pass
quietly. Detection is compared against the protector the run settled on, not
against whether any protector was found.

## Reactor 6

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
`Ptnifif` is a JIT-hook build: all 313 of its protected bodies come back and no
stub is left. Its strings are not behind Reactor's own resolver but behind a
decoder of the program's own, built at run time with `Reflection.Emit` and asked
for a string by number; the machine emits and runs it, and 153 call sites are
replaced with the 137 strings it answers with. Its own payload does not come
back, because the paths that would produce it call into `user32` and then ask
Windows about the machine it is running on, which is outside the runtime the
machine models.

`Lqcuzgc` is a virtualizing build whose string decryption and payload unpacking
are both inside the virtual machine, so what is locked for it is the reading of
that machine: 4,851 of its 4,854 operations written as IL, the walk reaching
4,846 and stopping nowhere, the depths agreeing everywhere, and the 8 operations
left over being code no path arrives at. Its strings and its payload are still
declined rather than guessed at, and its self-check is no longer what stands in
the way: the module is interpreted as the assembly with no file of its own that a
recovered payload is, which is the case its own code makes room for, and under
that reading nothing in the loader throws.

What stands in the way of its strings is two things above the decoder. Each call
site computes the key rather than carrying it — three constants combined with
`xor` and `sub`, and then an integer field of the second protector's state object
mixed in — and that object is never built during the loader initialization the
machine runs, so none of its fields is proven and the key is not a constant to
fold. Behind that, the table those keys index is parsed by the virtualized method,
so reading a string means running the engine far enough to have built it.

Validation-only deobfuscated counterparts:

- `82d2b678896ebb388c4ef9ea877e898d1ac2907d956deec4035faddda847dec0`
- `6cdf18c01fe19595d44022a587b3ecca978962013e78f006fdfb299aadbe33d9`
- `482100ea3682a84991de0e02dcce449ecd4bea6495999c1a05c95dd37facbd3d`

The counterparts are negative controls and structural oracles. They are not
used to derive algorithms, constants, keys, names, or output bytes.

Reproduce the normalized corpus result:

```bash
dotnet run --project src/Cilantro.Cli -- corpus run \
  --manifest corpus/reactor-6-nonvirt.manifest.json \
  --samples samples \
  --output artifacts/corpus
```

The command returns nonzero for a missing or mismatched file, an unexpected
detection/capability result, a failed pass, or a required sample that cannot
emit verified output. Manifest gates can additionally require exact restored
body counts, zero remaining stubs, complete string-site coverage, bounded
mutation counts, a regression-locked output hash, and normalized oracle parity.

## ConfuserEx 1.0.0

Two samples, both `detected`, and both using the same set of layers: invisible
names, an encrypted section, anti-tamper, anti-debug, and a constants table.

- `06b9d08b33f2e22bfea6196867d35bb3cef7f11eb745d43017c7cb75183a8e3f`
  (`detected`, `confuser_06b9d08b33f2.dll`) — 242 bodies
- `61e3154419b3fe12955b22487b22a56dccaf416a5c184c9a8b8de133b9aa8e40`
  (`detected`, `confuser_61e3154419b3.dll`) — 279 bodies

Every gate here is a gate on interpreting the sample's own decrypters, because
nothing about either sample's encryption is implemented in the tool. Each is
required to be identified as `confuserex` with all five capabilities, to have
every body come back with no stub left behind, and to reach complete coverage of
its string call sites — where complete means every site whose constant the tool
found literally at the call, which is what it claims rather than every site in
the module.

There are no oracles on this side. The counterparts that make the Reactor gates
sharp are unprotected builds of the same programs, and none exist for these two,
so what holds them is the internal agreement instead: the two interpretation runs
must produce identical write logs before the section is replayed, and the two
constants machines must agree on every value read in both directions before a
string is put back.

```bash
dotnet run --project src/Cilantro.Cli -- corpus run \
  --manifest corpus/confuserex-1-static.manifest.json \
  --samples samples \
  --output artifacts/corpus
```

## The suite where there are no samples

A checkout with an empty `samples/` directory still runs the suite. Tests that
read a real sample are marked as such and are skipped where there are none, so
`dotnet test` reports them as skipped with the reason instead of failing on a file
nobody could have supplied. That is how CI runs: green there means everything
checkable without samples was checked, and the skipped count is the measure of
what was not. Restoring the samples runs the same tests for real.

A checkout that has samples but not the one a test names fails rather than skips.
That is a corpus that has drifted from the suite, which is worth hearing about,
where a wholly absent corpus is a choice the repository made.

## What the suite costs

Where the samples are present the suite takes about twelve minutes, and eight
tests account for all but five seconds of it:

| Test | Share of the work |
| --- | --- |
| `CorpusTests.CorpusOutcomesAreDeterministic` | the Reactor corpus, twice over |
| `CorpusTests.ConfuserExSamplesAreDecryptedAndRead` | the ConfuserEx corpus |
| `PipelineTests.PipelineRecoversProfiledSamples` | two samples, fully emitted |
| `VmStringRecoveryTests.Qbjuef...` | one sample, string tables read |
| `StringLookupRecoveryTests.TheLayerUnderneathReactors...` | one sample, both string layers |
| `AntiTamperNeutralizationTests.RemovesProvenIntegrityCheck...` | one sample, analysed |
| `CorpusTests.MethodProtectedGenerationIsDetectedAndFullyRecovered` | one sample, analysed |

They are described by work rather than by seconds because the seconds are not a
property of the test: the same sample recovery has been measured at 108 seconds
in one run and 418 in the next, unchanged, because a dozen interpretations running
at once contend for memory bandwidth far more than for cores. What is stable is
that these eight are minutes and the other 405 are five seconds together.

Each of the eight is marked `Cost=High` and can be left out with
`--filter "Cost!=High"`, which is the loop to work in. None of them can run in
continuous integration, since the samples are not in the repository, so a person
running the full suite is the only thing that closes those gates.

Determinism is proven once, on the Reactor side, rather than per sample elsewhere.
`CorpusOutcomesAreDeterministic` runs that corpus twice at once and requires the
two outcome files to be byte-for-byte identical; because each outcome carries the
SHA-256 of the assembly emitted for that sample, that one comparison covers
emission for every sample in it. Pinned hashes do the rest: a payload or an output
that changed for any reason fails the expectations in `PipelineTests` and the
manifest's own output locks, which is a stricter test than comparing two runs of
one build against each other.

The ConfuserEx side is not run twice, because the determinism that matters there
is already inside a single run: neither the section nor a single string is accepted
unless two independently built machines agreed, so a nondeterministic result fails
the run rather than passing it and differing from a second one.

`detected` ReasonLabs entries are release candidates rather than
analysis-only fixtures. They pass only when all protected application bodies
are restored and verified. Qbjuef remains exploratory until its complete
string/proxy use set is accounted for; refusal without edits is an acceptable
exploratory outcome.
