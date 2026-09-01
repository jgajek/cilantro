# Corpus

There is one manifest per protector, and both contain metadata only. Malware and
oracle binaries are stored in the authorized Malware Vault and downloaded into
the ignored `samples/` directory. Every local file is SHA-256 verified before
analysis.

| Manifest | Covers |
| --- | --- |
| `corpus/reactor-6-nonvirt.manifest.json` | .NET Reactor 6, both generations, twelve samples |
| `corpus/reactor-7-static.manifest.json` | .NET Reactor 7.5, net48/net8/net10 probes, twelve entries |
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
  (`profiled`, `Qbjuef.exe`)
- `8266fb6626cb3ad88b3cb7d5d5542a530b38230445af7ff76d102f8c49129b16`
  (`detected`, `Reason.PAC.dll`)
- `15931d5e8c20547c24c851dcb2e29b747699e8b81b925c46c2245269c93d1c91`
  (`detected`, `rsServiceController.dll`)
- `be4044e81a4db3af715af05a0c34ebcc7ca909b42469e6b79ea15bbbf68f0c0b`
  (`detected`, `rsDatabase.protected.dll`)
- `e4e746f968a3ec89027484ab233d3d38c7778458a898d30f31bb74a2c97059d2`
  (`profiled`, `Qafcakg.payload.Ptnifif.dll`)
- `81cf796c987dbffeb950e38d7e4bc01e85bec2ef4b5a9750d9642843f8460c2a`
  (`detected`, `Mlfhntkcvb.payload.Lqcuzgc.dll`)
- `094dbed0af6664af52375a711e0b8e4e8e7e66c6d47390e8263b16efba4d1995`
  (`exploratory`, `WindowsManagement.exe`)

`Mlfhntkcvb.payload` and `Qafcakg.payload` are the assemblies that
`Mlfhntkcvb` and `Qafcakg` carry. Both are protected by Reactor in turn, so
recovering the outer sample only reaches the next wrapper, and they are in the
corpus in their own right for that reason.

`WindowsManagement.exe` is the odd one: not a .NET file at all, but a native
bootstrap with the assembly encrypted into a resource. Its only gate is
`expectedPayloadSha256`, the hash of what comes out, because the decryption has
no integrity check of its own — a table built slightly wrong still produces
bytes, and nothing short of the hash distinguishes those from the right ones.
What comes out is
`83ba5d833eba38f578eb8478f8961a0bddb63ff35016b40d8e0536b164ee1ed3`, a
Reactor-protected assembly in its own right, which is why the run stops there
rather than carrying on into it.

Fed back through the tool on its own, that inner assembly recovers in full:
28,725 method bodies come back with no stub left, its virtualized string table
is read whole (2,971 of 2,971 operations, the walk reaching 2,961 and the depths
agreeing everywhere), Reactor's resource-backed table is restored in full, its
resources come back, and five payloads are extracted — the 3.86 MB application
inside it and four Costura-packed dependencies — with the clean copy verifying
and reproducing byte-for-byte. All 11,107 of its string sites are restored, and
the reading that asks a resolver for each number reaching it now finishes clean
rather than owing three. Those three are not Reactor's: they are the program's
own methods wearing the `string(int)` shape a second-layer decoder would have —
an HTTP status-code to reason-phrase table read with a runtime status, a SOCKS5
code stringifier read with a runtime argument, and a `System.Random` name
generator. The reading tells each apart from a real decoder and leaves it alone:
a method reached only with a caller's own parameter is a pass-through the program
calls rather than a resolver of hidden literals, and one that draws on a random,
clock or guid source cannot be handing back a literal fixed at build time. None
holds a string to fold, and writing one in would replace behaviour with a wrong
constant, so none is counted as a string left undone. It is not a corpus entry
of its own: it is the payload the bootstrap already pins by hash, and reading it
in full costs minutes to re-assert that same hash, so the corpus stops at the
bootstrap and this is the note that it was carried the rest of the way by hand.

They are protected in two different ways, and each is held to what it reaches.
`Ptnifif` is a JIT-hook build: all 313 of its protected bodies come back and no
stub is left. Its strings are not behind Reactor's own resolver but behind a
decoder of the program's own, built at run time with `Reflection.Emit` and asked
for a string by number; the machine emits and runs it, and 153 call sites are
replaced with the 137 strings it answers with. Its own payload does not come
back, because the paths that would produce it call into `user32` and then ask
Windows about the machine it is running on, which is outside the runtime the
machine models.

`Lqcuzgc` is a virtualizing build whose string decryption is inside the virtual
machine, and it now comes back in full. The engine is read whole — 4,854 of
4,854 operations written as IL, the walk reaching 4,846 and stopping nowhere, the
depths agreeing everywhere, and the 8 operations left over being code no path
arrives at — and a triage run builds the one virtualized method back into the
cleaned copy from that reading. Its self-check no longer stands in the way: the
date-based trial guard the loader injects is recognised by shape and neutralised
during interpretation, so running the engine far enough to build the table no
longer throws. All 172 of its protected-string call sites are restored across
both layers — the 17 of Reactor's own resolver and the 155 the second protector
keeps in a domain-slot `Hashtable` and fetches by number — and a verified copy is
written, which is why it sits in the `detected` tier.

The one pass that reports unsupported without failing the run is
payload-extraction: this assembly is itself the final managed payload the outer
`Mlfhntkcvb` bootstrap unpacks, so there is no further stage inside it for the
module's own unpacker to produce.

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

## Reactor 7.5

The Reactor 6 samples above are real malware, which is their strength and their
limit: nobody has the unprotected original, so the only ground truth is what two
independent interpretations agree on and what a hash pins. The Reactor 7.5
manifest is the other kind of evidence. Its entries are *probes* — small programs
built from source by `corpus/probes/build.sh`, then run through .NET Reactor
7.5.0.0 — so each protected build has its unprotected self beside it as an oracle,
and recovery can be checked against the real answer byte for byte rather than only
against itself.

The same source is compiled for three target frameworks, which is what lets the
manifest separate a Reactor problem from a framework problem:

- **net48** — .NET Framework 4.8;
- **net8** and **net10** — modern .NET, which runs on CoreCLR rather than the
  .NET Framework runtime.

For each framework there are four entries: an `oracle` (the unprotected build, which
must be detected as `none`), a `strings`-only build, a `necrobit`-only build, and a
`full` build carrying string encryption, NecroBit, virtualization, and an encrypted
resource bundle. That is nine `detected` protected entries and three oracles.

All nine recover in full. The `necrobit` builds bring every protected body back with
no stub left (thirteen on net48, seven on each CoreCLR build); the `strings` builds
replace every protected-string call site with its plaintext; and the `full` builds do
both, resolve the delegate-proxy map, read the virtualized method end to end and
build it back into the cleaned copy, and decrypt the encrypted resource bundle. Every
recovered string and every recovered resource bundle matches the oracle's, and the
manifest
pins the body counts, full string-site coverage, the virtual-operation metrics, and
the SHA-256 of each recovered resource bundle, so a regression that reintroduced any
of the CoreCLR-specific gaps (module-base reflection, the JIT-hook delegate
round-trip, native-pointer body reads, Brotli resource decompression, or the
virtualized rebuild) fails here.

The one pass that reports unsupported without failing a `full` run is
payload-extraction: these probes pack no from-memory assembly for it to recover, so
there is nothing for it to produce.

Two caveats belong with this manifest. It is a controlled set of probes rather than a
cross-section of Reactor 7.x seen in the wild, so it proves the mechanisms work on
7.5, not that every real-world 7.x build is recognised. And the probes have few
methods, so in the `necrobit`-only configuration the detector's ten-stub and ten-proxy
thresholds sit near the edge and the detection confidence there says as much about
probe size as about the protector.

```bash
dotnet run --project src/Cilantro.Cli -- corpus run \
  --manifest corpus/reactor-7-static.manifest.json \
  --samples samples \
  --output artifacts/corpus
```

## ConfuserEx 1.0.0

Two samples, both `detected`, and both using the same set of layers: invisible
names, an encrypted section, anti-tamper, anti-debug, and a constants table.

- `06b9d08b33f2e22bfea6196867d35bb3cef7f11eb745d43017c7cb75183a8e3f`
  (`detected`, `confuser_06b9d08b33f2.dll`) — 242 bodies
- `61e3154419b3fe12955b22487b22a56dccaf416a5c184c9a8b8de133b9aa8e40`
  (`detected`, `confuser_61e3154419b3.dll`) — 279 bodies

Most gates here are gates on interpreting the sample's own decrypters, because
nothing about either sample's encryption is implemented in the tool. Each is
required to be identified as `confuserex` with all five capabilities, to have
every body come back with no stub left behind, and to reach complete coverage of
its string call sites — where complete means every site whose constant the tool
found literally at the call, which is what it claims rather than every site in
the module.

The flattening gates are the exception, since unflattening does not run the sample,
and there are two of them because one of them alone would be misleading. Each sample
pins a ceiling on how many methods may still hold a dispatcher — 77 of 127 flattened
methods for the first, 91 of 155 for the second — and a floor on how many dispatcher
edges must jump straight to their case: 4,600 and 5,850.

The pair is deliberate. A dispatcher survives if even one of its method's edges
does, so the method ceiling responds only weakly to the thing most worth protecting:
when edge redirection went from 144 edges to 4,451 on the first sample, the method
count moved by one. A regression that undid nearly all of that would sail through a
method ceiling and be caught immediately by the edge floor.

The string gate earns its keep here for a reason worth recording. Unflattening
these samples once broke the constants initializer, so the tool found no string
call sites at all rather than failing to replace the ones it found; because
coverage of nothing had been scored as full coverage, the gate stayed green through
a regression that cost every recovered string. Requiring a coverage minimum now
also requires that there was something to cover.

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

Where the samples are present the suite takes several minutes, and about a dozen
whole-sample tests account for all but a few seconds of it:

| Test | Share of the work |
| --- | --- |
| `CorpusTests.CorpusOutcomesAreDeterministic` | the Reactor 6 corpus, twice over |
| `CorpusTests.ConfuserExSamplesAreDecryptedAndRead` | the ConfuserEx corpus |
| `PipelineTests.PipelineRecoversProfiledSamples` | the profiled samples, fully emitted |
| `VmStringRecoveryTests.Qbjuef...` | one sample, string tables read |
| `StringLookupRecoveryTests.TheLayerUnderneathReactors...` | one sample, both string layers |
| `AntiTamperNeutralizationTests.RemovesProvenIntegrityCheck...` | one sample, analysed |
| `CorpusTests.MethodProtectedGenerationIsDetectedAndFullyRecovered` | one Reactor 6 sample, analysed |
| `CorpusTests.ReactorSixVirtualizedPayloadIsFullyRecovered` | one Reactor 6 payload, virtualized |
| `CorpusTests.ReactorSevenNecroBitFrameworkBodiesAreStaticallyRecovered` | one Reactor 7.5 net48 build |
| `CorpusTests.ReactorSevenNecroBitCoreClrBodiesAreStaticallyRecovered` | Reactor 7.5 net8 and net10 |
| `CorpusTests.ReactorSevenVirtualizedFullBuildIsFullyRecovered` | one Reactor 7.5 net48 full build |
| `CorpusTests.ReactorSevenCoreClrFullBuildIsFullyRecovered` | Reactor 7.5 net8 and net10 full builds |

They are described by work rather than by seconds because the seconds are not a
property of the test: the same sample recovery has been measured at 108 seconds
in one run and 418 in the next, unchanged, because a dozen interpretations running
at once contend for memory bandwidth far more than for cores. What is stable is
that these are minutes and the rest of the suite is a few seconds together.

Each is marked `Cost=High` and can be left out with
`--filter "Cost!=High"`, which is the loop to work in. None of them can run in
continuous integration, since the samples are not in the repository, so a person
running the full suite is the only thing that closes those gates.

Determinism is proven once, on the Reactor 6 side, rather than per sample elsewhere.
`CorpusOutcomesAreDeterministic` runs that corpus twice at once and requires the
two outcome files to be byte-for-byte identical; because each outcome carries the
SHA-256 of the assembly emitted for that sample, that one comparison covers
emission for every sample in it. Pinned hashes do the rest: a payload or an output
that changed for any reason fails the expectations in `PipelineTests`, the Reactor
7.5 corpus tests, and the manifests' own output locks, which is a stricter test
than comparing two runs of one build against each other.

The ConfuserEx side is not run twice, because the determinism that matters there
is already inside a single run: neither the section nor a single string is accepted
unless two independently built machines agreed, so a nondeterministic result fails
the run rather than passing it and differing from a second one.

`detected` ReasonLabs entries are release candidates rather than
analysis-only fixtures. They pass only when all protected application bodies
are restored and verified. `Qbjuef` is now `profiled`: its twelve string sites,
its delegate-proxy map and its virtualized method all come back, it emits a
verified clean copy deterministically, and the two payloads it carries are
pinned by hash. The `WindowsManagement` bootstrap stays `exploratory` because it
is a native file that emits no managed copy of its own; its only assertion is the
hash of the assembly it decrypts, which it meets.
