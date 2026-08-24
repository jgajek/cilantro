# How CILantro compares to the other Reactor tools

This page is about the Reactor side only. That is where the comparison is worth
making: four open-source tools deal with .NET Reactor and they are not competitors
so much as different jobs, whereas on the ConfuserEx side this tool is the newcomer
against a field that has had a decade to work on it, and the honest summary of that
comparison is the two rows in the README's matrix that say no.

So: which one to reach for, what each of them handles, and where CILantro is
weaker than the alternatives — because the fastest way to waste an afternoon is to
use a tool for the thing it does not do.

- **[NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer)** — the
  general-purpose Reactor unpacker most people start with. Fifteen stages, a
  Windows GUI and a CLI that also runs on Linux, GPLv3.
- **[de4dotEx](https://github.com/GDATAAdvancedAnalytics/de4dotEx)** — the
  maintained fork of de4dot, from G DATA Advanced Analytics. Handles about
  twenty-five obfuscator families, Reactor among them, and is the one with
  explicit support for Reactor 7.0 and later. GPLv3.
- **[Krypton](https://github.com/dawwinci/krypton-devirtualizer)** — a
  purpose-built devirtualizer whose goal is a devirtualized binary that still
  runs. Continuation of PeterG75's Krypton, GPLv3.
- **CILantro** — this tool. Reactor 6 and ConfuserEx 1.0.0, never executes the
  sample, and refuses to write anything it cannot prove. MIT.

Everything below was checked against each project's source and release notes in
August 2026. All three of the others are moving targets, and which Reactor
version each handles best changes with them.

## Which one to reach for

| If you want to | Reach for | Because |
| --- | --- | --- |
| Know what an unfamiliar sample is, and get the next stage out, without running it | CILantro | Nothing in the sample executes, and the payload comes out of a static reading of the unpacker |
| The most thoroughly cleaned assembly a Reactor tool will give you | NETReactorSlayer | Widest stage coverage of the four, and it invokes the sample's own decrypters, so codecs nobody has modeled still come out |
| Handle a Reactor 7+ sample, or one under a protector neither of these two covers | de4dotEx | It is the one that states support for Reactor 7.0 and later, and it covers about twenty-five families where this tool covers two |
| A devirtualized binary you can run and debug | Krypton | That is its stated goal; it rebuilds VM methods in place and patches the output until it starts |
| Read a virtualized method without running anything | CILantro | It builds the method back into the cleaned copy, reports the recovered program as a listing beside it, and says how each reading was arrived at |
| Rename everything, including public types, the way de4dot does | Slayer or de4dotEx | Both carry the full de4dot renamer; CILantro renames only what it can prove is generated |

If you have a Reactor 6 crypter and no idea what is inside it, a reasonable
order is: CILantro first, because it costs you nothing to run it on a live
sample and it hands you the payload; then Slayer or de4dotEx on that payload if
you want a more aggressively cleaned assembly; then Krypton if what you are left
with is virtualized and you would rather debug it than read it.

## What each one handles

| Protection | CILantro | NETReactorSlayer | de4dotEx | Krypton |
| --- | --- | --- | --- | --- |
| Method bodies encrypted (NecroBit) | Yes, statically | Yes | Yes | — |
| Strings encrypted | Yes, statically | Yes | Yes | Opt-in |
| Control flow flattened, junk woven in | Yes | Yes | Yes | Yes, in cleanup |
| Calls hidden behind proxy delegates | Yes | Yes | Yes | Yes, by running it |
| Metadata tokens proxied | Yes | Yes | Yes | — |
| Booleans decrypted at run time | Yes | Yes | Yes | — |
| Embedded resources encrypted | Yes | Yes | Yes | Opt-in |
| Next stage hidden inside | Yes, any crypter | Reactor's own | Reactor's own | — |
| Costura bundle | Yes | Yes | — | — |
| Anti-tamper and anti-debug | Yes, where proven | Yes | Anti-debug, strong name | Heuristic patches |
| Native-packed stub | Detects, refuses | Unpacks | Unpacks | — |
| Methods turned into bytecode | Reads, rebuilds in place | Detects only | Rebuilds in place | Rebuilds in place |
| Names destroyed | Non-public only | Full de4dot renamer | Full de4dot renamer | Pattern-based |
| Protectors other than Reactor | — | — | About 25 families | — |

A dash means the tool does not attempt it, which is not the same as failing at
it. Four cells deserve their footnote:

- **Krypton's strings and resources** are off unless you set
  `KRYPTON_STRING_DECRYPT=1` or `KRYPTON_RESOURCE_DECRYPT=1`, and its own README
  says both skip RSA and NecroBit-tier blobs. It has no method-body decryption
  stage at all, so on a NecroBit sample you want another tool first.
- **de4dotEx's Reactor devirtualizer** is on by default, but the release that
  introduced it notes it has mainly been tested on protection-specific methods
  such as string decryption, rather than on arbitrary program code.
- **CILantro's rebuilt virtualized methods** go into the cleaned copy, each
  marked with a `[RebuiltFromReading]` attribute that a decompiler shows above the
  method, because a body built from a reading is not the same kind of result as a
  decrypted one. Where the sample's own unpacking path runs through the method,
  the tool interprets that path both ways and tells you whether the same payload
  came out.
- **"Detects, refuses"** means the run stops and says what it found, rather than
  writing a mangled file that looks like a result.

## All four on one hard sample

The tables above are read off each project's source. This section is the opposite
kind of evidence: all four tools run on the same file, with the outputs measured
rather than taken from what each tool printed about itself.

The file is `81cf796c987dbffeb950e38d7e4bc01e85bec2ef4b5a9750d9642843f8460c2a`,
858,112 bytes, the .NET payload out of a Reactor crypter. It is worth using as a
yardstick because it is protected **twice**: Reactor on the outside, and a second
obfuscator underneath it that keeps its strings somewhere Reactor tooling has no
reason to look. Two things about its shape decide the whole result:

1. **Reactor's string table is built by a virtualized method.** The table is not
   a run of encrypted bytes anyone can decrypt in place. It is produced at run
   time by `Rj743eA3ha`, a method that is no longer CIL at all — it is 4,854
   operations of bytecode for a per-build interpreter. To get the table you have
   to read that program.
2. **The second layer's strings are behind the first.** Under Reactor there are
   155 more string sites, fetched from a dictionary parked in a slot of the
   application domain. The code that fills that dictionary is itself written in
   Reactor-encrypted strings, so the inner layer only becomes readable after the
   outer one is already undone.

The input has 36 distinct string literals, 673 types and 3,708 methods.

### What came out

| | CILantro | NETReactorSlayer | de4dotEx | Krypton |
| --- | --- | --- | --- | --- |
| Produced an output file | yes | only with its string stage switched off | only when told which obfuscator | yes |
| Wall time | 45s | 2.9s | 2.3s | 18s |
| **Distinct string literals in the output** | **192** | 31 | 8 | **0** |
| Reactor's own 17 string sites | **all 17** (11 distinct literals) | none | **all 17** (7 of those 11) | none |
| The inner layer's 155 string sites | **all 155** | none, all 155 left as calls | none, all 155 left as calls | not reached |
| String lookups left unresolved | **0** | 172 | 155 | n/a, still behind proxies |
| C2 address, port, campaign ID | **recovered** | no | no | no |
| The virtualized table builder | **rebuilt, 15,271 instructions** | detected and warned about | type removed | rebuild rejected by its own safety gate |
| Ran the sample | **no** | yes — and died there | no | attempted, could not on Linux |

The row that decides an analyst's afternoon is the configuration. Only
CILantro's output contains this, and it is the answer to "what is this
thing":

```
https://logs.uvexio.com    port 8443    campaign 36f871795ba82    TEA key
/ping  /userinfo  /browser  /crypto  /discord  /application  /plugin
/filesearch/req  /filesearch/res  /chunk/start  /chunk/data  /chunk/end
X-Api-Key
```

...alongside the sample's entire anti-analysis blacklist, which is the other
thing you want on first contact: `sbiedll.dll`, `cuckoomon.dll`, `x64dbg`,
`x32dbg`, `windbg`, `ollydbg`, `ida`, `wireshark`, `procmon`, `fiddler`, the
VMware / VirtualBox / QEMU / Xen / Parallels driver and registry paths, the four
`SELECT * FROM Win32_*` queries, and the MAC prefixes each hypervisor hands out.

de4dotEx's output keeps the same configuration blob in the form the inner layer
stored it, `n4Q4kpXa4q8ugJzSr4kii...`, which tells you nothing. Krypton's output
has no string literals in it at all.

### Why each of the other three stopped where it did

None of this is a bug in those tools. Each stopped for a reason that follows
from how it is built, and on a sample without the second layer all four would
look much more alike.

- **NETReactorSlayer** got furthest of the three on Reactor itself — it removed
  the anti-tamper and anti-debug, fixed 4,562 proxied calls and 13 metadata
  tokens, and correctly warned `CODE VIRTUALIZATION HAS BEEN DETECTED`. Then it
  **segfaulted**, writing nothing. The crash is in `StringDecrypter`, which is
  the stage that reflectively invokes the sample's own decrypter: disable that
  one stage with `--dec-strings false` and it finishes in 2.9 seconds. So the
  failure is precisely at the point where it hands control to the malware. Its
  method decrypter also could not start (`Could not initialize decrypter`),
  leaving NecroBit in place.
- **de4dotEx** was the only one to crack Reactor's own string layer without
  reading the virtual machine, which is a real result. It got there through its
  own reimplementation of the resource-backed decrypter, clearing all 17 sites
  and the resolver behind them; 7 of the 8 literals in its output are ones we
  also recover, the missing 4 being at sites in code it deleted. It then removed
  the type holding the virtualized method — defensible, since that method is
  Reactor's own table builder rather than the malware's code — and left all 155
  inner-layer lookups as calls to a `(int) -> string` method it does not
  recognise as a string resolver, because no run of bytes in the file looks like
  a table. Two smaller notes: it identified this Reactor 6 sample as `>= 7.0`,
  and on automatic detection it crashed in the **Babel** detector before ever
  reaching Reactor, so it only ran at all once told `-p dr4`.
- **Krypton** mapped the virtual machine and recompiled both methods, then its
  own IL safety gate refused to install the big one — `cil issues=26106,
  dnlib issues=854` against a limit of 512 — which is the honest outcome for a
  tool whose promise is that the output still runs. Its cleanup stage then
  stubbed that method's body to a single `ret`. Strings and resources are opt-in
  and we enabled both; the string stage found a decoder candidate but no call
  sites, because the calls are still behind Reactor's proxies at that point.

### What this does not show

Read the table as one hard sample, not a ranking.

- **The Linux environment penalised two of them.** Slayer and Krypton both lean
  on running the sample, and both were run here on Linux under .NET 10, where
  Reactor's runtime cannot do what it expects. Krypton's helper,
  `Krypton.Runner.exe`, is a .NET Framework 4.8 executable and simply could not
  start, so its `HiddenCallRecovery` stage was unavailable and its default run
  came out byte-identical to one with that stage disabled. **On Windows both
  would do better than this**, and Slayer's string stage might well succeed
  outright — that is the whole point of invoking the real decrypter.
- **We are much slower.** 45s against 2.3s. A third of that is reading the virtual
  machine: `--no-devirtualize` brings it to 29s with all 172 strings still
  recovered, so the string result does not depend on the rebuild. Interpreting a
  loader instead of running it costs more than an order of magnitude, every time.
  It used to cost nearly seven minutes here; the interpreter was doing work
  quadratic in the size of the buffers a protector decrypts into, and in the
  number of types in the module, and neither had to be.
- **One sample cannot rank renaming, Reactor 7, or native stubs**, all of which
  the others do better or at all. See [Where CILantro loses](#where-cilantro-loses).

### Reproducing it

Tools built from source at their August 2026 tips, on Linux with .NET 10:

```bash
# ours
cilantro Lqcuzgc.dll

# NETReactorSlayer — omit the flag to reproduce the segfault
dotnet NETReactorSlayer.CLI.dll Lqcuzgc.dll --dec-strings false --no-pause true

# de4dotEx — without -p dr4 it crashes in an unrelated family's detector
de4dot -f Lqcuzgc.dll -o out.dll -p dr4

# Krypton — both stages are opt-in
KRYPTON_STRING_DECRYPT=1 KRYPTON_RESOURCE_DECRYPT=1 dotnet Krypton.dll Lqcuzgc.dll
```

Literal counts are distinct `ldstr` operands over every method body; unresolved
lookups are `call`/`callvirt` sites targeting a static `(int) -> string` method.

## How each one behaves

| | CILantro | NETReactorSlayer | de4dotEx | Krypton |
| --- | --- | --- | --- | --- |
| Executes the protected sample | Never | Yes | Not on the Reactor path | Yes, by default |
| Reactor versions | 6 only, refuses the rest | Not stated | 3.x through 7.0+ | Where the handler patterns are known |
| What you get | Cleaned copy with virtualized methods built back into it, report, payloads | Cleaned copy | Cleaned copy | Runnable devirtualized copy and a per-method report |
| When it cannot do something | Writes nothing and names the blocker | Skips the stage | Skips the stage | Skips the method |
| Runs on | Single file, Windows or Linux, no runtime needed | CLI on .NET 6 or Framework, Windows or Linux; the GUI is Windows-only | .NET Framework or Mono, Docker image published | Windows x64, .NET 8 |
| Licence | MIT | GPLv3 | GPLv3 | GPLv3 |

## The question behind all of it: does the tool run the malware?

This is the difference that matters most and the one least visible in a feature
list. Reactor's decryption keys are in the sample, so the shortest way to get a
plaintext is to let the sample decrypt it for you. Two of these four take that
route, and both are stronger for it in exactly the way they are riskier.

**NETReactorSlayer** loads the target with `Assembly.Load`/`UnsafeLoadFrom` and
reflectively invokes the sample's own decrypter methods, defeating Reactor's
caller check by patching `StackTrace.GetMethod`. That is why its string recovery
is correct for codec variants nobody has modeled — and it is also why running it
on malware is an execution event on your machine. The CLI runs on Linux, which
puts it in a container where that matters less, at the cost of running the
sample's code on a host it was not written for: a decrypter that reaches for a
Windows API fails there rather than decrypting.

**Krypton** runs the original assembly through a .NET 4.8 helper to capture
Reactor's `DynamicMethod` delegate table, which is how it turns hidden calls back
into direct ones. It is on by default and can be turned off with
`KRYPTON_HCR_ENABLE=0`, at the cost of that recovery. Its output is also
deliberately patched to keep running — `Hashtable` capacity sanitisation, a
WinForms entry-guard bypass, anti-manipulation neutralisation — so the result is
a runnable approximation rather than a faithful copy. For its purpose that is
the right trade; it is worth knowing you have made it.

**de4dotEx** does not execute the sample on the Reactor path: decryption is
reimplemented in the tool, with de4dot's IL emulator for the algorithmic parts.
Note that de4dot's *generic* string-decryption modes do run the target's code —
the `--strtyp emulate` mode, despite the name, executes IL rather than emulating
it — but the Reactor deobfuscator does not use them.

**CILantro** never loads or invokes protected code. It reads the file as
data and interprets the IL under a bounded machine with no real filesystem,
registry, network, or process behind it, working out what the decryption *would*
produce. That is the whole design constraint, and everything CILantro is
worse at follows from it: no unmodeled codec can be run to see what it does, a
native stub cannot be unpacked by letting it unpack itself, and a value the
machine cannot establish stops the run instead of being guessed.

## Where CILantro loses

Worth knowing before you pick it up, and none of it is going to be fixed by
trying harder — each item is the same design constraint seen from a different
side.

- **Anything but Reactor 6 and ConfuserEx 1.0.0.** A 7.x sample, or a ConfuserEx
  fork whose structure has moved, is reported as unsupported and nothing is
  written. de4dotEx covers considerably more families than either.
- **ConfuserEx's strong proxies, resources and payloads, where the others handle
  them.** The ConfuserEx support here gets the bodies, the strings, the mild
  reference proxies and about nineteen dispatcher edges in twenty back, and stops
  there. de4dotEx has had years on that protector and its forks; if what you want
  is everything a ConfuserEx sample was hiding rather than its literals and most of
  its shape, start there.
- **Native-packed files.** The .NET part is inside a native stub, and the way
  the other tools get it out is by unpacking that stub. This one detects the
  case and stops. Slayer and de4dotEx unpack it.
- **String codecs nobody has modeled.** Slayer calls the sample's own decrypter,
  so a codec variant it has never seen still comes out. This tool has to
  interpret the codec, and where it cannot, the strings stay encrypted and the
  report says which sites.
- **Names.** Slayer and de4dotEx rename the whole de4dot surface, public types
  included. This tool renames only non-public members whose names it can prove
  are generated, so the result is less uniformly readable.
- **Speed.** A second or two on a normal sample, and up to a minute on a
  virtualized one — as on the sample measured
  [above](#all-four-on-one-hard-sample) — against two or three seconds for the
  others. Interpreting the loader is the price of not running it, and it is still
  a factor of ten or more.
- **A binary you can execute.** Krypton's output is meant to run; this tool's
  cleaned copy is meant to be read, and the virtualized methods built back into
  it are labelled as readings rather than offered as working code.

## Stage by stage against NETReactorSlayer

This matrix maps CILantro's passes onto the fifteen stages Slayer ships
under `NETReactorSlayer.Core/Stages/`. It records what is implemented, where
CILantro is stronger or weaker, and what remains a deliberate, fail-closed
boundary. Every mutating pass rolls back unless structural verification passes.

Slayer is GPL-3.0 throughout and bundles a de4dot-derived renamer
(`NETReactorSlayer.De4dot.Renamer`). CILantro re-derives every equivalent
capability from its own CFG, use-site dataflow, and naming primitives rather
than porting any of it.

| # | Slayer stage | CILantro pass | Status |
|---|--------------|--------------------|--------|
| 1 | `MethodDecrypter` | `method-body-recovery` | Parity. Static JIT-hook body recovery with write-log identity checks and per-body verification. |
| 2 | `AntiManipulationPatcher` | `antitamper-neutralization` | Parity. Removes only the proven integrity/verification subtree and guarded failure paths, using the static machine's RSA and hashing models. |
| 3 | `StrongNamePatcher` | `antitamper-neutralization` | Parity. The strong-name verdict is proven through the same modeled verification before any edit. |
| 4 | `BooleanDecrypter` | `boolean-recovery` | Parity by construction. Detects the `bool(int32)` resolver, proves each offset, and interprets the real resolver to fold sites. No corpus sample exercises it yet. |
| 5 | `StringDecrypter` | `string-table-recovery` + `string-recovery` | Stronger on proof, weaker on reach. Table capture and site rewriting are separate, all-or-nothing, and offset-proven; Slayer invokes the real decrypter and so handles unmodeled codecs. |
| 5a | no equivalent | `string-lookup-recovery` | Beyond Slayer, and aimed at the layer underneath Reactor rather than at Reactor. A sample protected twice may keep its strings where no run of bytes describes them — a dictionary parked in a slot of the application domain is the case in hand — so this reading stops looking for a table and asks the method that fetches the strings for each number reaching it, taking the answer only where the machine holds it concretely. Restricted to methods the assembly does not show the outside world, all-or-nothing per lookup, and run after Reactor's own strings are back, so the inner layer is ordinary code by the time it is asked. Recovers 155 of one payload's 172 strings, which the table readings alone report as 17 of 17. |
| 5b | no equivalent | `constant-strings` | Beyond Slayer. Alongside the table, the samples carry a decoder per string — a scrambled literal taken apart, altered, and rebuilt — which no table indexes and which the table recovery therefore never sees. Each such method is interpreted twice on separately built machines taking the candidates in opposite orders, and the call is replaced by the string only where both runs complete, agree, and leave nothing behind. Calls made through a delegate field written once over a null target are read as calls to the method bound there. |
| 6 | `TokenDeobfuscator` | `token-recovery` | Parity by construction. Rewrites constant-fed `Module.Resolve*` proxies and Reactor's own `int`-to-handle forwarders to direct `ldtoken`, validating every decoded token first and proving the forwarder's cached module handle is this module's by interpretation. Sixteen to seventeen sites per JIT-hook sample. |
| 7 | `ProxyCallFixer` | `delegate-proxy-analysis` | Stronger. Bijective field-to-target validation; the stream codec is derived structurally rather than by hash. |
| 8 | `TypeRestorer` | `type-restoration` | Weaker/conservative, clean-room. Promotes non-public `object` fields only when every writer agrees; no public-API signature changes. |
| 9 | `MethodInliner` | `method-inlining` | Parity. Redirects proven single-call pass-through forwarders, collapsing chains to their end, with stack-neutrality proof and full-body rollback. Covers Reactor's object-laundering wrappers over framework calls, whose declared types are allowed to differ from the target's only by a widening to `object`. Four hundred to six hundred sites per JIT-hook sample. |
| 10 | `AssemblyResolver` (payload dumping) | `payload-extraction` | Stronger on reach, equal on framing. The general route interprets whatever unpacker the module carries and takes the bytes as they reach `Assembly.Load`, so a crypter's cipher, container, and stage count need not be known and need not be Reactor's; a driver written as a constructed object is entered as readily as a static one. The sink is never invoked, and a recovered buffer is believed only after it parses as managed metadata twice over. A crypter whose setup is itself virtualized is reached by running its virtual machine as the IL it is, at the cost of a much longer interpretation. |
| 11 | `ResourceResolver` (reattach) | `resource-restoration` + `resource-hook-elision` | Parity. Interprets the module's own bundle reader under the bounded machine, reads the decrypted satellite assembly's streams back onto the module, and drops the resolve subscription those streams made unreachable. |
| 12 | `CosturaDumper` | `costura-extraction` | Parity. Extracts `costura.*.dll(.compressed)` assemblies into the payload writer. |
| 13 | `ControlFlowDeobfuscator` | `dispatcher-deobfuscation` + `control-flow-completion` | Clean-room. Proves dispatcher edges, folds constant branches, and deletes all unreachable code with EH regions preserved and per-method verification. |
| 14 | `Cleaner` | `runtime-cleanup` (on by default; `--keep-runtime` disables) | Weaker. Slayer also strips attributes and unused resources and fixes the entry point and metadata header. We delete any type or method that is unreachable, invisible outside the assembly, unexposed to reflection, unreferenced by survivors, and attributable to the protector, plus attributed type initializers whose bodies cannot do anything, for which reachability is beside the point. |
| 15 | `SymbolRenamer` | `symbol-renaming` (on by default; `--keep-names` and `--strict` disable) | Much weaker. Slayer renames the full de4dot surface including public types and restores properties and events. We rename only non-public, non-virtual, structurally proven names to synthetic identifiers. |
| — | no equivalent | `loader-call-elision` | Beyond Slayer. Cuts the loader calls Reactor injects at the head of type initializers throughout the assembly, once the bounded interpretation accounts for everything a call does and nothing that survives can read what it wrote. Slayer removes the runtime by recognizing it; this reaches the same code by proving the calls inert, and is what leaves the runtime unreachable for cleanup. The initializers left empty by the cut are handed to cleanup by the same pass, on the grounds that it is what emptied them. |
| — | anti-debug (folded into `AntiManipulationPatcher`) | `antitamper-neutralization` | Partial. Debugger-probe sites are neutralized only where the value provably feeds a Reactor termination path. |
| — | `Helper/NativeUnpacker` + `QuickLZ` | `metadata-preflight` (`NativePackDetector`) | Deferred. Native-packed input is detected and reported unsupported with a specific diagnostic rather than mis-processed. Slayer unpacks it. |
| — | `Helper/CodeVirtualizationUtils` | `reactor-detection`, `virtualization-disassembly`, `virtualization-rebuild` | Beyond Slayer. Slayer detects virtualization by looking for a known runtime; detection here is by the shape of the seam every virtualizer has to leave — pack the arguments, pass a program number, call once, return — which holds for engines neither tool has seen, and it names the affected methods rather than only reporting a flag. The engine's own decoder is then run under the machine and the decoded program read back off the heap, so nothing about the bytecode's framing or encryption has to be known, and what each operation means is derived per sample rather than from a table no per-build numbering would survive. The result is written as an annotated listing and as the IL it stands for, and built back into the cleaned copy with an attribute on each method saying it is a reading. See [devirtualization.md](devirtualization.md) for how the readings are arrived at and checked. |

## Where CILantro is intentionally different

- **Fail-closed everywhere.** Any pass that cannot prove its transform preserves
  behavior makes no edit. Partial or unsupported recovery blocks emit by default.
- **Static only.** There is no dynamic execution, so a protection that only
  yields to running it — a native stub, most obviously — is a boundary rather
  than a feature, and a virtualized method is read and rebuilt from that reading
  rather than recovered.
- **Identity is policy-aware, not bypassed.** Cleanup and renaming declare the
  exact removals, additions, and renames they perform; the verification gate still
  fails on anything undeclared.
- **Deletion needs provenance, not just deadness.** Slayer removes what it
  recognizes as Reactor's. We remove what recovery can account for: the pass that
  replaced a resolver call, redirected a call past a forwarder, or elided an inert
  loader call records what it left without a use, and only those declarations are
  candidates. A program's own unused internal class stays, which costs some
  parity against a tool that tree-shakes, and keeps the output an unobfuscated
  version of the input rather than a smaller program.

## The evidence behind the claims

The rest of this page is the working underneath the table: which capabilities
are proved on real samples rather than only unit tested, how close the output
gets to a known-good copy of the same program, and what has to hold before
anything is written at all. It is here so that "parity" is a measurement rather
than an assertion.

### Corpus coverage gaps

The corpus proves method-body recovery, proxy fixing, string recovery,
anti-tamper neutralization, control-flow completion, encrypted-resource
restoration, and payload extraction on real samples. Boolean protection, token
proxies, Costura packaging, and native packing are implemented and unit tested
but not yet represented by a real corpus sample. Payload recovery by
interpretation is proved on both payload-carrying samples, each of which hides
its unpacker behind a virtualized initializer that the machine runs rather than
lifts; the recovered stages are pinned by hash. The manifest schema and runner
already carry the gates (`minimumBooleansRecovered`, `minimumTokensRestored`,
`minimumResourcesRestored`, `maximumRemainingSwitchDispatchers`,
`minimumRedirectedDispatcherEdges`, `maximumUnreachableInstructions`,
`expectUnsupportedReason`) so those samples can be added without code changes.

"Parity by construction" on a stage no corpus sample exercises is weaker than
it sounds, and `resource-restoration` was the cautionary case. It was present,
unit tested, and recovered nothing on any of the three real samples carrying an
encrypted bundle, because it looked for a zero-argument `byte[]` decryptor
naming the bundle and Reactor has never emitted one: the plaintext is a
by-product of a resolver installer that returns nothing. Keying on the anchor
every version does share — a static method that names the bundle and reads it as
a manifest resource — and then taking the plaintext out of machine state rather
than off the stack recovers all three.

Two things Slayer's `Cleaner` and `SymbolRenamer` do have no corpus evidence
behind them and are therefore not implemented. Reactor 6 strips neither
properties nor events from these samples (the protected and oracle assemblies
carry identical `Property` and `Event` rows, with no orphaned accessor in
either), and it leaves the metadata header, runtime version, and custom
attributes byte-identical to the oracle's. Restoring what was never removed
would be untestable code. The oracle gate now counts properties and events as
preserved-name members in their own right, so a sample that does lose them
fails rather than passing quietly.

### Current corpus standing

Last full run: 9 passed, 0 failed, 0 missing, against 189 passing unit tests.

The three JIT-hook samples restore every protected body (199, 312, and 253),
fold their constant predicates, complete control flow, inline forwarders,
restore every string site, decrypt and reattach every resource stream their
bundle held, cut the loader calls Reactor injected into their type initializers,
and emit verified output that clears the structural oracle gate with every
preserved name intact.

What remains is surplus rather than failure, and it is measured per sample as a
ratchet in the manifest:

| Sample | Types emitted / oracle | Surplus in named types | Whole-module surplus | Unattributed dead methods |
| --- | --- | --- | --- | --- |
| `database` | 40 / 49 | 8 | -118 | 66 |
| `reason-pac` | 41 / 50 | 16 | -100 | 72 |
| `service-controller` | 37 / 44 | 4 | -110 | 61 |

The three clean oracle assemblies are the control: elision changes nothing in
any of them and cleanup removes nothing, which is the evidence that neither is
quietly tree-shaking the program.

Two surplus columns replace the one there used to be, because the single figure
stopped meaning what it says. De4dot renames Reactor's runtime type rather than
removing it, so the oracle for `database` carries a hundred and forty-four
methods of protector inside `Class1`; an output that deletes them scores a
negative whole-module surplus, and the same number would have appeared had the
output deleted program instead. The left column compares only types both sides
name — the ones Reactor never obfuscated — which separates the two: a surplus
there is Reactor's per-type helpers that cleanup cannot yet attribute, and a
deficit is program that went missing. The gate now fails on any deficit at all,
and all three samples have none.

`service-controller` used to be the outlier at a hundred and seventy-three, and
the reason was a single call. Its `ServiceUtils.GetServiceProcessID` loaded a type
handle through one of Reactor's token forwarders, which kept the resolver type
reachable and the shared cipher alive behind it; recovering that call closed a
hundred and forty methods in one step.

The surplus inside named types then fell from fifty-nine, seventy-nine, and
forty-four to five, twenty-eight, and fourteen, and that came from object
laundering. Reactor wraps ordinary framework calls in helpers that declare
everything they can as `System.Object` — `object f(object)` over
`FileVersionInfo.get_FileVersion` — and forwarder redirection was declining them
on two counts: the target sits outside the assembly, so it does not resolve to a
`MethodDef`, and the declared types do not match. Neither is a reason to decline,
because the body converts nothing: the values reach the target as the caller
pushed them either way. Admitting both took redirection from ninety-two sites to
six hundred and sixty on `service-controller`, and undoing the disguise leaves
the surviving code more strongly typed than it was, since a local already
declared `FileVersionInfo` now feeds a call that says so.

Removing the type initializers elision had hollowed out took the three the rest
of the way to eight, sixteen, and four. Reactor puts its loader call at the head
of every type's initializer, writing an initializer to hold it on types that had
none, so cutting the calls left twenty-two to thirty-five bodies per sample that
run and return. Those are removed on the strength of the body rather than of
reachability, which for an initializer answers the wrong question: nothing has
to call it, because the runtime starts it when the type is first used. What can
be said is that running it achieves nothing, and that holds whenever the runtime
chooses to. Emptiness also draws the line in the right place on its own, since a
type whose own initializer Reactor merely prepended to still has the program's
code in the body and so is never a candidate.

What is left is Reactor's per-type scaffolding: every type carries a static field
of its own type, a null-check predicate over it, and a getter. These are dead in
the input as well as the output — Reactor emits them and never calls them — so no
pass made them dead and nothing recovery did accounts for them. Attributing them
would need evidence of a different kind than the rule currently admits.

The oracle gate itself compares structure — type and method counts, the
preserved-name subset, per-type method counts inside named types, resource
names, and entry-point kind — because the oracle's own type names are `Class0`,
`Class1`, and `Class3/Delegate9`: it was produced by a de4dot-style renamer, not
built from original source. Requiring exact name equality would mean reproducing
another tool's arbitrary `ClassN` numbering, which is not a correctness property.
Names Reactor preserved, such as `Reason.rsServiceController.ServiceUtils`, do
appear verbatim in both, and those are what the preserved-name subset checks.

Resources are compared by name and not only by count, under
`requireOracleResourceParity`. Counting alone could not tell apart a module that
kept the application's resources alongside the protector's bundle from one that
lost them, and it was in fact reporting a *smaller* surplus for the second case:
before restoration the three samples each carried three Reactor resources and
were missing two of the oracle's, for a surplus of one. They now carry all three
of the oracle's resources plus the three Reactor ones, which reads as a surplus
of three and is strictly better.

### Emission policy

Emission is gated on the emitted module being trustworthy, so only passes that
can affect the module withhold output. `payload-extraction`,
`costura-extraction`, and `resource-restoration` recover side artifacts, so they
report `Unsupported` without blocking an otherwise verified assembly; when
restoration succeeds it does reattach, and that addition is declared to the
identity gate like any other mutation. `--fail-on-partial` restores the strict
policy in which any incomplete pass, artifacts included, withholds output.

Two separate questions are asked before output is kept. The module in memory is
compared against the input, and may differ only by what the passes declared. The
file is then compared against that module, by member name rather than by
metadata token: deleting a row forces the writer to renumber everything after it,
so tokens legitimately differ between memory and file while names do not. Token
preservation is requested whenever nothing was deleted, and dropped exactly when
it has become unachievable.

## Clean room

None of the three GPL projects above contributed source, binaries, or generated
output to this one, and none of them is called at runtime. Every equivalent
capability was re-derived from the samples and from independently authored
tests. The full statement is in
[compatibility.md](compatibility.md#clean-room-boundary).
