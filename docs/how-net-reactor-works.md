# Understanding Reactor protection

Reactor combines configurable layers. A sample can use only strings and control-flow obfuscation, or combine encrypted bodies, resources, native wrapping, and a custom virtual machine. The product name alone does not tell you which recovery steps are needed.

| Layer | What an analyst sees | CILantro's approach |
| --- | --- | --- |
| Encrypted method bodies / NecroBit | Stubs instead of useful IL | Interpret the supported loader and restore the bodies it writes |
| Protected strings and constants | Decoder calls instead of readable values | Interpret supported decoders and replace established values |
| Control-flow flattening | Dispatch loops and large switches | Resolve known state transitions and simplify verified paths |
| Proxies and hidden metadata references | Indirect calls and token lookups | Resolve supported targets into explicit references |
| Encrypted resources | Opaque embedded data | Restore supported containers and inspect recoverable assemblies |
| Anti-tamper and loader setup | Startup routines that depend on the protected file | Neutralize supported obsolete protection effects while preserving required initialization |
| Virtualization | A stub calls a custom interpreter | Decode, analyze, and reconstruct supported VM programs |
| Native bootstrap | The input does not initially look like a managed assembly | Extract the supported wrapper's managed stage and continue recovery |

## What removal means to an analyst

Unpacking the outer file, decrypting method bodies and removing a VM are different steps. A native wrapper can reveal a still-protected managed dropper, which can contain another protected payload. Inspect the recovered chain rather than stopping at the first valid PE file.

For supported virtualized inputs, useful recovery means application methods are readable as CIL and the original interpreter machinery is physically absent when retirement checks pass. Removing every switch is not the goal: application switches and compiler-generated state machines must survive. Required initialization calls and actual payload resources can also remain without being protector machinery.

Recovered methods and strings can expose another obfuscation layer or another protected assembly. Recursive recovery follows embedded managed stages; it is bounded and does not retrieve downloaded payloads.

Reactor version labels are not used as proof of support. Some Reactor 6 and 7.5 structures overlap, so detection identifies the family without inventing a precise version. See [compatibility](compatibility.md) for tested scope and [devirtualization](devirtualization.md) for reconstruction limits.

[Historical Reactor research](history/pre-0.10/how-net-reactor-works.md) contains earlier sample-specific observations.
