# Recognize .NET Reactor protection

Reactor can combine several layers in one file. An analyst may first encounter an encrypted native wrapper, then a managed loader with hidden API calls, then a payload whose methods or strings are still protected. Work through the recovered stages rather than stopping at the first valid assembly.

The [before-and-after walkthrough](protection-removal.md#net-reactor) shows these layers in real malware, including VM reconstruction and a hidden PowerShell launcher.

## Empty-looking methods: encrypted bodies

Method-body encryption, often called NecroBit, hides the implementation and leaves a stub where a decompiler expects instructions. A method may look like a few no-ops followed by a return.

CILantro interprets the supported recovery setup and restores the bodies it recovers. Reopen the cleaned assembly and inspect the method's callers and API use. Strings inside the restored body may need separate decoding before its purpose becomes obvious.

## Decoder calls and unknown helpers: strings and proxies

String encryption replaces values such as executable names, resource names and reflection targets with decoder calls. Reference proxies replace recognizable API calls with helper/delegate calls.

Recovering both can turn an obscure loader into an explicit sequence: `Assembly.Load`, `GetType`, `GetMethod`, then `Invoke`. Follow those targets into the loaded stage.

## Large dispatch loops: control-flow flattening

Flattening replaces ordinary control flow with a state variable and a dispatcher that repeatedly chooses the next block. Opaque predicates add branches whose results are fixed.

Unflattening resolves established transitions and reconnects the code into readable branches. Ordinary application switches and async state machines can still remain. Look at what the remaining switch does before treating it as protection.

## A stub calling an interpreter: code virtualization

A virtualized method's program is stored as bytecode for Reactor's custom VM. Decrypting ordinary method bodies does not translate that instruction set.

CILantro lifts supported operations into CIL and reconstructs supported method bodies so they can be decompiled. Use the [VM guide](devirtualization.md) to locate listings, distinguish reconstructed code from decrypted original CIL, and interpret comparison results.

## Opaque resources or a native outer file: hidden stages

Encrypted resource containers can hold application resources, dependencies or another assembly. A native bootstrap can conceal the entire managed program.

Recovery extracts supported content and records its identity and source. Use the artifact tree to distinguish a resource-only bundle from a loaded stage. Open a cleaned managed child when available; retain its extracted original for comparison.

## What should disappear after recovery?

When the recovered code no longer needs a protector helper, cleanup can remove it and its supporting resources. The malware's own payload decryptor, required startup calls and application data may remain.

Support depends on the implementation and selected protections. Reactor 6 malware and Reactor 7.5 source-built probes are part of the validation evidence; overlapping structures can prevent a precise version label. See [support and limitations](compatibility.md) and [validation results](status-report.md).
