# Protector coverage

CILantro turns protected .NET assemblies into code and data you can investigate in a decompiler. Use this guide to check whether it handles the layers in your sample and whether you need to supply companion files.

## Supported protectors

| Protector | Recovery coverage |
| --- | --- |
| **.NET Reactor** | Encrypted methods/NecroBit, strings and numeric constants, virtualized methods, control flow, reference proxies, native bootstraps and embedded managed stages. Tested on captured Reactor 6 samples and source-built Reactor 7.5 probes. |
| **ConfuserEx and ConfuserEx 2** | Official 1.0.0 and mkaring 1.6.0 source-built probes: normal/dynamic/x86 constants and resources, control flow, mild and strong proxies, normal and JIT anti-tamper, and safe/Win32/Antinet startup checks. Combined strong-proxy, dynamic/JIT and x86/normal-tamper profiles have executable parity. Proven x86 expression stubs are translated to CIL for IL-only output. Compressor payloads are extracted byte-exactly and emitted as standalone executables with restored entry points. |
| **Babel .NET** | XOR/hash strings, numeric values and arrays, delegate proxies, encrypted methods, resources, embedded dependencies, control flow and debugging/integrity checks. Coverage includes legacy captures and Babel 12.1. |
| **Dotfuscator** | Managed v1 and native-key v2 strings, encrypted resources and culture satellites, control flow, debugging/integrity checks and Android Root Check removal. Coverage centers on 7.9, with older managed string forms also recognized. |

The official ConfuserEx probes target .NET Framework 4.8; Reactor, Babel and Dotfuscator probes cover .NET Framework 4.8, .NET 8 and .NET 10. ConfuserEx validation includes 51 protected captures across isolated, combined and packed profiles, with cleaned executable comparisons on three inputs. Release builds target Windows x64, Linux x64/ARM64 and macOS Apple Silicon/Intel. Product labels alone do not identify every implementation; the report records the recovery result for your file.

### Babel .NET coverage

Method recovery covers instance methods, generic owners, inheritance, byref arguments and exception handlers. AES, managed AES, DES, TripleDES, Rijndael, RC2 and XOR are tested across all three frameworks. Password-protected methods recover when their password callback can be resolved; the tool does not guess passwords.

For separately deployed method data, pass each file with `--babel-code-source FILE`. Analysis reads snapshots of those files, and recovered methods run without them. Embedded dependencies are written as ordinary DLLs beside the cleaned host; keep that deployment together.

**Stream string encryption is outside the current coverage target** because the supplied trial does not license it.

### Dotfuscator coverage

For native-key v2 strings, keep the original `environment????????.bin` and `runtimes/<platform>/native/Runtime.Extensions.*` files beside the input in their original layout. CILantro authenticates them and recovers strings without executing the native library. Missing, changed or unknown companions prevent complete recovery.

Reviewed companions cover Windows x86/x64, Linux x64/ARM64 and macOS x64/ARM64. Windows and Linux runtime comparisons pass; Linux ARM64 validation uses emulation. macOS companions have static validation only. Android check removal is tested with desktop clean-verdict comparisons, without running the original checks on Android devices.

**Shelf Life is outside the current coverage target** because its separate activation key is unavailable. No separate Dotfuscator method-encryption support is claimed.

## Working with a sample

- Start from the untouched protected file. Previous rewriting can remove metadata or encrypted data needed for recovery.
- Follow **OUTPUT** to the recommended assembly; embedded payloads have their own reports and cleaned files.
- Read **NEEDS REVIEW** and **REMAINING** for unresolved methods, strings or stages. A valid output can still need further analysis.
- Keep recovered dependencies and culture directories beside the cleaned assembly.
- Use `--signing-key key.snk` when you need to re-sign cleaned assemblies with a matching private key. Enhanced strong-name signing and satellite re-signing are not implemented.

Unknown/custom decoders, missing runtime state and damaged inputs can remain unresolved. Replacement names improve navigation but do not restore discarded original identifiers. Native wrapper extraction does not provide general native-code decompilation or NativeAOT recovery. Arbitrary serialized resource objects are not deserialized.

Recovery does not execute the sample. Cleaned malware remains an analysis artifact: structural verification checks the rewritten assembly, not safety or equivalent behavior on every possible input. `--strict` disables implicit host assumptions and also retains names and VM stubs; see [CLI options](quick-start.md) before using it as a comparison run.

For examples, see the [malware walkthrough](protection-removal.md). Detailed implementation boundaries live in the [protector reference](assets/protector-implementation-reference.md); [validation results](status-report.md), the [trial-target audit](babel-dotfuscator-targets.md) and [corpus guide](corpus.md) record the evidence.
