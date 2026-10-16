# Protection-removal capture notes

This appendix records sample identities, method mappings, capture conventions, and reproduction instructions for the [analyst walkthrough](../protection-removal.md).

## Original captures

| Capture ID | Malware fixture | Behavior exposed |
| --- | --- | --- |
| `reactor-loader` | `Qbjuef.exe` | Decrypts embedded content, loads a managed stage in memory, finds a named type and invokes its method |
| `reactor-necrobit` | `Qafcakg.payload.Ptnifif.dll` | Encrypted method bodies conceal PowerShell process creation and another in-memory assembly loader |
| `confuser-tasking` | `confuser_06b9d08b33f2.dll` | Sends HTTP POST requests, decodes responses and sends received script content to PowerShell |
| Native extraction | `WindowsManagement.exe` | Native wrapper conceals a managed stage |

These are corpus filenames, not malware-family attributions. Identity is established by SHA-256:

```text
Qbjuef.exe
c8fab65dedd9c62a35cfab7e318225c42cc838d57fe0a1f072b195a1a779523b
Qafcakg.payload.Ptnifif.dll
e4e746f968a3ec89027484ab233d3d38c7778458a898d30f31bb74a2c97059d2
confuser_06b9d08b33f2.dll
06b9d08b33f2e22bfea6196867d35bb3cef7f11eb745d43017c7cb75183a8e3f
WindowsManagement.exe
094dbed0af6664af52375a711e0b8e4e8e7e66c6d47390e8263b16efba4d1995
```

**Before/after** labels name their checkpoint. Decrypting a method must precede inspecting its strings or control flow, so a pass-entry snippet can already contain earlier recovery. **Final C#** means ILSpy decompilation of a written output. **Recovered CIL** means an in-memory pass snapshot. `...` marks omitted instructions; display aliases are declared explicitly. Tokens refer to the input/in-memory method identity and can change on emission.

The [evidence JSON](protection-removal-evidence.json) contains selected complete snapshots, method identities, pass diagnostics, output hashes, extraction records and the VM-removal audit. All three managed runs passed structural verification. This checks metadata and CIL, not execution equivalence or successful task delivery.

Windows blocked subsequent opening of the extracted `Zebekeadu.dll` and cleaned Qafcakg payload as malware. For those files, the guide uses extraction records and CIL captured during recovery, rather than claiming a subsequent decompiler inspection or downstream payload behavior.

## Final C# follow-up

On 2026-10-16, the Qafcakg payload was recovered again with the published CILantro 1.0.1 Windows executable, with recursion disabled and output under `C:\cilantro-verify\walkthrough-1.0.1`. ILSpy 11.0.0.9375 successfully decompiled the written assembly there. This supplies the final C# for the PowerShell launcher that could not be reopened during the original capture. The original capture records above retain their original inspection limitation; it does not apply to this follow-up.

The [follow-up evidence](protection-removal-final-csharp.json) records the source and output hashes, rename mapping, verification result, and exact decompiled launcher. The main page omits its initialization calls with `...`; it does not present a rewritten equivalent as decompiler output.

## Method map

| Walkthrough example | Capture | Input method token | Final identifier |
| --- | --- | --- | --- |
| Hidden PowerShell | `reactor-necrobit` | `0600009F` | `generatedMethod_0068(string P_0)` in the 1.0.1 follow-up |
| In-memory loading and entry point | `reactor-loader` | `0600001A` | See original rename map and final C# excerpt |
| Payload decryption | `reactor-loader` | `06000018` | See original rename map and final C# excerpt |
| Additional in-memory load | `reactor-necrobit` | `0600008F` | `generatedMethod_0057(byte[] P_0)` in the 1.0.1 follow-up |
| HTTP transport | `confuser-tasking` | `0600006B` | `generatedMethod_0171` |
| Command response and PowerShell | `confuser-tasking` | `0600006C` | Public obfuscated tasking method; original signature in evidence |
| VM string-resolution dependency | `reactor-loader` | `0600004A` | Reconstructed, then removed as replaced protection code |

## Virtualization evidence

```cil
IL_0026: ldc.i4 0
IL_002B: ldloc.0
IL_002C: ldnull
IL_002D: call System.Object[] JQhawTywsS1NVjM0U2D.H7iSNmyMGuPXNmAEDJn::RxryXcNYIa(System.Int32,System.Object,System.Object)
IL_0032: pop
IL_0033: ret
```

The original stub has 18 instructions; the reconstructed body has 5,480 inferred CIL instructions. This is a protector string-resolution dependency, not a recovered malicious application algorithm. The reconstructed dependency and lifted pool initializer are removed after their work is replaced.

```text
Original VM engines identified:             1
VM engine/nested declarations retained:     0
VM bytecode resource removed:
  yK5UxXIr2I53OoU4rx.cQo0ikDMfplHMV8mSA
Reconstructed protection-code disposition: retired-protector
Physical VM-removal gate:                   passed
```

See [VM validation and limits](../devirtualization.md).

## Extraction hashes

```text
Decoded resource assembly:
bb8fb1ca76cb531bdbedcdafa851b5de6e86042350e7cc5cb121c0fe4f23ca2b
Zebekeadu.dll:
417032e561fe410a246fea4f580b7ae8de4a8cc5098a508931a78322916199dd
```

The native-wrapper extraction yields `stub.exe` (14,724,608 bytes, 6,155 types, CLR v4.0.30319), SHA-256 `83ba5d833eba38f578eb8478f8961a0bddb63ff35016b40d8e0536b164ee1ed3`. This capture demonstrates native extraction, not removal of the managed stage's own protection.

## Scope of the examples

The managed captures passed structural verification. They are static evidence, not detonation or proof of behavioral equivalence. The ConfuserEx fixture demonstrates section decryption, string recovery, control-flow simplification, renaming and dead-code removal. It does not demonstrate reference-proxy, dedicated-resource or packer removal. Some startup helpers and anti-analysis effects remain; 34 decoded array constants were reported without being rewritten. The original decompilation exposed HTTP and PowerShell logic, not successful command delivery.

## Reproduce the captures

Use the [capture source](protection-removal-capture.cs) from the repository root with the .NET 10 SDK:

```powershell
dotnet new console -f net10.0 -o artifacts/protection-capture
dotnet add artifacts/protection-capture reference src/Cilantro.Core/Cilantro.Core.csproj
Get-Content docs/assets/protection-removal-capture.cs -Raw | Set-Content artifacts/protection-capture/Program.cs
dotnet run -c Release --project artifacts/protection-capture -- C:\cases\Qbjuef.exe artifacts/protection-review/reactor-loader 06000018,06000019,0600001A,0600004A,060003CD
```

The optional third argument selects input method tokens, so useful application methods can be captured instead of the helper's default small-body examples. For `Qafcakg.payload.Ptnifif.dll`, select `0600009F,0600008F`. For the ConfuserEx fixture, select `0600006B,0600006C`. The helper records the default recognized-root pipeline without recursive child recovery and writes `frames.json`, `identity.json`, `run.json`, cleaned output and normal reports. The checked-in JSON retains selected methods; long VM-body captures explicitly mark truncation.

The [native extraction source](protection-removal-native-capture.cs) can replace `Program.cs` in that scratch project; it takes the input path and prints an inventory without writing or executing the managed stage.

For the Qbjuef run, check physical VM retirement separately:

```powershell
dotnet build src/Cilantro.Cli -c Release
pwsh -File corpus/verify-vm-removal.ps1 -RunPath artifacts/protection-review/reactor-loader/run.json -ToolDirectory src/Cilantro.Cli/bin/Release/net10.0
```

Recorded hashes identify the captured outputs. Regeneration can differ with build or metadata emission changes. These examples supplement [corpus validation](../corpus.md), not release-candidate validation.
