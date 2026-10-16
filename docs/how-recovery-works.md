# How recovery works

CILantro turns protected .NET code into assemblies and extracted files you can inspect in a decompiler. It follows the sample's decoding and unpacking logic in a bounded interpreter, without launching the sample or loading its code into the host CLR.

A useful way to follow a run is to ask what each layer is hiding. An encrypted method hides instructions; a string decoder hides a value; a VM hides a program written in another instruction set. Recovery works through those obstacles and records the result in the case folder.

## 1. Find the code behind the wrapper

A file that looks native may contain the actual .NET program as encrypted data. A managed loader may contain another assembly inside a resource or construct its bytes before loading it in memory.

CILantro extracts supported stages and records their hashes and parent-child relationships. Open the artifact tree in the HTML report to follow the chain. A restored resource container and an assembly captured at `Assembly.Load` have different roles; the latter is often the more useful next stage.

**For example:** the Qbjuef loader yields a decoded resource assembly and a separate `Zebekeadu.dll` loaded in memory. The [walkthrough](protection-removal.md) shows the call chain and recovered files.

## 2. Restore encrypted instructions and values

Method encryption can leave a decompiler showing only a few `nop` instructions and a `ret`. Recovery interprets the supported decoding setup and restores the hidden method bodies.

Strings and numeric constants need separate recovery. A method can become visible while its executable names, URLs or reflection targets still appear as decoder calls. Resolving those calls puts established values back into the code.

**For example:** an empty-looking method in the Qafcakg payload becomes a hidden PowerShell launcher. Recovering the string `powershell.exe` then makes the process-creation code immediately recognizable.

Some calls remain beside recovered constants because they also trigger initialization. Follow the literal's use and the surrounding code when assessing the behavior.

## 3. Expose the calls and branches

Reference proxies hide familiar API calls behind helper methods or delegate fields. Resolving them makes calls such as `Assembly.Load(byte[])` explicit.

Control-flow flattening replaces ordinary branches with a loop that selects blocks through a dispatcher. Unflattening reconnects the blocks so the decompiler can show the underlying decisions. Opaque predicates add branches whose outcome is fixed; simplifying established outcomes removes those distractions.

**For example:** the ConfuserEx command handler in the walkthrough goes from arithmetic dispatch and four switches to readable checks for response bytes `202` and `244`.

Application switches, exception handlers and compiler-generated state machines can still be legitimate. Judge the recovered behavior rather than treating every remaining switch as protection.

## 4. Translate VM programs back into .NET code

Virtualization replaces a method with bytecode for a custom interpreter. Decrypting ordinary CIL does not reveal that program.

CILantro reads supported VM operations, lifts them into CIL-level operations and reconstructs supported bodies in an assembly. The resulting code can be decompiled and investigated. VM listings remain available for tracing a reconstructed operation back to its source.

The [VM guide](devirtualization.md) explains the files and comparison results. The [Qbjuef example](protection-removal.md#net-reactor) shows a real VM-call stub becoming a decoding routine that ILSpy can read.

## 5. Remove obsolete protection code and improve navigation

Once strings, methods and references have been recovered, some support machinery is no longer needed. Cleanup removes attributable protector code and resources when the remaining references permit it. This can include a replaced string decoder and its VM engine.

The malware's own cryptography, payload resources and required initialization may remain. A TripleDES payload decryptor is useful application logic even when the protector also uses cryptography.

Type recovery and replacement names make surviving code easier to navigate. `generatedMethod_...` is a navigation label; the rename map connects it to the original identifier.

## 6. Write the analysis copy and explain the result

The output includes cleaned assemblies, extracted originals, an offline HTML report, change and rename maps, and any VM listings. Supported extracted managed stages receive their own recovery runs within the traversal limits.

Structural checks examine the written assembly's metadata and CIL. Reconstruction comparisons add observations about the VM paths and state they exercised. Read the result for the artifact you intend to use, especially when the recommended file is a child stage.

For routine work, start with **OUTPUT**, open the recommended assembly, and read **NEEDS REVIEW** and **REMAINING**. Use [reading the output](reading-the-output.md) to decide what a warning means for the case.

## When recovery stops short

A missing dependency, unknown environment value, unsupported operation or exhausted budget can block a path. The report records the stop and, where possible, a remedy. Supply the specific missing input and retry in a fresh folder; [troubleshooting](troubleshooting.md) gives practical next steps.

A readable file and passed structural checks do not establish behavior on every input. Keep the original, the report and the recovery qualifications together. [Support and limitations](compatibility.md) describes the coverage boundary.

## For contributors

The [implementation reference](assets/recovery-implementation-reference.md) records the detailed rules for constant recovery, control-flow changes, initialization effects, protector cleanup and verification. Use [code organization](code-organization.md) to locate the source and [corpus validation](corpus.md) to select checks for a change.
