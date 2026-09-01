using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>
/// One method body NecroBit decrypted eagerly into its JIT-hook lookup table, as the loader
/// interpretation captured it: the loader's own integer identity for the method, and the plaintext
/// IL stream it would have handed the JIT when that method was first compiled.
/// </summary>
public sealed record NecroBitBody(long Key, byte[] Il, bool NativeMode);

/// <summary>
/// Recovers NecroBit-protected method bodies without running the loader to completion, by reading
/// the decrypt table the loader fills before it installs its JIT hook.
/// </summary>
/// <remarks>
/// Reactor 6 writes decrypted bodies back into the mapped image and is recovered by replaying those
/// writes. NecroBit never writes them: its module initializer decrypts every protected body up front
/// into a managed <see cref="System.Collections.Hashtable"/>, keyed by the address the runtime will
/// later ask for, and its <c>compileMethod</c> hook only copies the already-decrypted bytes out of
/// that table. The loader interpretation stops when it turns to installing the native hook — reading
/// live process memory it cannot model — but by then the table is already full, so the plaintext is
/// sitting in the interpreter heap. This reads it out, maps each entry back to the method it belongs
/// to by the loader's own key, and grafts it.
///
/// On CoreCLR the table is the same up-front <see cref="System.Collections.Hashtable"/>, but each
/// record names its plaintext by a length and a native pointer into a single page the loader decrypts
/// into rather than carrying a managed <c>byte[]</c>, and the loader finds the module base by
/// reflecting runtime-internal fields rather than from metadata. Modelling that reflection surface and
/// the native decrypt page lets the loader run to the end and this reads each body back out of the page
/// its record points at; the mapping and grafting are otherwise identical.
/// </remarks>
public static class NecroBitBodyRecovery
{
    // NecroBit prepends every decrypted body with a two-byte `br.s +5` over the five-byte `call` to
    // its per-body tamper marker, so the real IL begins seven bytes in and the stream opens 2B 05 28.
    private const int MarkerLength = 7;

    /// <summary>
    /// Reads every decrypted body out of the loader's JIT-hook table in the interpreter heap.
    /// </summary>
    public static IReadOnlyList<NecroBitBody> Harvest(ModuleDefMD module, StaticMachineState state)
    {
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(state);
        var heap = state.Heap;
        var found = new Dictionary<long, (byte[], bool)>();
        // The table's static field is named differently in every build, so it is found by shape: a
        // Hashtable whose entries are keyed by the method's IL address and hold a struct carrying the
        // decrypted body. Any other Hashtable the loader keeps simply contributes no such entries.
        foreach (var field in state.StaticFields.Values)
        {
            if (!heap.TryGetModelValue(
                    field,
                    "Entries",
                    out Dictionary<StaticValue, StaticValue>? entries) ||
                entries is null)
            {
                continue;
            }
            foreach (var entry in entries)
            {
                if (entry.Key.Kind != StaticValueKind.Int64 ||
                    !TryReadBodyBytes(module, heap, entry.Value, out var il, out var nativeMode))
                {
                    continue;
                }
                found.TryAdd(entry.Key.AsInt64(), (il, nativeMode));
            }
        }
        return found
            .OrderBy(pair => pair.Key)
            .Select(pair => new NecroBitBody(pair.Key, pair.Value.Item1, pair.Value.Item2))
            .ToArray();
    }

    /// <summary>
    /// Whether two harvests captured the same table, which the two-run gate requires before any body
    /// is grafted.
    /// </summary>
    public static bool CapturesAgree(
        IReadOnlyList<NecroBitBody> left,
        IReadOnlyList<NecroBitBody> right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.Count == right.Count &&
            left.Zip(right).All(pair =>
                pair.First.Key == pair.Second.Key &&
                pair.First.NativeMode == pair.Second.NativeMode &&
                pair.First.Il.AsSpan().SequenceEqual(pair.Second.Il));
    }

    /// <summary>
    /// Maps each captured body to the method it belongs to, rebuilds it, and grafts the lot as one
    /// transaction that verifies or rolls back whole.
    /// </summary>
    /// <remarks>
    /// NecroBit zeroes each protected method's <c>LocalVarSigTok</c> and shrinks its header to a stub in
    /// static metadata, then restores the real token at load time with a four-byte write into the mapped
    /// image header — the same image-write channel Reactor 6 uses for whole bodies. The signatures those
    /// tokens name are still in the module's <c>StandAloneSig</c> table, so replaying the writes hands
    /// back the exact locals frame the JIT compiled against. <paramref name="imageWrites"/> carries them;
    /// a method the loader restored a token for is rebuilt against that token rather than the zeroed stub.
    /// </remarks>
    public static bool TryApply(
        ArtifactContext context,
        IReadOnlyList<ProtectedMethodStub> stubs,
        IReadOnlyList<NecroBitBody> bodies,
        IReadOnlyList<MappedImageWrite> imageWrites,
        out IReadOnlyList<uint> recovered,
        out IReadOnlyList<string> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(stubs);
        ArgumentNullException.ThrowIfNull(bodies);
        ArgumentNullException.ThrowIfNull(imageWrites);
        recovered = [];
        var notes = new List<string>();

        // The loader restores each protected header field with its own four-byte write, so a write's
        // offset is the image RVA it lands on. Indexing them by offset lets each stub look up the token
        // and flags the loader would have put back before the JIT ever read its header.
        var writeByOffset = new Dictionary<long, uint>();
        foreach (var write in imageWrites)
        {
            if (write.Bytes.Length == 4)
                writeByOffset[write.Offset] = BitConverter.ToUInt32(write.Bytes, 0);
        }

        // The loader keys its table by the method's IL address: module base plus the method's own IL
        // RVA. Every key is therefore its stub's IL RVA offset by one shared base, so the base that
        // lines the keys up with the stubs is the mapping, and its being a single constant across all
        // of them is the proof the mapping is right rather than a coincidence.
        var ilRvaToToken = new Dictionary<long, uint>();
        foreach (var stub in stubs)
        {
            if (context.Module.ResolveToken(stub.Token) is not MethodDef method ||
                method.Body is null)
            {
                continue;
            }
            ilRvaToToken[(long)stub.Rva + method.Body.HeaderSize] = stub.Token;
        }
        if (!TrySolveBase(bodies, ilRvaToToken.Keys, out var baseAddress, out var mappingDiagnostic))
        {
            diagnostics = [mappingDiagnostic!, "No method body was modified."];
            return false;
        }

        var stubByToken = stubs.ToDictionary(stub => stub.Token);
        var built = new Dictionary<MethodDef, CilBody>();
        var refused = new List<string>();
        foreach (var body in bodies)
        {
            if (!ilRvaToToken.TryGetValue(body.Key - baseAddress, out var token) ||
                context.Module.ResolveToken(token) is not MethodDef method ||
                method.Body is null)
            {
                continue;
            }
            // A body NecroBit compiled to native code carries machine code, not IL, in the same table
            // slot; the flag on its record is what says so. Grafting those bytes as IL would be wrong,
            // and the original IL is gone, so such a body is left as its stub.
            if (body.NativeMode)
            {
                refused.Add($"0x{token:X8}: the body is native-compiled and its IL cannot be recovered.");
                continue;
            }
            var frame = ResolveFrame(context.Module, stubByToken[token], method.Body, writeByOffset);
            if (TryBuildBody(context.Module, stubByToken[token], method, body.Il, frame,
                    out var rebuilt, out var buildDiagnostic))
                built[method] = rebuilt;
            else
                refused.Add($"0x{token:X8}: {buildDiagnostic}");
        }
        if (built.Count == 0)
        {
            notes.Add("No captured NecroBit body could be rebuilt into a valid method body.");
            notes.AddRange(refused);
            diagnostics = notes;
            return false;
        }

        var snapshots = built.Keys.ToDictionary(method => method, MethodBodySnapshot.Capture);
        foreach (var pair in built)
            pair.Key.Body = pair.Value;
        var verification = AssemblyVerifier.Verify(
            context.Module,
            context.OriginalIdentity,
            context.OriginalStructure);
        if (!verification.Passed)
        {
            foreach (var snapshot in snapshots)
                snapshot.Value.Restore(snapshot.Key);
            notes.Add(
                "Grafted NecroBit bodies failed verification and were rolled back: " +
                string.Join("; ", verification.Diagnostics.Take(8)));
            diagnostics = notes;
            return false;
        }

        recovered = built.Keys.Select(method => method.MDToken.Raw).ToArray();
        if (refused.Count != 0)
        {
            notes.Add(
                $"{refused.Count} captured body(ies) could not be rebuilt and were left as stubs: " +
                string.Join("; ", refused.Take(8)));
        }
        diagnostics = notes;
        return true;
    }

    /// <summary>
    /// Finds the one base address that maps every captured key onto a distinct stub's IL address.
    /// </summary>
    private static bool TrySolveBase(
        IReadOnlyList<NecroBitBody> bodies,
        IEnumerable<long> ilRvas,
        out long baseAddress,
        out string? diagnostic)
    {
        baseAddress = 0;
        diagnostic = null;
        var rvaSet = ilRvas.ToHashSet();
        if (bodies.Count == 0 || rvaSet.Count == 0)
        {
            diagnostic = "There was nothing to map: no captured bodies or no protected stubs.";
            return false;
        }
        var counts = new Dictionary<long, int>();
        foreach (var body in bodies)
        {
            foreach (var rva in rvaSet)
            {
                var candidate = body.Key - rva;
                counts[candidate] = counts.GetValueOrDefault(candidate) + 1;
            }
        }
        var best = counts.MaxBy(pair => pair.Value);
        baseAddress = best.Key;
        var solved = best.Key;
        // A base that only lines up some of the keys is not the loader's base; it is two unrelated
        // numbers that happened to differ by the same amount once. Requiring every captured body to
        // map is what makes a wrong base fail here rather than graft a body onto the wrong method.
        if (best.Value != bodies.Count)
        {
            diagnostic =
                $"No single base address mapped all {bodies.Count} captured bodies onto protected " +
                $"stubs; the best lined up {best.Value}.";
            return false;
        }
        var mapped = bodies.Select(body => body.Key - solved).ToHashSet();
        if (mapped.Count != bodies.Count)
        {
            diagnostic = "Two captured bodies mapped to the same stub, so the mapping is ambiguous.";
            return false;
        }
        return true;
    }

    /// <summary>
    /// The header fields the JIT reads from metadata that NecroBit stubbed out and restores at load
    /// time: the locals-signature token, whether locals are zeroed, the stack depth, and whether the
    /// real body carried exception clauses.
    /// </summary>
    private readonly record struct RecoveredFrame(
        uint LocalVarSigTok,
        bool InitLocals,
        ushort MaxStack,
        bool HasExceptionSections);

    /// <summary>
    /// Reconstructs a protected method's header frame by preferring the values the loader wrote back
    /// into the mapped image over the zeroed stub the module ships with.
    /// </summary>
    private static RecoveredFrame ResolveFrame(
        ModuleDefMD module,
        ProtectedMethodStub stub,
        CilBody stubBody,
        Dictionary<long, uint> writeByOffset)
    {
        var localTok = stubBody.LocalVarSigTok;
        var initLocals = stubBody.InitLocals;
        var maxStack = stubBody.MaxStack;
        var hasExceptionSections = stubBody.ExceptionHandlers.Count > 0;

        // A fat header keeps its LocalVarSigTok four bytes past maxStack and codeSize, so header+8; the
        // loader restores the real StandAloneSig token there. Only trust one that actually names a sig.
        if (stubBody.HeaderSize >= 12 &&
            writeByOffset.TryGetValue((long)stub.Rva + 8, out var restoredToken) &&
            (restoredToken & 0xFF000000) == 0x11000000 &&
            module.ResolveToken(restoredToken) is StandAloneSig)
        {
            localTok = restoredToken;
        }

        // The header's first four bytes are the flags word and maxStack. When the loader restores a
        // method that carried exception clauses it rewrites that word to set the more-sections flag, so
        // the restored flags are what say whether the real body needs handlers the IL stream lacks.
        if (writeByOffset.TryGetValue((long)stub.Rva, out var restoredFlagsWord) &&
            ((ushort)restoredFlagsWord & 0x3) == 0x3)
        {
            var flags = (ushort)restoredFlagsWord;
            hasExceptionSections = (flags & 0x8) != 0;
            initLocals = (flags & 0x10) != 0;
            maxStack = (ushort)(restoredFlagsWord >> 16);
        }

        return new RecoveredFrame(localTok, initLocals, maxStack, hasExceptionSections);
    }

    /// <summary>
    /// Rebuilds one method body from its plaintext IL, taking the frame the JIT reads from metadata —
    /// the locals signature, whether locals are zeroed, and the stack depth — from the header the loader
    /// restored rather than the zeroed stub the module ships with. A body the loader flagged as carrying
    /// exception clauses has them read back from the section NecroBit left in the image and reattached.
    /// </summary>
    private static bool TryBuildBody(
        ModuleDefMD module,
        ProtectedMethodStub stub,
        MethodDef method,
        byte[] rawIl,
        RecoveredFrame frame,
        out CilBody body,
        out string? diagnostic)
    {
        body = new CilBody();
        diagnostic = null;
        if (rawIl.Length <= MarkerLength ||
            rawIl[0] != 0x2B || rawIl[1] != 0x05 || rawIl[2] != 0x28)
        {
            diagnostic = "the captured body did not carry NecroBit's body marker.";
            return false;
        }
        var code = rawIl[MarkerLength..];
        CilBody parsed;
        try
        {
            parsed = MethodBodyReader.CreateCilBody(
                module,
                code,
                exceptions: null,
                method.Parameters,
                flags: (ushort)(frame.InitLocals ? 0x10 : 0),
                maxStack: (ushort)Math.Max(frame.MaxStack, (ushort)8),
                codeSize: (uint)code.Length,
                localVarSigTok: frame.LocalVarSigTok);
        }
        catch (Exception exception) when (
            exception is OutOfMemoryException or IOException or ArgumentException or
                InvalidOperationException)
        {
            diagnostic = $"the plaintext IL did not parse ({exception.Message}).";
            return false;
        }
        if (parsed.Instructions.Count == 0)
        {
            diagnostic = "the plaintext IL parsed to an empty instruction stream.";
            return false;
        }
        parsed.UpdateInstructionOffsets();

        // NecroBit stubs the header's more-sections flag but leaves the real exception section in the
        // image, at the fixed offset the JIT computes from the stub's own code size. When the loader's
        // flag write says the body carried handlers, read them back and reattach them; a body that
        // needed them but whose section will not parse is refused rather than grafted without them.
        if (frame.HasExceptionSections)
        {
            if (!TryAttachExceptionHandlers(module, stub, parsed, out var ehDiagnostic))
            {
                diagnostic = ehDiagnostic;
                return false;
            }
        }
        else if (parsed.Instructions.Any(instruction =>
                     instruction.OpCode.Code is Code.Endfinally or Code.Endfilter))
        {
            diagnostic = "the body needs exception handlers the decrypt table does not carry.";
            return false;
        }

        if (parsed.Instructions.Any(instruction =>
                instruction.OpCode.FlowControl == FlowControl.Call && instruction.Operand is null))
        {
            diagnostic = "the body calls a token that does not resolve in the module.";
            return false;
        }
        // With the loader's own locals token every local operand should now resolve to a declared slot;
        // if one still does not, the restored signature did not match the body and it is refused rather
        // than grafted with a store that points at nothing.
        if (!LocalOperandsResolve(parsed))
        {
            diagnostic = "the restored locals signature did not cover the locals the body uses.";
            return false;
        }
        parsed.InitLocals = frame.InitLocals;
        parsed.KeepOldMaxStack = false;
        parsed.UpdateInstructionOffsets();
        body = parsed;
        return true;
    }

    /// <summary>
    /// Reads the exception section NecroBit left in the mapped image for a protected method and
    /// reattaches its clauses to the rebuilt body, translating the section's blob-relative offsets past
    /// the body marker and onto the instructions the offsets fall on.
    /// </summary>
    private static bool TryAttachExceptionHandlers(
        ModuleDefMD module,
        ProtectedMethodStub stub,
        CilBody body,
        out string? diagnostic)
    {
        diagnostic = null;
        var image = module.Metadata.PEImage;
        var reader = image.CreateReader();
        reader.Position = (uint)image.ToFileOffset((RVA)stub.Rva);
        var flags = reader.ReadUInt16();
        if ((flags & 0x3) != 0x3)
        {
            diagnostic = "the protected method does not have a fat header to carry an exception section.";
            return false;
        }
        reader.ReadUInt16();
        var imageCodeSize = reader.ReadUInt32();
        var headerSize = (uint)((flags >> 12) * 4);

        // The JIT locates the exception section at the four-byte-aligned end of the method's code, and
        // the section that outlives the stub was laid down against the stub's own code size, so that is
        // the offset it still sits at.
        var sectionRva = (stub.Rva + headerSize + imageCodeSize + 3) & ~3u;
        reader.Position = (uint)image.ToFileOffset((RVA)sectionRva);
        var kind = reader.ReadByte();
        if ((kind & 0x1) == 0)
        {
            diagnostic = "the exception section was not an exception table.";
            return false;
        }
        var fat = (kind & 0x40) != 0;
        List<(uint Flags, uint TryOffset, uint TryLength, uint HandlerOffset, uint HandlerLength, uint Token)> clauses = [];
        if (fat)
        {
            var dataSize = reader.ReadByte() | ((uint)reader.ReadByte() << 8) | ((uint)reader.ReadByte() << 16);
            var count = (dataSize - 4) / 24;
            for (var i = 0; i < count; i++)
            {
                clauses.Add((
                    reader.ReadUInt32(), reader.ReadUInt32(), reader.ReadUInt32(),
                    reader.ReadUInt32(), reader.ReadUInt32(), reader.ReadUInt32()));
            }
        }
        else
        {
            var dataSize = reader.ReadByte();
            reader.ReadUInt16();
            var count = (dataSize - 4) / 12;
            for (var i = 0; i < count; i++)
            {
                clauses.Add((
                    reader.ReadUInt16(), reader.ReadUInt16(), reader.ReadByte(),
                    reader.ReadUInt16(), reader.ReadByte(), reader.ReadUInt32()));
            }
        }
        if (clauses.Count == 0)
        {
            diagnostic = "the exception section held no clauses.";
            return false;
        }

        var byOffset = body.Instructions.ToDictionary(instruction => instruction.Offset);
        var codeEnd = (uint)(body.Instructions[^1].Offset + body.Instructions[^1].GetSize());
        foreach (var clause in clauses)
        {
            if (!TryResolveBoundary(byOffset, codeEnd, clause.TryOffset, out var tryStart) ||
                !TryResolveBoundary(byOffset, codeEnd, clause.TryOffset + clause.TryLength, out var tryEnd) ||
                !TryResolveBoundary(byOffset, codeEnd, clause.HandlerOffset, out var handlerStart) ||
                !TryResolveBoundary(byOffset, codeEnd, clause.HandlerOffset + clause.HandlerLength, out var handlerEnd))
            {
                diagnostic = "an exception clause boundary did not fall on an instruction.";
                return false;
            }
            var handler = new ExceptionHandler((ExceptionHandlerType)(clause.Flags & 0x7))
            {
                TryStart = tryStart,
                TryEnd = tryEnd,
                HandlerStart = handlerStart,
                HandlerEnd = handlerEnd,
            };
            if ((clause.Flags & 0x7) == 0 && clause.Token != 0)
            {
                if (module.ResolveToken(clause.Token) is not ITypeDefOrRef catchType)
                {
                    diagnostic = "a catch clause named a type token that does not resolve.";
                    return false;
                }
                handler.CatchType = catchType;
            }
            else if ((clause.Flags & 0x7) == 1)
            {
                if (!TryResolveBoundary(byOffset, codeEnd, clause.Token, out var filterStart))
                {
                    diagnostic = "a filter clause did not start on an instruction.";
                    return false;
                }
                handler.FilterStart = filterStart;
            }
            body.ExceptionHandlers.Add(handler);
        }
        return true;
    }

    /// <summary>
    /// Maps a clause boundary — a blob-relative byte offset past the body marker — onto the instruction
    /// it opens, or onto null when it marks the very end of the code, refusing anything that lands in the
    /// middle of an instruction.
    /// </summary>
    private static bool TryResolveBoundary(
        Dictionary<uint, Instruction> byOffset,
        uint codeEnd,
        uint blobOffset,
        out Instruction? instruction)
    {
        instruction = null;
        if (blobOffset < MarkerLength)
            return false;
        var offset = blobOffset - MarkerLength;
        if (offset == codeEnd)
            return true;
        return byOffset.TryGetValue(offset, out instruction);
    }

    /// <summary>
    /// Whether every local- and argument-referencing instruction resolves to a slot the body
    /// actually declares, which a body rebuilt against the wrong locals signature would fail.
    /// </summary>
    /// <remarks>
    /// The short single-byte forms (<c>ldloc.0</c> through <c>stloc.3</c>) carry their index in the
    /// opcode and leave the operand null, so they have to be bounds-checked by that implicit index
    /// rather than by a resolved <see cref="Local"/>. Missing them is what lets a body that uses
    /// locals the stub never declared graft anyway and decompile to out-of-range loads.
    /// </remarks>
    private static bool LocalOperandsResolve(CilBody body)
    {
        foreach (var instruction in body.Instructions)
        {
            var implicitIndex = instruction.OpCode.Code switch
            {
                Code.Ldloc_0 or Code.Stloc_0 => 0,
                Code.Ldloc_1 or Code.Stloc_1 => 1,
                Code.Ldloc_2 or Code.Stloc_2 => 2,
                Code.Ldloc_3 or Code.Stloc_3 => 3,
                _ => -1,
            };
            if (implicitIndex >= 0)
            {
                if (implicitIndex >= body.Variables.Count)
                    return false;
                continue;
            }
            switch (instruction.OpCode.Code)
            {
                case Code.Ldloc:
                case Code.Ldloc_S:
                case Code.Ldloca:
                case Code.Ldloca_S:
                case Code.Stloc:
                case Code.Stloc_S:
                    if (instruction.Operand is not Local local || !body.Variables.Contains(local))
                        return false;
                    break;
                case Code.Ldarg:
                case Code.Ldarg_S:
                case Code.Ldarga:
                case Code.Ldarga_S:
                case Code.Starg:
                case Code.Starg_S:
                    if (instruction.Operand is not Parameter)
                        return false;
                    break;
            }
        }
        return true;
    }

    private static bool TryReadBodyBytes(
        ModuleDefMD module,
        StaticHeap heap,
        StaticValue value,
        out byte[] il,
        out bool nativeMode)
    {
        il = [];
        nativeMode = false;
        var instance = heap.TryUnbox(value, out var unboxed) ? unboxed : value;
        if (!heap.TryGetRuntimeTypeName(instance, out var typeName))
            return false;
        var type = module.GetTypes().FirstOrDefault(candidate => candidate.FullName == typeName);
        if (type is null)
            return false;
        byte[]? bodyBytes = null;
        var lengthField = 0;
        var haveLength = false;
        var pointerFields = new List<FieldDef>();
        foreach (var field in type.Fields)
        {
            // NecroBit's per-body record holds one byte array — the plaintext the JIT hook hands over
            // — and one boolean that selects the hook's alternate path, in which those bytes are the
            // method's native code rather than its IL. The original IL of a method compiled that way
            // is gone, so the flag is what tells a recoverable body from one that is not.
            if (field.FieldSig?.Type is SZArraySig array && array.Next?.ElementType == ElementType.U1)
            {
                if (heap.TryReadField(instance, field, out var reference) &&
                    heap.GetBytesSnapshot(reference) is { } bytes)
                {
                    bodyBytes = bytes;
                }
            }
            else if (field.FieldSig?.Type.ElementType == ElementType.Boolean &&
                     heap.TryReadField(instance, field, out var flag) &&
                     flag.Kind == StaticValueKind.Int32)
            {
                nativeMode = flag.AsInt32() != 0;
            }
            // A CoreCLR NecroBit record carries no plaintext array. Its bodies are decrypted into one
            // native page and each record names its own with a length and a pointer into that page,
            // where a .NET Framework record would have carried the bytes themselves. The length is the
            // record's only Int32; the pointer is one of its two native-int fields (the other is the IL
            // address the record is keyed by), so both are tried and the one whose bytes are a body wins.
            else if (field.FieldSig?.Type.ElementType == ElementType.I4 &&
                     heap.TryReadField(instance, field, out var length) &&
                     length.Kind == StaticValueKind.Int32)
            {
                lengthField = length.AsInt32();
                haveLength = true;
            }
            else if (field.FieldSig?.Type.ElementType is ElementType.I or ElementType.U)
            {
                pointerFields.Add(field);
            }
        }
        if (bodyBytes is null && haveLength && lengthField > MarkerLength)
            bodyBytes = TryReadNativeBody(heap, instance, pointerFields, lengthField);
        if (bodyBytes is null || bodyBytes.Length <= MarkerLength ||
            bodyBytes[0] != 0x2B || bodyBytes[1] != 0x05 || bodyBytes[2] != 0x28)
        {
            return false;
        }
        il = bodyBytes;
        return true;
    }

    /// <summary>
    /// Reads a CoreCLR NecroBit body out of the native page it was decrypted into, given the record's
    /// length and the candidate pointer fields.
    /// </summary>
    /// <remarks>
    /// The record keeps two native-int fields: the address of its decrypted body in the shared page,
    /// and the IL address it is keyed by. Only the first points into a page the run allocated, so each
    /// is resolved to a region and read from; the one that yields a body -- length bytes that open with
    /// the anti-tamper marker -- is the body, and the IL-address field simply fails to read as one.
    /// </remarks>
    private static byte[]? TryReadNativeBody(
        StaticHeap heap,
        StaticValue instance,
        IReadOnlyList<FieldDef> pointerFields,
        int length)
    {
        foreach (var field in pointerFields)
        {
            if (!heap.TryReadField(instance, field, out var pointer))
                continue;
            if (!TryResolvePointerAddress(heap, pointer, out var address) ||
                !heap.TryResolveNativeAddress(address, out var native))
            {
                continue;
            }
            var bytes = new byte[length];
            if (heap.TryReadBytes(native, 0, bytes) &&
                bytes[0] == 0x2B && bytes[1] == 0x05 && bytes[2] == 0x28)
            {
                return bytes;
            }
        }
        return null;
    }

    /// <summary>
    /// Resolves a native-int field value -- which the loader stores as an <see cref="System.IntPtr"/>
    /// wrapping either a synthetic pointer or a raw address -- to the absolute address it names.
    /// </summary>
    private static bool TryResolvePointerAddress(StaticHeap heap, StaticValue value, out long address)
    {
        address = 0;
        var current = value;
        for (var unwound = 0; unwound < 8; unwound++)
        {
            if (heap.TryGetModelValue(current, "Pointer", out StaticValue modeled))
            {
                current = modeled;
                continue;
            }
            break;
        }
        if (current.Kind == StaticValueKind.NativePointer &&
            heap.TryGetNativeAddress(current, out address))
        {
            return true;
        }
        if (current.IsInteger)
        {
            address = current.AsInt64();
            return true;
        }
        return false;
    }
}
