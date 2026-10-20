using System.Buffers.Binary;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

internal sealed record ConfuserExJitBodyRecord(
    MethodDef Method, byte[] Il, byte[] Locals, byte[] Exceptions,
    uint MaxStack, uint Options, uint MulSeed, int[] Layout);

internal static class ConfuserExJitBodyDecoder
{
    internal static bool TryRestore(ArtifactContext context,
        IReadOnlyList<ConfuserExJitBodyRecord> records, out string diagnostic)
    {
        diagnostic = string.Empty;
        var replacements = new Dictionary<MethodDef, CilBody>();
        foreach (var record in records)
        {
            if (!TryBuildBody((ModuleDefMD)record.Method.Module, record,
                    out var body, out diagnostic)) return false;
            replacements.Add(record.Method, body);
        }
        using var batch = new BodyMutationBatch(replacements.Keys);
        foreach (var replacement in replacements)
            replacement.Key.Body = replacement.Value;
        var verification = AssemblyVerifier.Verify(context.Module,
            context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context));
        if (!verification.Passed)
        {
            diagnostic = "Rebuilt JIT bodies failed assembly verification: " +
                string.Join("; ", verification.Diagnostics.Take(3));
            return false;
        }
        batch.Commit();
        return true;
    }

    private static bool TryBuildBody(ModuleDefMD module, ConfuserExJitBodyRecord record,
        out CilBody body, out string diagnostic)
    {
        body = new CilBody();
        diagnostic = string.Empty;
        LocalSig? locals = null;
        if (record.Locals.Length > 0)
        {
            try { locals = SignatureReader.ReadSig(module, record.Locals) as LocalSig; }
            catch (Exception exception) when (exception is ArgumentException or IOException or
                InvalidOperationException)
            {
                diagnostic = $"{record.Method.MDToken}: local signature did not parse.";
                return false;
            }
            if (locals is null)
            {
                diagnostic = $"{record.Method.MDToken}: local signature was not a LocalSig.";
                return false;
            }
        }
        try
        {
            var resolver = new JitOperandResolver(module, locals);
            body = MethodBodyReader.CreateCilBody(resolver, record.Il, null,
                record.Method.Parameters, (ushort)(record.Options & 0x10),
                (ushort)record.MaxStack, (uint)record.Il.Length,
                locals is null ? 0u : 0x11000001u);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or
            InvalidOperationException or IndexOutOfRangeException)
        {
            diagnostic = $"{record.Method.MDToken}: recovered IL did not parse ({exception.Message}).";
            return false;
        }
        if (body.Instructions.Count == 0 || body.Instructions[^1].OpCode.Code is not
            (Code.Ret or Code.Throw or Code.Rethrow or Code.Endfinally or
             Code.Br or Code.Br_S or Code.Leave or Code.Leave_S))
        {
            diagnostic = $"{record.Method.MDToken}: recovered IL has no terminal instruction " +
                $"(last {body.Instructions.LastOrDefault()?.OpCode.Code}).";
            return false;
        }
        body.UpdateInstructionOffsets();
        var byOffset = body.Instructions.ToDictionary(instruction => instruction.Offset);
        for (var index = 0; index < record.Exceptions.Length; index += 24)
        {
            var clause = record.Exceptions.AsSpan(index, 24);
            var flags = BinaryPrimitives.ReadUInt32LittleEndian(clause);
            var tryOffset = BinaryPrimitives.ReadUInt32LittleEndian(clause[4..]);
            var tryLength = BinaryPrimitives.ReadUInt32LittleEndian(clause[8..]);
            var handlerOffset = BinaryPrimitives.ReadUInt32LittleEndian(clause[12..]);
            var handlerLength = BinaryPrimitives.ReadUInt32LittleEndian(clause[16..]);
            var token = BinaryPrimitives.ReadUInt32LittleEndian(clause[20..]);
            if (flags is not (0 or 1 or 2 or 4) ||
                !Boundary(byOffset, record.Il.Length, tryOffset, out var tryStart) ||
                !Boundary(byOffset, record.Il.Length, (ulong)tryOffset + tryLength, out var tryEnd) ||
                !Boundary(byOffset, record.Il.Length, handlerOffset, out var handlerStart) ||
                !Boundary(byOffset, record.Il.Length, (ulong)handlerOffset + handlerLength, out var handlerEnd) ||
                tryStart is null || handlerStart is null)
            {
                diagnostic = $"{record.Method.MDToken}: JIT exception clause {index / 24} has invalid boundaries.";
                return false;
            }
            var handler = new ExceptionHandler((ExceptionHandlerType)flags)
            {
                TryStart = tryStart, TryEnd = tryEnd,
                HandlerStart = handlerStart, HandlerEnd = handlerEnd
            };
            if (flags == 0)
            {
                if (module.ResolveToken(token) is not ITypeDefOrRef catchType)
                {
                    diagnostic = $"{record.Method.MDToken}: JIT catch type token is invalid.";
                    return false;
                }
                handler.CatchType = catchType;
            }
            else if (flags == 1)
            {
                if (!Boundary(byOffset, record.Il.Length, token, out var filterStart) ||
                    filterStart is null)
                {
                    diagnostic = $"{record.Method.MDToken}: JIT filter start is invalid.";
                    return false;
                }
                handler.FilterStart = filterStart;
            }
            body.ExceptionHandlers.Add(handler);
        }
        body.InitLocals = (record.Options & 0x10) != 0;
        body.KeepOldMaxStack = true;
        return true;
    }

    private static bool Boundary(Dictionary<uint, Instruction> offsets, int codeLength,
        ulong offset, out Instruction? instruction)
    {
        instruction = null;
        if (offset == (ulong)codeLength) return true;
        return offset < (ulong)codeLength && offsets.TryGetValue((uint)offset, out instruction);
    }

    private sealed class JitOperandResolver(ModuleDefMD module, LocalSig? locals)
        : IInstructionOperandResolver
    {
        private readonly ModuleDefMD source = module;
        public IMDTokenProvider? ResolveToken(uint token, GenericParamContext context) =>
            token == 0x11000001 && locals is not null
                ? new StandAloneSigUser(locals)
                : ((IInstructionOperandResolver)source).ResolveToken(token, context);
        public string ReadUserString(uint token) =>
            ((IInstructionOperandResolver)source).ReadUserString(token);
    }

    internal static bool TryFindKey(ModuleDefMD module, out uint key)
    {
        key = 0;
        var found = new HashSet<uint>();
        foreach (var method in module.GlobalType.Methods.Where(method => method.HasBody &&
            method.Body.Instructions.Any(instruction => instruction.Operand is IMethod call &&
                call.DeclaringType?.FullName == "System.Runtime.InteropServices.Marshal" &&
                call.Name == "AllocHGlobal")))
        {
            var il = method.Body.Instructions;
            for (var index = 2; index < il.Count; index++)
                if (il[index].OpCode.Code == Code.Mul && il[index - 1].IsLdcI4() &&
                    il[index - 2].OpCode.Code == Code.Ldloc_0)
                    found.Add(unchecked((uint)il[index - 1].GetLdcI4Value()));
        }
        if (found.Count != 1) return false;
        key = found.Single();
        return true;
    }

    internal static bool TryDecode(byte[] restoredFile, IReadOnlyList<ConfuserExJitEntry> entries,
        uint key, out IReadOnlyList<ConfuserExJitBodyRecord> records,
        out string diagnostic)
    {
        records = [];
        diagnostic = string.Empty;
        var plaintexts = entries.Select(entry => Decrypt(restoredFile, entry, key)).ToArray();
        var layouts = Permutations([0, 1, 2, 3, 4, 5]);
        var candidates = new List<(int[] Layout, ConfuserExJitBodyRecord[] Records)>();
        foreach (var layout in layouts)
        {
            var decoded = new ConfuserExJitBodyRecord[entries.Count];
            var valid = true;
            for (var index = 0; index < entries.Count; index++)
            {
                if (!TryParse(entries[index].Method, plaintexts[index], layout, out decoded[index]))
                { valid = false; break; }
            }
            if (valid) candidates.Add((layout, decoded));
        }
        if (candidates.Count != 1)
        {
            diagnostic = $"JIT record header layout had {candidates.Count} valid candidate(s), expected one; " +
                $"headers: {string.Join(';', plaintexts.Select(plain =>
                    $"{plain.Length}[{string.Join(',', Enumerable.Range(0, 6).Select(index =>
                        BinaryPrimitives.ReadUInt32LittleEndian(plain.AsSpan(index * 4))))}]"))}.";
            return false;
        }
        records = candidates[0].Records;
        return true;
    }

    private static byte[] Decrypt(byte[] file, ConfuserExJitEntry entry, uint key)
    {
        var output = new byte[entry.WordCount * 4];
        var state = unchecked(entry.Method.MDToken.Raw * key);
        var counter = state;
        for (var index = 0; index < entry.WordCount; index++)
        {
            var cipher = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(entry.FileOffset + index * 4));
            var plain = cipher ^ state;
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(index * 4), plain);
            state = unchecked(state + (plain ^ counter));
            counter ^= (state >> 5) | (state << 27);
        }
        return output;
    }

    private static bool TryParse(MethodDef method, byte[] plain, int[] layout,
        out ConfuserExJitBodyRecord record)
    {
        record = null!;
        if (plain.Length < 28) return false;
        var fields = new uint[6];
        for (var physical = 0; physical < 6; physical++)
            fields[layout[physical]] = BinaryPrimitives.ReadUInt32LittleEndian(plain.AsSpan(physical * 4));
        var ilLength = fields[0];
        var maxStack = fields[1];
        var ehCount = fields[2];
        var localsLength = fields[3];
        var options = fields[4];
        if (ilLength == 0 || maxStack > 65535 || ehCount > 256 ||
            (options & ~0x98u) != 0 ||
            24ul + ilLength + localsLength + 24ul * ehCount > (ulong)plain.Length ||
            (ulong)plain.Length - (24ul + ilLength + localsLength + 24ul * ehCount) > 4)
            return false;
        if ((ehCount == 0) != ((options & 8) == 0)) return false;
        var il = plain.AsSpan(24, (int)ilLength).ToArray();
        var locals = plain.AsSpan(24 + (int)ilLength, (int)localsLength).ToArray();
        var eh = plain.AsSpan(24 + (int)ilLength + (int)localsLength, checked((int)ehCount * 24)).ToArray();
        if (locals.Length > 0 && locals[0] != 0x07) return false;
        record = new ConfuserExJitBodyRecord(method, il, locals, eh,
            maxStack, options, fields[5], (int[])layout.Clone());
        return true;
    }

    private static IEnumerable<int[]> Permutations(int[] numbers)
    {
        for (var start = 0; start < numbers.Length; start++)
        {
            (numbers[0], numbers[start]) = (numbers[start], numbers[0]);
            foreach (var remainder in PermutationsAt(numbers, 1)) yield return remainder;
            (numbers[0], numbers[start]) = (numbers[start], numbers[0]);
        }
    }

    private static IEnumerable<int[]> PermutationsAt(int[] numbers, int position)
    {
        if (position == numbers.Length) { yield return (int[])numbers.Clone(); yield break; }
        for (var index = position; index < numbers.Length; index++)
        {
            (numbers[position], numbers[index]) = (numbers[index], numbers[position]);
            foreach (var result in PermutationsAt(numbers, position + 1)) yield return result;
            (numbers[position], numbers[index]) = (numbers[index], numbers[position]);
        }
    }
}
