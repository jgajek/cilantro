using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Passes;

namespace ReactorUnpack.Core.Recovery;

public sealed record StubPrefixWindow(
    uint Token,
    uint Rva,
    int FileOffset,
    int Length)
{
    public ulong EndRva => (ulong)Rva + (uint)Length;
}

public sealed record MappedImageWrite(
    int Offset,
    byte[] Bytes,
    string RegionKind,
    long RegionIdentity = 0)
{
    public static MappedImageWrite From(ImageRegionWrite write) =>
        new(write.Offset, (byte[])write.Bytes.Clone(), write.RegionKind, write.Region.Bits);
}

public static class MethodBodyRecoveryInfrastructure
{
    private const int MaximumReservedPadding = 4096;

    public static bool TryCatalogStubPrefixWindows(
        PeImageView image,
        IReadOnlyList<ProtectedMethodStub> stubs,
        out IReadOnlyList<StubPrefixWindow> windows,
        out string? diagnostic)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(stubs);
        var sorted = stubs.OrderBy(item => item.Rva).ToArray();
        var declared = new int[sorted.Length];
        var tokens = new HashSet<uint>();
        for (var index = 0; index < sorted.Length; index++)
        {
            var stub = sorted[index];
            if (stub.Token == 0 || stub.Rva == 0 || !tokens.Add(stub.Token))
                return CatalogFailure(
                    out windows,
                    out diagnostic,
                    "The protected-stub catalog contains a zero or duplicate identity.");
            if (!TryReadMethodPrefixLength(image, stub.Rva, out declared[index], out diagnostic))
                return CatalogFailure(out windows, out diagnostic, diagnostic!);
        }

        var result = new List<StubPrefixWindow>(sorted.Length);
        for (var index = 0; index < sorted.Length; index++)
        {
            var stub = sorted[index];
            var limit = index + 1 < sorted.Length
                ? sorted[index + 1].Rva
                : (ulong)stub.Rva + (uint)declared[index] + MaximumReservedPadding;
            var length = ExtendToReservedSlot(image, stub.Rva, declared[index], limit);
            if (!TryMapContiguousRange(image, stub.Rva, length, out var fileOffset))
                return CatalogFailure(
                    out windows,
                    out diagnostic,
                    $"Stub 0x{stub.Token:X8} has a prefix that is not wholly file-backed.");
            result.Add(new StubPrefixWindow(stub.Token, stub.Rva, fileOffset, length));
        }

        var ordered = result.OrderBy(item => item.Rva).ToArray();
        for (var index = 1; index < ordered.Length; index++)
        {
            if (ordered[index].Rva < ordered[index - 1].EndRva)
                return CatalogFailure(
                    out windows,
                    out diagnostic,
                    "Protected-stub prefix windows overlap.");
        }

        windows = ordered;
        diagnostic = null;
        return true;
    }

    public static bool WriteLogsEqual(
        IReadOnlyList<MappedImageWrite> left,
        IReadOnlyList<MappedImageWrite> right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.Count == right.Count &&
            left.Zip(right).All(pair =>
                pair.First.Offset == pair.Second.Offset &&
                pair.First.RegionIdentity == pair.Second.RegionIdentity &&
                string.Equals(
                    pair.First.RegionKind,
                    pair.Second.RegionKind,
                    StringComparison.Ordinal) &&
                pair.First.Bytes.AsSpan().SequenceEqual(pair.Second.Bytes));
    }

    public static bool TryValidateAndReplayWrites(
        PeImageView image,
        IReadOnlyList<StubPrefixWindow> windows,
        IReadOnlyList<MappedImageWrite> writes,
        out byte[] restoredFile,
        out IReadOnlySet<uint> touchedTokens,
        out string? diagnostic)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(windows);
        ArgumentNullException.ThrowIfNull(writes);
        restoredFile = image.CreateFileCopy();
        var original = image.CreateFileCopy();
        var touched = new HashSet<uint>();

        foreach (var write in writes)
        {
            if (!string.Equals(write.RegionKind, "MappedImage", StringComparison.Ordinal))
                return ReplayFailure(
                    out restoredFile,
                    out touchedTokens,
                    out diagnostic,
                    $"A write targeted non-image region '{write.RegionKind}'.");
            if (write.Bytes.Length == 0 || write.Offset < 0)
                return ReplayFailure(
                    out restoredFile,
                    out touchedTokens,
                    out diagnostic,
                    "A mapped-image write has an empty or negative range.");
            var start = (uint)write.Offset;
            var end = (ulong)start + (uint)write.Bytes.Length;
            var containing = windows.Where(window =>
                    start >= window.Rva && end <= window.EndRva)
                .ToArray();
            if (containing.Length != 1)
            {
                var nearest = windows.LastOrDefault(window => window.Rva <= start);
                var context = nearest is null
                    ? "no preceding stub"
                    : $"nearest stub 0x{nearest.Token:X8} spans " +
                        $"[0x{nearest.Rva:X8},0x{nearest.EndRva:X8})";
                return ReplayFailure(
                    out restoredFile,
                    out touchedTokens,
                    out diagnostic,
                    $"Mapped-image write [0x{start:X8},0x{end:X8}) is outside one stub " +
                        $"prefix ({context}, {containing.Length} candidates).");
            }

            for (var index = 0; index < write.Bytes.Length; index++)
            {
                var rva = checked(start + (uint)index);
                if (!image.TryRvaToFileOffset(rva, out var fileOffset))
                    return ReplayFailure(
                        out restoredFile,
                        out touchedTokens,
                        out diagnostic,
                        $"Mapped-image write at RVA 0x{rva:X8} is not file-backed.");
                restoredFile[fileOffset] = write.Bytes[index];
            }
            touched.Add(containing[0].Token);
        }

        if (touched.Count != windows.Count)
            return ReplayFailure(
                out restoredFile,
                out touchedTokens,
                out diagnostic,
                $"Writes touched {touched.Count} of {windows.Count} protected stub prefixes.");
        if (!TailsArePreserved(original, restoredFile, windows))
            return ReplayFailure(
                out restoredFile,
                out touchedTokens,
                out diagnostic,
                "Replay changed bytes outside catalogued stub prefix windows.");

        touchedTokens = touched;
        diagnostic = null;
        return true;
    }

    public static CilBody CloneBody(
        MethodDef source,
        MethodDef destination,
        ModuleDef destinationModule)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(destinationModule);
        if (!source.HasBody)
            throw new InvalidOperationException("The source method has no CIL body.");

        var importer = new Importer(destinationModule);
        var sourceBody = source.Body;
        var body = new CilBody
        {
            KeepOldMaxStack = sourceBody.KeepOldMaxStack,
            InitLocals = sourceBody.InitLocals,
            HeaderSize = sourceBody.HeaderSize,
            MaxStack = sourceBody.MaxStack,
            LocalVarSigTok = sourceBody.LocalVarSigTok,
        };
        foreach (var local in sourceBody.Variables)
        {
            body.Variables.Add(new Local(importer.Import(local.Type), local.Name)
            {
                Attributes = local.Attributes,
            });
        }

        var instructionMap = sourceBody.Instructions.ToDictionary(
            instruction => instruction,
            instruction => new Instruction(instruction.OpCode, null));
        foreach (var sourceInstruction in sourceBody.Instructions)
            body.Instructions.Add(instructionMap[sourceInstruction]);
        foreach (var sourceInstruction in sourceBody.Instructions)
        {
            instructionMap[sourceInstruction].Operand = RemapOperand(
                sourceInstruction.Operand,
                source,
                destination,
                destinationModule,
                importer,
                instructionMap,
                sourceBody.Variables,
                body.Variables);
        }

        foreach (var sourceHandler in sourceBody.ExceptionHandlers)
        {
            body.ExceptionHandlers.Add(new ExceptionHandler(sourceHandler.HandlerType)
            {
                TryStart = MapBoundary(sourceHandler.TryStart, instructionMap),
                TryEnd = MapBoundary(sourceHandler.TryEnd, instructionMap),
                FilterStart = MapBoundary(sourceHandler.FilterStart, instructionMap),
                HandlerStart = MapBoundary(sourceHandler.HandlerStart, instructionMap),
                HandlerEnd = MapBoundary(sourceHandler.HandlerEnd, instructionMap),
                CatchType = sourceHandler.CatchType is null
                    ? null
                    : RemapMetadata(sourceHandler.CatchType, destinationModule) as ITypeDefOrRef ??
                      importer.Import(sourceHandler.CatchType),
            });
        }
        body.UpdateInstructionOffsets();
        return body;
    }

    /// <summary>Reactor reserves more room for a protected stub than its placeholder body uses,
    /// and the recovered body can fill the whole slot. The window therefore grows across the
    /// trailing gap, but only over bytes proven to be unused zero padding and never past the
    /// next stub. A zero byte is not a legal CIL method header, so no other body starts there.
    /// </summary>
    private static int ExtendToReservedSlot(PeImageView image, uint rva, int length, ulong limit)
    {
        var end = checked((ulong)rva + (uint)length);
        if (limit <= end)
            return length;
        var available = checked((int)Math.Min(limit - end, MaximumReservedPadding));
        if (available <= 0 || !image.TryRead(rva + (uint)length, available, out var padding))
            return length;
        var firstUsed = padding.Span.IndexOfAnyExcept((byte)0);
        return checked(length + (firstUsed < 0 ? available : firstUsed));
    }

    private static bool TryReadMethodPrefixLength(
        PeImageView image,
        uint rva,
        out int length,
        out string? diagnostic)
    {
        length = 0;
        diagnostic = null;
        if (!image.TryRead(rva, 1, out var firstByteMemory))
        {
            diagnostic = $"Stub RVA 0x{rva:X8} is outside the mapped image.";
            return false;
        }
        var first = firstByteMemory.Span[0];
        if ((first & 3) == 2)
        {
            var tinyCodeSize = first >> 2;
            if (tinyCodeSize == 0)
            {
                diagnostic = $"Stub RVA 0x{rva:X8} has an empty tiny method body.";
                return false;
            }
            length = checked(1 + tinyCodeSize);
            return image.TryRead(rva, length, out _);
        }
        if ((first & 3) != 3 || !image.TryRead(rva, 12, out var fatHeader))
        {
            diagnostic = $"Stub RVA 0x{rva:X8} has an invalid CIL method header.";
            return false;
        }

        var headerDwords = fatHeader.Span[1] >> 4;
        if (headerDwords < 3)
        {
            diagnostic = $"Stub RVA 0x{rva:X8} has a truncated fat CIL header.";
            return false;
        }
        var headerSize = checked(headerDwords * 4);
        if (!image.TryRead(rva, headerSize, out var fullHeader))
        {
            diagnostic = $"Stub RVA 0x{rva:X8} fat CIL header is out of range.";
            return false;
        }
        var codeSize = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
            fullHeader.Span.Slice(4, 4));
        if (codeSize == 0 || codeSize > int.MaxValue - headerSize)
        {
            diagnostic = $"Stub RVA 0x{rva:X8} has an invalid CIL code size.";
            return false;
        }
        length = checked(headerSize + (int)codeSize);
        if (!image.TryRead(rva, length, out _))
        {
            diagnostic = $"Stub RVA 0x{rva:X8} CIL prefix is outside the mapped image.";
            return false;
        }
        return true;
    }

    private static bool TryMapContiguousRange(
        PeImageView image,
        uint rva,
        int length,
        out int fileOffset)
    {
        fileOffset = 0;
        if (length <= 0 || !image.TryRvaToFileOffset(rva, out fileOffset))
            return false;
        for (var index = 1; index < length; index++)
        {
            if (!image.TryRvaToFileOffset(checked(rva + (uint)index), out var current) ||
                current != fileOffset + index)
                return false;
        }
        return true;
    }

    private static bool TailsArePreserved(
        ReadOnlySpan<byte> original,
        ReadOnlySpan<byte> restored,
        IReadOnlyList<StubPrefixWindow> windows)
    {
        if (original.Length != restored.Length)
            return false;
        var allowed = new bool[original.Length];
        foreach (var window in windows)
            allowed.AsSpan(window.FileOffset, window.Length).Fill(true);
        for (var index = 0; index < original.Length; index++)
        {
            if (!allowed[index] && original[index] != restored[index])
                return false;
        }
        return true;
    }

    private static object? RemapOperand(
        object? operand,
        MethodDef sourceMethod,
        MethodDef destinationMethod,
        ModuleDef destinationModule,
        Importer importer,
        Dictionary<Instruction, Instruction> instructions,
        LocalList sourceLocals,
        LocalList destinationLocals)
    {
        return operand switch
        {
            null => null,
            Instruction target => instructions[target],
            IList<Instruction> targets => targets.Select(target => instructions[target]).ToArray(),
            Local local => destinationLocals[sourceLocals.IndexOf(local)],
            Parameter parameter => RemapParameter(parameter, sourceMethod, destinationMethod),
            IMethod method => RemapMetadata(method, destinationModule) as IMethod ??
                importer.Import(method),
            IField field => RemapMetadata(field, destinationModule) as IField ??
                importer.Import(field),
            ITypeDefOrRef type => RemapMetadata(type, destinationModule) as ITypeDefOrRef ??
                importer.Import(type),
            MethodSig signature => importer.Import(signature),
            _ => operand,
        };
    }

    private static Parameter RemapParameter(
        Parameter parameter,
        MethodDef source,
        MethodDef destination)
    {
        var index = source.Parameters.IndexOf(parameter);
        if ((uint)index >= (uint)destination.Parameters.Count)
            throw new InvalidOperationException("A recovered parameter operand is outside its method.");
        return destination.Parameters[index];
    }

    private static IMDTokenProvider? RemapMetadata(
        IMDTokenProvider source,
        ModuleDef destinationModule)
    {
        var token = source.MDToken.Raw;
        return token == 0 ? null : destinationModule.ResolveToken(token);
    }

    private static Instruction? MapBoundary(
        Instruction? source,
        Dictionary<Instruction, Instruction> instructions) =>
        source is null ? null : instructions[source];

    private static bool CatalogFailure(
        out IReadOnlyList<StubPrefixWindow> windows,
        out string? diagnostic,
        string message)
    {
        windows = [];
        diagnostic = message;
        return false;
    }

    private static bool ReplayFailure(
        out byte[] restoredFile,
        out IReadOnlySet<uint> touchedTokens,
        out string? diagnostic,
        string message)
    {
        restoredFile = [];
        touchedTokens = new HashSet<uint>();
        diagnostic = message;
        return false;
    }
}
