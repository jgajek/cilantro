using System.Buffers.Binary;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Payload;
using Cilantro.Core.Strings;
using Cilantro.Core.Verification;

namespace Cilantro.Tests;

public sealed class ArchitectureTests
{
    [Fact]
    public void RawMetadataPreflightAcceptsMinimalManagedAssembly()
    {
        using var module = new ModuleDefUser("negative.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("negative", new Version(1, 0));
        assembly.Modules.Add(module);
        using var stream = new MemoryStream();
        module.Write(stream);

        var facts = RawMetadataPreflight.Analyze(stream.ToArray());

        Assert.Equal(1u, facts.ModuleRows);
        Assert.Equal(1u, facts.AssemblyRows);
        Assert.DoesNotContain(facts.Anomalies,
            anomaly => anomaly.Contains("outside", StringComparison.Ordinal));
    }

    /// <summary>
    /// A protected assembly that verifies its own metadata header carries the <c>BSJB</c> signature
    /// as an ordinary <c>ldc.i4</c> operand, and the method body holding it can precede the
    /// metadata it describes. The root has to come from the CLI header, not from the first place
    /// those four bytes happen to appear.
    /// </summary>
    [Fact]
    public void RawMetadataRootComesFromTheCliHeaderNotAnEarlierSignatureConstant()
    {
        var bytes = SignatureConstantAssembly();
        var firstSignature = IndexOfMetadataSignature(bytes, 0);
        Assert.True(PeImageView.TryParse(bytes, out var image));
        Assert.True(image!.TryGetCliMetadataFileRange(out var declared, out _));
        // The trap this guards against has to actually be present in the fixture.
        Assert.InRange(firstSignature, 0, declared - 1);

        var facts = RawMetadataPreflight.Analyze(bytes, image);

        Assert.Equal(declared, facts.MetadataOffset);
        Assert.Equal(1u, facts.ModuleRows);
        Assert.Equal(1u, facts.AssemblyRows);
        Assert.DoesNotContain(facts.Anomalies,
            anomaly => anomaly.Contains("searching the file", StringComparison.Ordinal));
    }

    /// <summary>
    /// With no believable CLI header the search is all that is left, and then a candidate has to
    /// parse as a metadata root before it is accepted — which the signature constant does not.
    /// </summary>
    [Fact]
    public void RawMetadataRootIsSearchedForOnlyWhenNoCliHeaderNamesIt()
    {
        var bytes = SignatureConstantAssembly();
        Assert.True(PeImageView.TryParse(bytes, out var intact));
        Assert.True(intact!.TryGetCliMetadataFileRange(out var declared, out _));
        ClearCliHeaderDirectory(bytes);
        Assert.True(PeImageView.TryParse(bytes, out var cleared));
        Assert.False(cleared!.TryGetCliMetadataFileRange(out _, out _));

        var facts = RawMetadataPreflight.Analyze(bytes, cleared);

        Assert.Equal(declared, facts.MetadataOffset);
        Assert.Contains(facts.Anomalies,
            anomaly => anomaly.Contains("searching the file", StringComparison.Ordinal));
    }

    /// <summary>
    /// Alignment alone is not enough to tell a metadata root from four bytes that look like one, so
    /// the search also requires a candidate to parse. Here the decoy is aligned and first.
    /// </summary>
    [Fact]
    public void RawMetadataSearchRejectsAnAlignedCandidateThatDoesNotParse()
    {
        var assembly = SignatureConstantAssembly();
        Assert.True(PeImageView.TryParse(assembly, out var image));
        Assert.True(image!.TryGetCliMetadataFileRange(out var declared, out _));
        var decoy = new byte[16];
        "BSJB"u8.CopyTo(decoy);
        // A version-string length no file could satisfy, which is how a stray constant reads.
        BinaryPrimitives.WriteUInt32LittleEndian(decoy.AsSpan(12), 0x7FFF_FFF0);
        var bytes = new byte[decoy.Length + assembly.Length];
        decoy.CopyTo(bytes, 0);
        assembly.CopyTo(bytes, decoy.Length);
        // Prefixed bytes are not a PE any more, so only the search can answer.
        Assert.False(PeImageView.TryParse(bytes, out _));
        Assert.Equal(0, IndexOfMetadataSignature(bytes, 0));

        var facts = RawMetadataPreflight.Analyze(bytes);

        Assert.Equal(decoy.Length + declared, facts.MetadataOffset);
        Assert.Equal(1u, facts.ModuleRows);
    }

    [Fact]
    public void ResourceDirectoryWalkFindsARcdataPayloadByName()
    {
        var payload = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22 };
        var image = ImageWithRcdataResource("PAYLOAD", payload);
        bool Read(int rva, Span<byte> destination) =>
            rva >= 0 && rva <= image.Length - destination.Length &&
            image.AsSpan(rva, destination.Length).TryCopyTo(destination);

        Assert.True(PeResourceDirectory.TryGetDirectory(Read, out var directoryRva, out _));
        Assert.Equal(ResourceDirectoryRva, directoryRva);
        Assert.True(PeResourceDirectory.TryFindDataEntry(
            Read,
            ResourceName.FromId(RcdataType),
            // Windows compares resource names without case, and so does this.
            ResourceName.FromString("payload"),
            out var dataEntryRva));
        Assert.True(PeResourceDirectory.TryReadDataEntry(
            Read,
            dataEntryRva,
            out var dataRva,
            out var size));

        Assert.Equal(PayloadRva, dataRva);
        Assert.Equal(payload.Length, size);
        Assert.Equal(payload, image.AsSpan((int)dataRva, size).ToArray());
    }

    [Fact]
    public void ResourceDirectoryWalkDoesNotInventAnAbsentResource()
    {
        var image = ImageWithRcdataResource("PAYLOAD", [1, 2, 3]);
        bool Read(int rva, Span<byte> destination) =>
            rva >= 0 && rva <= image.Length - destination.Length &&
            image.AsSpan(rva, destination.Length).TryCopyTo(destination);

        Assert.False(PeResourceDirectory.TryFindDataEntry(
            Read,
            ResourceName.FromId(RcdataType),
            ResourceName.FromString("OTHER"),
            out _));
        Assert.False(PeResourceDirectory.TryFindDataEntry(
            Read,
            ResourceName.FromId(24),
            ResourceName.FromString("PAYLOAD"),
            out _));
        // A named type is not the same key as a numbered one.
        Assert.False(PeResourceDirectory.TryFindDataEntry(
            Read,
            ResourceName.FromString("10"),
            ResourceName.FromString("PAYLOAD"),
            out _));
    }

    internal const ushort RcdataType = 10;
    internal const uint ResourceDirectoryRva = 0x1000;
    internal const uint PayloadRva = 0x2000;

    /// <summary>
    /// Builds the smallest mapped image that carries one <c>RT_RCDATA</c> resource under a named
    /// entry: DOS stub, PE signature, an optional header long enough to reach its data directories,
    /// and a three-level resource tree of type, name, and language.
    /// </summary>
    internal static byte[] ImageWithRcdataResource(string name, ReadOnlySpan<byte> payload)
    {
        const int peOffset = 0x80;
        const int optionalOffset = peOffset + 24;
        const int directoriesOffset = optionalOffset + 96;
        var image = new byte[0x4000];
        "MZ"u8.CopyTo(image);
        BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(0x3C), peOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(peOffset), 0x0000_4550);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 4), 0x014C);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 20), 224);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(optionalOffset), 0x10B);
        BinaryPrimitives.WriteUInt32LittleEndian(
            image.AsSpan(directoriesOffset + PeResourceDirectory.ResourceDirectoryIndex * 8),
            ResourceDirectoryRva);
        BinaryPrimitives.WriteUInt32LittleEndian(
            image.AsSpan(directoriesOffset + PeResourceDirectory.ResourceDirectoryIndex * 8 + 4),
            0x1000);

        const int root = (int)ResourceDirectoryRva;
        const int typeNode = root + 0x18;
        const int nameNode = root + 0x30;
        const int dataEntry = root + 0x48;
        const int nameText = root + 0x60;

        // Root: one entry, keyed by the numeric type.
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(root + 14), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(root + 16), RcdataType);
        BinaryPrimitives.WriteUInt32LittleEndian(
            image.AsSpan(root + 20), 0x8000_0000 | (uint)(typeNode - root));
        // Type node: one entry, keyed by a name whose offset is relative to the directory.
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(typeNode + 12), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(
            image.AsSpan(typeNode + 16), 0x8000_0000 | (uint)(nameText - root));
        BinaryPrimitives.WriteUInt32LittleEndian(
            image.AsSpan(typeNode + 20), 0x8000_0000 | (uint)(nameNode - root));
        // Name node: one language, pointing at the data entry rather than a further directory.
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(nameNode + 14), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(nameNode + 16), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(
            image.AsSpan(nameNode + 20), (uint)(dataEntry - root));
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(dataEntry), PayloadRva);
        BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(dataEntry + 4), payload.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(nameText), (ushort)name.Length);
        System.Text.Encoding.Unicode.GetBytes(name).CopyTo(image.AsSpan(nameText + 2));
        payload.CopyTo(image.AsSpan((int)PayloadRva));
        return image;
    }

    private static byte[] SignatureConstantAssembly()
    {
        using var module = new ModuleDefUser("decoy.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("decoy", new Version(1, 0));
        assembly.Modules.Add(module);
        var type = new TypeDefUser(
            "Tests",
            "Tamper",
            module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var method = new MethodDefUser(
            "SignatureOfItsOwnHeader",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        method.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(0x424A5342));
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type.Methods.Add(method);
        using var stream = new MemoryStream();
        module.Write(stream);
        return stream.ToArray();
    }

    private static int IndexOfMetadataSignature(ReadOnlySpan<byte> bytes, int start)
    {
        var hit = bytes[start..].IndexOf("BSJB"u8);
        return hit < 0 ? -1 : start + hit;
    }

    private static void ClearCliHeaderDirectory(Span<byte> bytes)
    {
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes[0x3C..]);
        var optionalOffset = peOffset + 24;
        var magic = BinaryPrimitives.ReadUInt16LittleEndian(bytes[optionalOffset..]);
        var directories = optionalOffset + (magic == 0x20B ? 112 : 96);
        bytes.Slice(directories + PeImageView.CliHeaderDirectoryIndex * 8, 8).Clear();
    }

    [Fact]
    public void LengthPrefixedStringTableEnforcesFraming()
    {
        var text = System.Text.Encoding.Unicode.GetBytes("Reactor");
        var table = new byte[text.Length + 4];
        BinaryPrimitives.WriteInt32LittleEndian(table, text.Length);
        text.CopyTo(table, 4);

        Assert.True(LengthPrefixedStringTable.TryDecode(table, 0, out var record));
        Assert.Equal("Reactor", record!.Value);
        table[0] = 0xFF;
        Assert.False(LengthPrefixedStringTable.TryDecode(table, 0, out _));
    }

    [Fact]
    public void TerminalByteArrayRequiresUniqueExactEnd()
    {
        var resource = new byte[10];
        resource[2] = 0x20;
        BinaryPrimitives.WriteInt32LittleEndian(resource.AsSpan(3), 3);
        resource[7] = 1;
        resource[8] = 2;
        resource[9] = 3;

        Assert.True(PayloadStageValidator.TryExtractTerminalByteArray(resource, out var value));
        Assert.Equal([1, 2, 3], value);
        Assert.False(PayloadStageValidator.TryExtractTerminalByteArray(
            resource.AsSpan(0, resource.Length - 1),
            out _));
    }

    [Fact]
    public void InstructionTransactionRollsBackUncommittedChanges()
    {
        var instruction = Instruction.Create(OpCodes.Ldc_I4_0);
        using (var transaction = new InstructionMutationTransaction())
        {
            transaction.Capture(instruction);
            instruction.OpCode = OpCodes.Ldc_I4_1;
        }

        Assert.Equal(OpCodes.Ldc_I4_0, instruction.OpCode);
    }

    [Fact]
    public void StackAnalyzerFindsBalancedSyntheticMethod()
    {
        using var module = new ModuleDefUser("stack.dll") { Kind = ModuleKind.Dll };
        var method = new MethodDefUser(
            "Add",
            MethodSig.CreateStatic(
                module.CorLibTypes.Int32,
                module.CorLibTypes.Int32,
                module.CorLibTypes.Int32));
        method.Body = new CilBody();
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var result = EvaluationStackAnalyzer.Analyze(method);

        Assert.True(result.Valid);
        Assert.Equal(2, result.MaximumDepth);
    }

    /// <summary>
    /// The table naming the proxies is available to a reader before the pass that rewrites them runs.
    /// </summary>
    /// <remarks>
    /// The string table is read early, long before proxy dispatch is undone, so its interpreter walks
    /// into proxy fields the loader fills at run time and this run does not and stops on the null one
    /// holds. Rewriting the sites first would settle it, but that pass has to follow much of the
    /// pipeline, and moving it ahead of the loader-state census cost that census its static fields.
    /// The table itself has no such ordering: it falls out of interpreting the bootstrap, which is
    /// the pass before the string table.
    /// </remarks>
    [Fact]
    public void TheProxyTableIsPublishedBeforeAnyReaderNeedsIt()
    {
        var passes = CilantroPipeline.CreateDefaultPasses().Select(pass => pass.Name).ToList();
        var published = passes.IndexOf("method-body-recovery");
        Assert.InRange(published, 0, passes.Count - 1);
        foreach (var reader in new[] { "string-table-recovery", "string-table-relearning" })
            Assert.True(passes.IndexOf(reader) > published, $"{reader} runs before the table exists.");

        // The census whose static fields the reorder cost keeps its place ahead of the rewrite.
        Assert.True(
            passes.IndexOf("global-state-capture") < passes.IndexOf("delegate-proxy-analysis"),
            "The loader-state census now runs on a module whose proxies are already rewritten.");
    }

    /// <summary>
    /// A table naming something other than the proxy fields is not taken for the proxy map.
    /// </summary>
    [Fact]
    public void ALoaderTableIsOnlyReadAsTheProxyMapWhenItAccountsForEveryProxy()
    {
        using var module = ModuleDefMD.Load(typeof(ArchitectureTests).Module);
        var target = module.GetTypes()
            .SelectMany(type => type.Methods)
            .First(method => method.HasBody);
        var field = module.GetTypes().SelectMany(type => type.Fields).First();
        var proxyFields = new Dictionary<uint, FieldDef> { [field.MDToken.Raw] = field };
        var naming = (int field, int method) =>
            new Dictionary<uint, IReadOnlyDictionary<int, int>>
            {
                [0x04000001] = new Dictionary<int, int> { [field] = method }
            };

        Assert.True(ProxyLoaderTable.TryRead(
            module,
            naming((int)field.MDToken.Raw, (int)target.MDToken.Raw),
            proxyFields,
            out var bindings,
            out var source));
        Assert.Equal(target.MDToken.Raw, Assert.Single(bindings).TargetToken);
        Assert.Contains("04000001", source, StringComparison.Ordinal);

        // A key that is not one of the proxy fields, and a value that names no method of this module.
        Assert.False(ProxyLoaderTable.TryRead(
            module, naming(0x04FFFFFF, (int)target.MDToken.Raw), proxyFields, out _, out _));
        Assert.False(ProxyLoaderTable.TryRead(
            module, naming((int)field.MDToken.Raw, 0x06FFFFFF), proxyFields, out _, out _));

        // Two tables that both qualify leave nothing to choose between them, so neither is read.
        var ambiguous = new Dictionary<uint, IReadOnlyDictionary<int, int>>
        {
            [0x04000001] = new Dictionary<int, int>
                { [(int)field.MDToken.Raw] = (int)target.MDToken.Raw },
            [0x04000002] = new Dictionary<int, int>
                { [(int)field.MDToken.Raw] = (int)target.MDToken.Raw }
        };
        Assert.False(ProxyLoaderTable.TryRead(module, ambiguous, proxyFields, out _, out _));
    }
}
