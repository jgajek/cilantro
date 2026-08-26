using System.Buffers.Binary;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
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
}
