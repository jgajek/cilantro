using System.Buffers.Binary;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Payload;
using ReactorUnpack.Core.Strings;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Tests;

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
