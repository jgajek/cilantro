using System.Buffers.Binary;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Strings;

namespace Cilantro.Tests;

public sealed class VmStringRecoveryTests
{
    [Fact]
    public void StrictFramingConsumesTheWholeUtf16Table()
    {
        var first = Encoding.Unicode.GetBytes("alpha");
        var second = Encoding.Unicode.GetBytes("β");
        var bytes = new byte[sizeof(int) * 2 + first.Length + second.Length];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, first.Length);
        first.CopyTo(bytes.AsSpan(sizeof(int)));
        var secondOffset = sizeof(int) + first.Length;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(secondOffset), second.Length);
        second.CopyTo(bytes.AsSpan(secondOffset + sizeof(int)));

        Assert.True(StrictStringTable.TryDecodeComplete(bytes, out var records));
        Assert.Equal(["alpha", "β"], records.Select(record => record.Value));

        Assert.False(StrictStringTable.TryDecodeComplete([.. bytes, 0], out _));
        var invalidSurrogate = new byte[6];
        BinaryPrimitives.WriteInt32LittleEndian(invalidSurrogate, 2);
        BinaryPrimitives.WriteUInt16LittleEndian(invalidSurrogate.AsSpan(4), 0xD800);
        Assert.False(StrictStringTable.TryDecodeComplete(invalidSurrogate, out _));
    }

    [Fact]
    public void WhatAReadingMaySpendIsSetByTheTableItWasPointedAt()
    {
        // The cipher costs about eighty steps a byte, so a table has to be allowed that much to be
        // decrypted at all. A quarter-megabyte one measured at just under twenty-five million.
        var quarterMegabyte = StaticStringTableInterpreter.Reading(326_188);
        Assert.InRange(quarterMegabyte.MaximumSteps, 25_000_000, 400_000_000);

        // A table small enough to fit the old flat figure is still given it, so nothing that reads
        // today is given less than it had.
        var small = StaticStringTableInterpreter.Reading(1_024);
        Assert.Equal(4_000_000, small.MaximumSteps);
        Assert.Equal(4_000_000, StaticStringTableInterpreter.Reading(0).MaximumSteps);

        // And a larger table is allowed more, up to a ceiling that holds however large it claims to
        // be, so a length read out of a hostile file cannot ask for an unbounded run.
        Assert.True(
            StaticStringTableInterpreter.Reading(1_000_000).MaximumSteps >
            quarterMegabyte.MaximumSteps);
        Assert.Equal(400_000_000, StaticStringTableInterpreter.Reading(int.MaxValue).MaximumSteps);

        // The rest of the machine is left exactly as it was; only the step ceiling moves.
        Assert.Equal(96, quarterMegabyte.MaximumRecursionDepth);
        Assert.Equal(64 * 1024 * 1024, quarterMegabyte.MaximumAllocatedBytes);
    }

    [Theory]
    [InlineData(StaticStringTableInterpreter.VmMeaning.ShiftRight, -128, 2, -32)]
    [InlineData(StaticStringTableInterpreter.VmMeaning.ShiftLeft, 3, 4, 48)]
    [InlineData(StaticStringTableInterpreter.VmMeaning.ExclusiveOr, 0x55, 0x0F, 0x5A)]
    [InlineData(StaticStringTableInterpreter.VmMeaning.Subtract, 191, 63, 128)]
    [InlineData(StaticStringTableInterpreter.VmMeaning.Add, 53, 28, 81)]
    internal void EachArithmeticMeaningComputesTheArithmeticItNames(
        StaticStringTableInterpreter.VmMeaning meaning,
        long left,
        long right,
        long expected)
    {
        Assert.True(StaticStringTableInterpreter.TryEvaluateVmIntegerBinary(
            meaning, left, right, out var result));
        Assert.Equal(expected, result);
    }

    [Fact]
    public void MeaningsThatAreNotArithmeticAreNotGivenArithmetic()
    {
        Assert.False(StaticStringTableInterpreter.TryEvaluateVmIntegerBinary(
            StaticStringTableInterpreter.VmMeaning.Return, 1, 2, out _));
    }

    [Fact]
    public void SerializedVmReturnSentinelTerminatesAfterDispatcherIncrement()
    {
        Assert.True(StaticStringTableInterpreter.TryEvaluateVmControlFlow(
            StaticStringTableInterpreter.VmMeaning.Return, out var handlerPointer, out var returns));
        Assert.Equal(-3, handlerPointer);
        Assert.Equal(-2, handlerPointer + 1);
        Assert.True(returns);

        Assert.False(StaticStringTableInterpreter.TryEvaluateVmControlFlow(
            StaticStringTableInterpreter.VmMeaning.Branch, out _, out _));
    }

    [Fact]
    public void StringOffsetSlicePropagatesLocalsAndArithmetic()
    {
        var method = CreateSliceMethod();
        method.Body.Instructions.Add(Instruction.CreateLdcI4(37));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
        method.Body.Instructions.Add(Instruction.CreateLdcI4(5));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));

        Assert.True(StringOffsetSlicer.TryEvaluate(
            method, method.Body.Instructions.Count, new Dictionary<uint, int>(),
            out var value, out var diagnostic), diagnostic);
        Assert.Equal(32, value);
    }

    [Fact]
    public void StringOffsetSliceRejectsAmbiguousLocalDefinitions()
    {
        var method = CreateSliceMethod();
        method.Body.Instructions.Add(Instruction.CreateLdcI4(1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));
        method.Body.Instructions.Add(Instruction.CreateLdcI4(2));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));

        Assert.False(StringOffsetSlicer.TryEvaluate(
            method, method.Body.Instructions.Count, new Dictionary<uint, int>(),
            out _, out var diagnostic));
        Assert.Contains("distinct reaching constants", diagnostic, StringComparison.Ordinal);
    }

    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
    public void QbjuefSerializedVmCapturesUniqueTableAndRewritesEverySiteAtomically()
    {
        var reportDirectory = Path.Combine(
            Path.GetTempPath(), $"Cilantro.VmStrings.{Guid.NewGuid():N}");
        try
        {
            var result = new CilantroPipeline().Run(
                Checkout.Sample("Qbjuef.exe"),
                new PipelineOptions(AnalyzeOnly: true, ReportDirectory: reportDirectory));

            var capture = Assert.Single(
                result.Report.Passes,
                pass => pass.Pass == "string-table-recovery");
            Assert.Equal(PassStatus.Success, capture.Status);
            Assert.Equal(0, capture.Changes);
            Assert.Contains(capture.Diagnostics,
                diagnostic =>
                    diagnostic.Contains(
                        "Captured 11 strings",
                        StringComparison.Ordinal));
            Assert.Contains(capture.Diagnostics,
                diagnostic => diagnostic.Contains(
                    "Accounted for all 12 direct resolver use(s)",
                    StringComparison.Ordinal));
            var rewrite = Assert.Single(
                result.Report.Passes,
                pass => pass.Pass == "string-recovery");
            Assert.Equal(PassStatus.Success, rewrite.Status);
            Assert.Equal(12, rewrite.Changes);
            Assert.Contains(rewrite.Diagnostics,
                diagnostic => diagnostic.Contains(
                    "Atomically restored all 12 proven string sites",
                    StringComparison.Ordinal));
        }
        finally
        {
            if (Directory.Exists(reportDirectory))
                Directory.Delete(reportDirectory, true);
        }
    }

    private static MethodDefUser CreateSliceMethod()
    {
        var module = new ModuleDefUser("slice.dll");
        var type = new TypeDefUser("Tests", "Slice", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var method = new MethodDefUser(
            "slice", MethodSig.CreateStatic(module.CorLibTypes.Void));
        type.Methods.Add(method);
        method.Body = new CilBody();
        method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
        return method;
    }
}
