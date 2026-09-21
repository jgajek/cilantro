using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace Cilantro.Tests;

public sealed class RecoveryEvidenceTests
{
    [Theory]
    [InlineData(false, false)] [InlineData(true, false)] [InlineData(false, true)]
    public void PublishedLiteralTableRejectsCallsAndEscapes(bool callAfterPublish, bool escape)
    {
        using var module = new ModuleDefUser("Fixture");
        var type = new TypeDefUser("Host", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(type);
        var field = new FieldDefUser("Table", new FieldSig(new SZArraySig(module.CorLibTypes.Int32)), FieldAttributes.Static | FieldAttributes.InitOnly);
        type.Fields.Add(field);
        var method = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
        type.Methods.Add(method);
        foreach (var i in new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef),
            OpCodes.Stsfld.ToInstruction(field), OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ldc_I4_0.ToInstruction(),
            OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Stelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction() }) method.Body.Instructions.Add(i);
        if (callAfterPublish) method.Body.Instructions.Insert(3, OpCodes.Call.ToInstruction(method));
        if (escape) {
            var getter = new MethodDefUser("Expose", MethodSig.CreateStatic(field.FieldType))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            getter.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); getter.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); type.Methods.Add(getter);
        }
        Assert.Equal(!callAfterPublish && !escape, NumericTableRecoveryPass.LiteralInitializerField(field));
    }

    [Fact]
    public void DifferentTerminalOutcomesCannotBeHiddenByOpaqueStaticState()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var field = new FieldDefUser("Opaque", new FieldSig(new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), FieldAttributes.Static);
            owner.Fields.Add(field);
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.GetTypeRef("System", "Exception"));
            foreach (var i in new[] { OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Stsfld.ToInstruction(field),
                OpCodes.Newobj.ToInstruction(ctor), OpCodes.Throw.ToInstruction() }) method.Body.Instructions.Add(i);
            owner.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var rebuilt = new CilBody();
        foreach (var i in method.Body.Instructions.Take(2)) rebuilt.Instructions.Add(new Instruction(i.OpCode, i.Operand));
        rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction());
        Assert.Equal(DevirtualizationCheck.Disagreed, RebuiltMethodTrial.Compare(context, method, rebuilt, 0).Verdict);
    }

    [Theory]
    [InlineData(-2147483648)] [InlineData(-1)] [InlineData(0)] [InlineData(1)] [InlineData(2147483647)]
    public void CompiledBranchMatchesBenignNativeOracle(int input)
    {
        using var module = ModuleDefMD.Load(typeof(Probe.RecoveryGroundTruth).Assembly.Location);
        var method = module.GetTypes().Single(t => t.FullName == "Probe.RecoveryGroundTruth").FindMethod("Branch");
        ControlFlowCompletionPass.TryComplete(method);
        DispatcherPathPass.Rewrite(method);
        var result = new StaticMachine().Execute(method, [StaticValue.FromInt32(input)]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(Probe.RecoveryGroundTruth.Branch(input), result.Value.AsInt32());
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(-3)]
    public void CompiledExceptionAndMutableArgumentMatchBenignNativeOracle(int divisor)
    {
        using var module = ModuleDefMD.Load(typeof(Probe.RecoveryGroundTruth).Assembly.Location);
        var method = module.GetTypes().Single(t => t.FullName == "Probe.RecoveryGroundTruth").FindMethod("Mutate");
        ControlFlowCompletionPass.TryComplete(method);
        var expectedBytes = new byte[] { 0, 1, 127, 255 };
        var machine = new StaticMachine();
        Assert.True(machine.State.Heap.TryAllocateByteArray(expectedBytes, out var argument));
        var expected = Probe.RecoveryGroundTruth.Mutate(expectedBytes, divisor);
        var result = machine.Execute(method, [argument, StaticValue.FromInt32(divisor)]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(expected, result.Value.AsInt32());
        Assert.Equal(expectedBytes, machine.State.Heap.GetArraySnapshot(argument)!.Select(v => (byte)v.AsInt32()).ToArray());
    }

    [Theory]
    [InlineData(3, false)]
    [InlineData(4, false)]
    [InlineData(3, true)]
    public void StreamTrialDetectsPositionMutation(int scenario, bool extraRead)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var reader = module.CorLibTypes.GetTypeRef("System.IO", "BinaryReader");
            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void,
                module.CorLibTypes.GetTypeRef("System.IO", "Stream").ToTypeSig()), reader);
            var read = new MemberRefUser(module, "ReadInt32", MethodSig.CreateInstance(module.CorLibTypes.Int32), reader);
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            foreach (var i in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Newobj.ToInstruction(ctor),
                OpCodes.Callvirt.ToInstruction(read), OpCodes.Ret.ToInstruction() }) method.Body.Instructions.Add(i);
            owner.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var rebuilt = new CilBody();
        foreach (var i in method.Body.Instructions) rebuilt.Instructions.Add(new Instruction(i.OpCode, i.Operand));
        if (extraRead) {
            rebuilt.Instructions.Insert(2, OpCodes.Dup.ToInstruction());
            rebuilt.Instructions.Insert(3, new Instruction(OpCodes.Callvirt, method.Body.Instructions[2].Operand));
            rebuilt.Instructions.Insert(4, OpCodes.Pop.ToInstruction());
        }
        Assert.Equal(extraRead ? DevirtualizationCheck.Disagreed : DevirtualizationCheck.Agreed,
            RebuiltMethodTrial.Compare(context, method, rebuilt, scenario).Verdict);
    }

    [Theory]
    [InlineData(Code.Shl)] [InlineData(Code.Shr)] [InlineData(Code.Shr_Un)]
    [InlineData(Code.Ceq)] [InlineData(Code.Clt)] [InlineData(Code.Clt_Un)]
    [InlineData(Code.Cgt)] [InlineData(Code.Cgt_Un)]
    public void DispatcherArithmeticMatchesOriginalAcrossBoundaryValues(Code operation)
    {
        foreach (var state in new[] { int.MinValue, -33, -1, 0, 1, 31, int.MaxValue })
        foreach (var operand in new[] { -1, 0, 1, 32, 33 })
        {
            using var module = new ModuleDefUser("Fixture");
            var type = new TypeDefUser("Host", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(type);
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            type.Methods.Add(method);
            var local = new Local(module.CorLibTypes.Int32); method.Body.Variables.Add(local);
            var head = OpCodes.Ldloc.ToInstruction(local);
            var first = OpCodes.Ldc_I4.ToInstruction(123);
            var second = OpCodes.Ldc_I4.ToInstruction(456);
            var op = operation switch { Code.Shl => OpCodes.Shl, Code.Shr => OpCodes.Shr, Code.Shr_Un => OpCodes.Shr_Un,
                Code.Ceq => OpCodes.Ceq, Code.Clt => OpCodes.Clt, Code.Clt_Un => OpCodes.Clt_Un,
                Code.Cgt => OpCodes.Cgt, _ => OpCodes.Cgt_Un };
            foreach (var i in new[] { OpCodes.Ldc_I4.ToInstruction(state), OpCodes.Stloc.ToInstruction(local),
                OpCodes.Br.ToInstruction(head), head, OpCodes.Ldc_I4.ToInstruction(operand), op.ToInstruction(),
                OpCodes.Switch.ToInstruction(new[] { first, second }), OpCodes.Ldc_I4_M1.ToInstruction(),
                OpCodes.Ret.ToInstruction(), first, OpCodes.Ret.ToInstruction(), second, OpCodes.Ret.ToInstruction() })
                method.Body.Instructions.Add(i);
            var before = new StaticMachine().Execute(method);
            Assert.Equal(StaticExecutionStatus.Completed, before.Status);
            Assert.Equal(1, DispatcherPathPass.Rewrite(method));
            var after = new StaticMachine().Execute(method);
            Assert.Equal(before.Status, after.Status); Assert.Equal(before.Value, after.Value);
        }
    }
}
