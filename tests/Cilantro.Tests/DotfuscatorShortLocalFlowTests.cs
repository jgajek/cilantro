using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorShortLocalFlowTests
{
    [Fact]
    public void ExceptionEntriesDoNotInheritTheNormalEdgeValue()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static)
            { Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(method); module.EntryPoint = method;
            var local = new Local(module.CorLibTypes.Int16); var result = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(local); method.Body.Variables.Add(result);
            var start = OpCodes.Ldnull.ToInstruction(); var handler = OpCodes.Pop.ToInstruction(); var exit = OpCodes.Ldloc.ToInstruction(result);
            foreach (var instruction in new[] { OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Stloc.ToInstruction(local), start,
                OpCodes.Throw.ToInstruction(), handler, OpCodes.Ldloca.ToInstruction(local), OpCodes.Ldind_I2.ToInstruction(),
                OpCodes.Stloc.ToInstruction(result), OpCodes.Leave.ToInstruction(exit), exit, OpCodes.Ret.ToInstruction() })
                method.Body.Instructions.Add(instruction);
            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = exit, CatchType = module.CorLibTypes.GetTypeRef("System", "Exception") });
        });
        var method = context.Module.EntryPoint; var before = MethodBodySnapshot.Capture(method);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        Assert.Equal(0, DotfuscatorShortLocalFlow.Rewrite(method));
        Assert.True(before.StructurallyEquals(method));
    }

    [Theory]
    [InlineData("branch", true)]
    [InlineData("same-join", true)]
    [InlineData("low-bits-join", true)]
    [InlineData("different-join", false)]
    [InlineData("missing-store", false)]
    [InlineData("unknown-store", false)]
    [InlineData("escaped", false)]
    [InlineData("loop", true)]
    public void OnlyClosedMustKnownShortStorageCanCrossBlocks(string shape, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Boolean),
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(method); module.EntryPoint = method;
            var local = new Local(module.CorLibTypes.Int16); method.Body.Variables.Add(local);
            var read = OpCodes.Ldloca.ToInstruction(local);
            var alternate = OpCodes.Nop.ToInstruction();
            void Add(params Instruction[] instructions) { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }
            var join = shape.Contains("join", StringComparison.Ordinal) || shape == "missing-store";
            if (join) Add(OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(alternate));
            Add(OpCodes.Ldc_I4.ToInstruction(65534), OpCodes.Stloc.ToInstruction(local));
            if (shape == "unknown-store") Add(OpCodes.Ldarg_0.ToInstruction(), OpCodes.Conv_I2.ToInstruction(), OpCodes.Stloc.ToInstruction(local));
            if (shape == "escaped") Add(OpCodes.Ldloca.ToInstruction(local), OpCodes.Call.ToInstruction(new MemberRefUser(module,
                "Mutate", MethodSig.CreateStatic(module.CorLibTypes.Void, new ByRefSig(module.CorLibTypes.Int16)),
                new TypeRefUser(module, "Foreign", "Api", new AssemblyRefUser("Foreign")))));
            Add(OpCodes.Br.ToInstruction(read));
            if (join)
            {
                Add(alternate);
                if (shape != "missing-store") Add(OpCodes.Ldc_I4.ToInstruction(shape == "different-join" ? 1 : shape == "low-bits-join" ? -2 : 65534),
                    OpCodes.Stloc.ToInstruction(local));
                Add(OpCodes.Br.ToInstruction(read));
            }
            if (shape == "loop")
            {
                var loop = OpCodes.Ldarg_0.ToInstruction();
                method.Body.Instructions[^1].Operand = loop;
                Add(loop, OpCodes.Brfalse.ToInstruction(read), OpCodes.Ldc_I4.ToInstruction(65534),
                    OpCodes.Stloc.ToInstruction(local), OpCodes.Br.ToInstruction(loop));
            }
            Add(read, OpCodes.Ldind_I2.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.EntryPoint;
        var before = MethodBodySnapshot.Capture(method);
        Assert.Equal(expected ? 1 : 0, DotfuscatorShortLocalFlow.Rewrite(method));
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        if (!expected) { Assert.True(before.StructurallyEquals(method)); return; }
        Assert.DoesNotContain(method.Body.Instructions, instruction => instruction.OpCode.Code == Code.Ldind_I2);
        Assert.Contains(method.Body.Instructions, instruction => instruction.IsStloc());
        var machine = new StaticMachine();
        machine.State.RegisterModuleMetadata(context.Module);
        var result = machine.Execute(method, [StaticValue.FromInt32(0)]);
        Assert.True(result.Succeeded, result.Diagnostic); Assert.Equal(-2, result.Value.AsInt32());
        Assert.Equal(0, DotfuscatorShortLocalFlow.Rewrite(method));
    }
}
