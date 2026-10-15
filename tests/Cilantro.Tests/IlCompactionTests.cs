using Cilantro.Core;
using Cilantro.Core.Passes;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class IlCompactionTests
{
    [Fact]
    public void CollapsesFallThroughChainsButKeepsConditionalStackConsumption()
    {
        using var module = new ModuleDefUser();
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
        var padding = OpCodes.Nop.ToInstruction(); var finish = OpCodes.Ret.ToInstruction();
        foreach (var i in new[] { OpCodes.Nop.ToInstruction(), OpCodes.Br.ToInstruction(padding), padding,
            OpCodes.Br.ToInstruction(finish), finish }) method.Body.Instructions.Add(i);
        Assert.True(new StaticMachine().Execute(method).Succeeded);
        Assert.Equal(4, IlCompactionPass.Compact(method));
        Assert.Same(finish, Assert.Single(method.Body.Instructions));
        Assert.True(new StaticMachine().Execute(method).Succeeded);
        method.Body.Instructions.Clear();
        method.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
        method.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
        var conditional = OpCodes.Brtrue.ToInstruction(finish);
        method.Body.Instructions.Add(conditional); method.Body.Instructions.Add(finish);
        Assert.Equal(1, IlCompactionPass.Compact(method));
        Assert.Contains(conditional, method.Body.Instructions);
        Assert.True(new StaticMachine().Execute(method).Succeeded);
    }

    [Fact]
    public void PreservesSwitchEntriesAndResultsWhileRemovingPadding()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "App");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(method);
            var zero = OpCodes.Nop.ToInstruction(); var one = OpCodes.Nop.ToInstruction();
            foreach (var i in new[] { OpCodes.Nop.ToInstruction(), OpCodes.Ldarg_0.ToInstruction(),
                OpCodes.Switch.ToInstruction(new[] { zero, one, zero }), OpCodes.Ldc_I4_M1.ToInstruction(), OpCodes.Ret.ToInstruction(),
                zero, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ret.ToInstruction(), one, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ret.ToInstruction() })
                method.Body.Instructions.Add(i);
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        int Run(int value) => new StaticMachine().Execute(method, [StaticValue.FromInt32(value)]).Value.AsInt32();
        var before = new[] { -1, 0, 1, 2, 3 }.Select(Run).ToArray();
        Assert.Equal(3, new IlCompactionPass().Run(context).Changes);
        Assert.Equal(before, new[] { -1, 0, 1, 2, 3 }.Select(Run));
        var entries = (IList<Instruction>)method.Body.Instructions.Single(i => i.OpCode.Code == Code.Switch).Operand;
        Assert.Equal(3, entries.Count); Assert.Same(entries[0], entries[2]);
        Assert.Equal(0, new IlCompactionPass().Run(context).Changes);
        Assert.True(AssemblyVerifier.Verify(context.Module).Passed);
    }

    [Fact]
    public void KeepsSelfLoopsAndLeaveInstructions()
    {
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(new CorLibTypes(new ModuleDefUser()).Void)) { Body = new CilBody() };
        var pad = OpCodes.Nop.ToInstruction(); var loop = OpCodes.Br.ToInstruction(pad);
        method.Body.Instructions.Add(pad); method.Body.Instructions.Add(loop);
        Assert.Equal(1, IlCompactionPass.Compact(method));
        Assert.Same(loop, loop.Operand);
        var next = OpCodes.Ret.ToInstruction(); var leave = OpCodes.Leave.ToInstruction(next);
        method.Body.Instructions.Clear(); method.Body.Instructions.Add(leave); method.Body.Instructions.Add(next);
        Assert.Equal(0, IlCompactionPass.Compact(method));
        Assert.Equal(Code.Leave, leave.OpCode.Code);
    }

    [Fact]
    public void KeepsExceptionBoundariesAndTheirPredecessors()
    {
        using var module = new ModuleDefUser();
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Body = new CilBody() };
        var il = method.Body.Instructions;
        var first = OpCodes.Nop.ToInstruction(); var pad = OpCodes.Nop.ToInstruction(); var end = OpCodes.Nop.ToInstruction();
        var handler = OpCodes.Nop.ToInstruction(); var finish = OpCodes.Ret.ToInstruction();
        foreach (var i in new[] { first, pad, end, handler, OpCodes.Endfinally.ToInstruction(), finish }) il.Add(i);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
            { TryStart = first, TryEnd = handler, HandlerStart = handler, HandlerEnd = finish });
        Assert.Equal(1, IlCompactionPass.Compact(method));
        Assert.Contains(first, il); Assert.Contains(end, il); Assert.Contains(handler, il); Assert.Contains(finish, il);
    }
}
