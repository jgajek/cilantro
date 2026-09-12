using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Passes;

namespace Cilantro.Tests;

public sealed class ControlFlowCompletionPassTests
{
    [Fact]
    public void FoldsTakenOpaquePredicateAndDeletesGuardedCode()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var method = NewVoidMethod(module);
            var instructions = method.Body.Instructions;
            var end = Instruction.Create(OpCodes.Ret);
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            instructions.Add(Instruction.Create(OpCodes.Brtrue, end));
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4_7));
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4_8));
            instructions.Add(end);
            host.Methods.Add(method);
        });

        var result = new ControlFlowCompletionPass().Run(context);
        var method = SingleBodyMethod(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(3, result.Changes);
        Assert.DoesNotContain(method.Body.Instructions,
            instruction => instruction.IsLdcI4() && instruction.GetLdcI4Value() == 7);
        Assert.DoesNotContain(method.Body.Instructions,
            instruction => instruction.IsLdcI4() && instruction.GetLdcI4Value() == 8);
        Assert.Equal(OpCodes.Ret, method.Body.Instructions[^1].OpCode);
    }

    [Fact]
    public void DropsBranchThatIsNeverTakenAndItsTarget()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var method = NewVoidMethod(module);
            var instructions = method.Body.Instructions;
            var deadTarget = Instruction.Create(OpCodes.Ldc_I4_8);
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            instructions.Add(Instruction.Create(OpCodes.Brtrue, deadTarget));
            instructions.Add(Instruction.Create(OpCodes.Ret));
            instructions.Add(deadTarget);
            instructions.Add(Instruction.Create(OpCodes.Ret));
            host.Methods.Add(method);
        });

        var result = new ControlFlowCompletionPass().Run(context);
        var method = SingleBodyMethod(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(3, result.Changes);
        Assert.DoesNotContain(method.Body.Instructions,
            instruction => instruction.OpCode.Code is Code.Brtrue or Code.Brtrue_S);
        Assert.DoesNotContain(method.Body.Instructions,
            instruction => instruction.IsLdcI4() && instruction.GetLdcI4Value() == 8);
    }

    [Fact]
    public void RemovesCodeAfterUnconditionalBranch()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var method = NewVoidMethod(module);
            var instructions = method.Body.Instructions;
            var end = Instruction.Create(OpCodes.Ret);
            instructions.Add(Instruction.Create(OpCodes.Br, end));
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4_3));
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4_4));
            instructions.Add(end);
            host.Methods.Add(method);
        });

        var result = new ControlFlowCompletionPass().Run(context);
        var method = SingleBodyMethod(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(2, result.Changes);
        Assert.Equal(2, method.Body.Instructions.Count);
    }

    [Fact]
    public void LeavesCleanMethodUntouched()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var method = NewVoidMethod(module);
            var kept = new Local(module.CorLibTypes.Int32);
            var also = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(kept);
            method.Body.Variables.Add(also);
            var instructions = method.Body.Instructions;
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            instructions.Add(Instruction.Create(OpCodes.Stloc, kept));
            instructions.Add(Instruction.Create(OpCodes.Ldloc, kept));
            instructions.Add(Instruction.Create(OpCodes.Stloc, also));
            instructions.Add(Instruction.Create(OpCodes.Ldloc, also));
            instructions.Add(Instruction.Create(OpCodes.Stloc, kept));
            instructions.Add(Instruction.Create(OpCodes.Ret));
            host.Methods.Add(method);
        });

        var result = new ControlFlowCompletionPass().Run(context);
        var method = SingleBodyMethod(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Equal(7, method.Body.Instructions.Count);
    }

    /// <summary>
    /// A value thrown away is removed along with the arithmetic that worked it out.
    /// </summary>
    /// <remarks>
    /// Reactor computes numbers nothing uses, and this tool leaves the store of a dispatcher's
    /// state behind when it makes one of that dispatcher's edges direct. Both end up as a value
    /// produced and dropped, and neither is dismissable at a glance by a reader: one prints as a
    /// discarded expression, the other as a named local holding a number.
    /// </remarks>
    [Fact]
    public void RemovesAValueWorkedOutAndThrownAway()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var method = NewVoidMethod(module);
            var unread = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(unread);
            var instructions = method.Body.Instructions;
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x306B51E));
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x306B178));
            instructions.Add(Instruction.Create(OpCodes.Xor));
            instructions.Add(Instruction.Create(OpCodes.Stloc, unread));
            instructions.Add(Instruction.Create(OpCodes.Ret));
            host.Methods.Add(method);
        });

        var result = new ControlFlowCompletionPass().Run(context);
        var method = SingleBodyMethod(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(4, result.Changes);
        Assert.Equal(
            OpCodes.Ret,
            Assert.Single(method.Body.Instructions, item => item.OpCode != OpCodes.Nop).OpCode);
    }

    /// <summary>
    /// A discarded value is left alone when working it out could matter for another reason.
    /// </summary>
    /// <remarks>
    /// Reading a static field can run a type initializer, which is a consequence the discard of
    /// its result says nothing about. The same goes for a call, a load through a pointer and a
    /// conversion that checks its range, so the walk stops at all of them.
    /// </remarks>
    [Fact]
    public void KeepsADiscardedValueWhoseWorkingOutCouldMatter()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var watched = new FieldDefUser(
                "Watched",
                new FieldSig(module.CorLibTypes.Int32),
                FieldAttributes.Public | FieldAttributes.Static);
            host.Fields.Add(watched);
            var method = NewVoidMethod(module);
            var instructions = method.Body.Instructions;
            instructions.Add(Instruction.Create(OpCodes.Ldsfld, watched));
            instructions.Add(Instruction.Create(OpCodes.Pop));
            instructions.Add(Instruction.Create(OpCodes.Ret));
            host.Methods.Add(method);
        });

        var result = new ControlFlowCompletionPass().Run(context);
        var method = SingleBodyMethod(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Equal(3, method.Body.Instructions.Count);
    }

    [Fact]
    public void PreservesExceptionHandlerBoundariesWhileRemovingDeadCode()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var method = NewVoidMethod(module);
            var instructions = method.Body.Instructions;
            var end = Instruction.Create(OpCodes.Ret);
            var handlerStart = Instruction.Create(OpCodes.Pop);
            var tryStart = Instruction.Create(OpCodes.Ldc_I4_1);
            instructions.Add(tryStart);
            instructions.Add(Instruction.Create(OpCodes.Pop));
            instructions.Add(Instruction.Create(OpCodes.Leave, end));
            instructions.Add(handlerStart);
            instructions.Add(Instruction.Create(OpCodes.Leave, end));
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)9));
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4_6));
            instructions.Add(end);
            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                CatchType = module.CorLibTypes.Object.TypeDefOrRef,
                TryStart = tryStart,
                TryEnd = handlerStart,
                HandlerStart = handlerStart,
                HandlerEnd = end,
            });
            host.Methods.Add(method);
        });

        var result = new ControlFlowCompletionPass().Run(context);
        var method = SingleBodyMethod(context);

        Assert.Equal(PassStatus.Success, result.Status);
        // Two unreachable instructions after the handler, and the constant pushed and dropped
        // inside the guarded region, which is two more.
        Assert.Equal(4, result.Changes);
        var handler = Assert.Single(method.Body.ExceptionHandlers);
        Assert.Contains(handler.TryStart, method.Body.Instructions);
        Assert.Contains(handler.TryEnd, method.Body.Instructions);
        Assert.Contains(handler.HandlerStart, method.Body.Instructions);
        Assert.Contains(handler.HandlerEnd, method.Body.Instructions);
        Assert.DoesNotContain(method.Body.Instructions,
            instruction => instruction.IsLdcI4() && instruction.GetLdcI4Value() == 9);
    }

    private static MethodDefUser NewVoidMethod(ModuleDef module) =>
        new("Method", MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody { KeepOldMaxStack = true, MaxStack = 8 }
        };

    private static MethodDef SingleBodyMethod(ArtifactContext context) =>
        context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Single(method => method.Name == "Method");
}
