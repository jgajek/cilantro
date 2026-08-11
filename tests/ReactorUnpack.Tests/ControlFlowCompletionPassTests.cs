using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Passes;

namespace ReactorUnpack.Tests;

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
            var instructions = method.Body.Instructions;
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
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
        Assert.Equal(2, result.Changes);
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
