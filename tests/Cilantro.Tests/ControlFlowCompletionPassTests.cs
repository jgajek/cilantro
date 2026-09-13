using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Analysis;
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

    /// <summary>
    /// A switch reached only by a jump from below it still folds, and the block it leaves behind
    /// is one a forward scan can name the stack at.
    /// </summary>
    /// <remarks>
    /// Walking back through the layout finds the push that feeds a switch only while the two are
    /// laid out in the order they run in. A dispatcher inside a handler is not: the block that
    /// assigns the state sits after the switch that reads it, so the state arrives by a jump
    /// backwards and the walk used to stop at the start of the block and fold nothing.
    ///
    /// What was left is worse than an unfolded switch. The block holding the switch is entered
    /// only by that backward jump, and the jump arrives with the state still on the stack, which
    /// ECMA-335 III.1.7.5 forbids: a block nothing falls into and only a backward branch reaches
    /// has to be entered with an empty stack, so that one forward pass can say what the stack
    /// holds everywhere. Nothing in the tool was asking, and the bodies it wrote were the
    /// unverifiable kind — nine findings across the three corpus libraries, in methods as ordinary
    /// as <c>Crypto::AesCbcEncrypt</c>, where the unprotected originals have none. Folding the
    /// switch takes the state off the stack and the constraint is met by consequence.
    /// </remarks>
    [Fact]
    public void FoldsASwitchWhoseStateArrivesByAJumpFromBelowIt()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var method = NewVoidMethod(module);
            var instructions = method.Body.Instructions;
            var end = Instruction.Create(OpCodes.Ret);
            var dispatch = Instruction.Create(OpCodes.Switch, new[] { end });
            var body = Instruction.Create(OpCodes.Nop);

            // The switch is jumped over, so nothing falls into it and the only way in is the jump
            // from below, which arrives holding the state.
            instructions.Add(Instruction.Create(OpCodes.Br, body));
            instructions.Add(dispatch);
            instructions.Add(Instruction.Create(OpCodes.Br, end));
            instructions.Add(body);
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            instructions.Add(Instruction.Create(OpCodes.Br, dispatch));
            instructions.Add(end);
            host.Methods.Add(method);
        });

        var result = new ControlFlowCompletionPass().Run(context);
        var method = SingleBodyMethod(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.DoesNotContain(
            method.Body.Instructions,
            instruction => instruction.OpCode == OpCodes.Switch);

        // Nothing is left pushing the state the switch used to read, which is what the backward
        // branch would otherwise arrive holding.
        Assert.DoesNotContain(method.Body.Instructions, instruction => instruction.IsLdcI4());
        Assert.True(
            EvaluationStackAnalyzer.Analyze(method) is { Valid: true },
            string.Join("; ", EvaluationStackAnalyzer.Analyze(method).Diagnostics));
    }

    /// <summary>
    /// A dispatcher whose state is assigned once collapses, loop and switch and comparison alike.
    /// </summary>
    /// <remarks>
    /// This is the shape a dispatcher is left in once its edges are direct: a local assigned a
    /// number, a switch over the local that no longer picks anything, and a comparison of the
    /// local against the number for one block deciding whether the loop goes round. Nothing could
    /// fold any of it while the local was opaque, and the reads are reached round a back edge, so
    /// no walk back through the layout reaches the assignment either. The whole of this method is
    /// one field store.
    /// </remarks>
    [Fact]
    public void CollapsesADispatcherWhoseStateIsAssignedOnce()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var method = NewVoidMethod(module);
            var state = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(state);
            var instructions = method.Body.Instructions;

            var store = Instruction.Create(OpCodes.Stloc, state);
            var read = Instruction.Create(OpCodes.Ldloc, state);
            var done = Instruction.Create(OpCodes.Ret);
            var work = Instruction.Create(OpCodes.Nop);

            instructions.Add(Instruction.Create(OpCodes.Br, work));
            instructions.Add(store);
            instructions.Add(read);
            instructions.Add(Instruction.Create(OpCodes.Switch, new[] { work }));
            instructions.Add(Instruction.Create(OpCodes.Ldloc, state));
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 9));
            instructions.Add(Instruction.Create(OpCodes.Beq, done));
            instructions.Add(Instruction.Create(OpCodes.Ldloc, state));
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 989));
            instructions.Add(Instruction.Create(OpCodes.Beq, read));
            instructions.Add(Instruction.Create(OpCodes.Br, done));
            instructions.Add(work);
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 9));
            instructions.Add(Instruction.Create(OpCodes.Br, store));
            instructions.Add(done);
            host.Methods.Add(method);
        });

        var result = new ControlFlowCompletionPass().Run(context);
        var method = SingleBodyMethod(context);

        Assert.Equal(PassStatus.Success, result.Status);
        var left = method.Body.Instructions
            .Where(instruction => instruction.OpCode != OpCodes.Nop)
            .ToArray();

        // Nothing reads the state, nothing switches on it, and nothing compares it.
        Assert.DoesNotContain(left, instruction => instruction.IsLdloc() || instruction.IsStloc());
        Assert.DoesNotContain(left, instruction => instruction.OpCode == OpCodes.Switch);
        Assert.DoesNotContain(left, instruction => instruction.OpCode == OpCodes.Beq);
        Assert.True(
            EvaluationStackAnalyzer.Analyze(method) is { Valid: true },
            string.Join("; ", EvaluationStackAnalyzer.Analyze(method).Diagnostics));
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
