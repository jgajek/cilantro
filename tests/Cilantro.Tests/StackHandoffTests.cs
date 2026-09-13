using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Tests;

public sealed class StackHandoffTests
{
    /// <summary>
    /// The value a conditional branch hands over is under the condition, so the store goes on the
    /// far side of the branch and the path that does not take it jumps over.
    /// </summary>
    /// <remarks>
    /// Putting it there rather than in a block at the end of the body is what keeps the repair
    /// inside whatever protected region the edge was already crossing: a `br` out of a try is
    /// invalid IL, and a block appended after the last instruction is outside every clause that
    /// runs to the end of the method.
    /// </remarks>
    [Fact]
    public void ReachesUnderAConditionByStoringOnTheFarSideOfTheBranch()
    {
        using var module = new ModuleDefUser("handoff.dll");
        var method = Dispatching(module, out var head);

        Assert.Single(ForwardScan.Unnamed(method));
        Assert.True(StackHandoff.Repair(method, head));

        Assert.Equal(0, ForwardScan.Unnameable(method));
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        Assert.Equal(
            new[] { Code.Ldloc, Code.Switch },
            method.Body.Instructions
                .SkipWhile(instruction => instruction.OpCode.Code != Code.Ldloc)
                .Take(2)
                .Select(instruction => instruction.OpCode.Code));

        // The branch goes to the store; what follows the branch is the jump that carries the path it
        // did not take over the store, and it lands where it used to fall.
        var branch = method.Body.Instructions.Single(
            instruction => instruction.OpCode.Code == Code.Brtrue);
        var at = method.Body.Instructions.IndexOf(branch);
        Assert.Same(method.Body.Instructions[at + 2], branch.Operand);
        Assert.Equal(Code.Br, method.Body.Instructions[at + 1].OpCode.Code);
        Assert.Equal(Code.Stloc, method.Body.Instructions[at + 2].OpCode.Code);
        Assert.Equal(Code.Pop, ((Instruction)method.Body.Instructions[at + 1].Operand).OpCode.Code);
    }

    /// <summary>
    /// An unconditional branch has nothing above the value, so the store goes in front of it.
    /// </summary>
    [Fact]
    public void StoresInFrontOfAnUnconditionalBranch()
    {
        using var module = new ModuleDefUser("handoff.dll");
        var method = Jumping(module, out var head);

        Assert.Single(ForwardScan.Unnamed(method));
        Assert.True(StackHandoff.Repair(method, head));

        Assert.Equal(0, ForwardScan.Unnameable(method));
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        var branch = method.Body.Instructions.Single(
            instruction => instruction.OpCode.Code == Code.Br &&
                           instruction.Operand is Instruction { OpCode.Code: Code.Ldloc });
        var at = method.Body.Instructions.IndexOf(branch);
        Assert.Equal(Code.Stloc, method.Body.Instructions[at - 1].OpCode.Code);
        var reload = (Instruction)branch.Operand;
        Assert.Same(head, method.Body.Instructions[method.Body.Instructions.IndexOf(reload) + 1]);
    }

    /// <summary>
    /// A head that begins a clause is left alone: what a handler is entered holding is the runtime's
    /// to say, and a reload in front of it would be outside the clause it belongs to.
    /// </summary>
    [Fact]
    public void LeavesAloneAHeadWhereAClauseBegins()
    {
        using var module = new ModuleDefUser("handoff.dll");
        var method = Dispatching(module, out var head);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
        {
            TryStart = head,
            TryEnd = method.Body.Instructions[^1],
            HandlerStart = method.Body.Instructions[^1],
            HandlerEnd = null
        });

        Assert.False(StackHandoff.Repair(method, head));
        Assert.Single(ForwardScan.Unnamed(method));
    }

    /// <summary>
    /// And a head whose value nothing names is left alone rather than given a local of a guessed
    /// type: what takes the value says what it is, and an `add` does not say.
    /// </summary>
    [Fact]
    public void LeavesAloneAHeadThatDoesNotSayWhatItTakes()
    {
        using var module = new ModuleDefUser("handoff.dll");
        var method = Jumping(module, out var head);
        head.OpCode = OpCodes.Not;
        head.Operand = null;

        Assert.False(StackHandoff.Repair(method, head));
    }

    /// <summary>
    /// A dispatcher reached only from below by a conditional branch, with the state pushed.
    /// </summary>
    private static MethodDefUser Dispatching(ModuleDef module, out Instruction head)
    {
        var method = Hosting(module);
        var instructions = method.Body.Instructions;
        var done = Instruction.Create(OpCodes.Ret);
        var work = Instruction.Create(OpCodes.Nop);
        head = Instruction.Create(OpCodes.Switch, new[] { done, work });

        instructions.Add(Instruction.Create(OpCodes.Br, work));
        instructions.Add(head);
        instructions.Add(done);
        instructions.Add(work);
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        instructions.Add(Instruction.Create(OpCodes.Brtrue, head));
        instructions.Add(Instruction.Create(OpCodes.Pop));
        instructions.Add(Instruction.Create(OpCodes.Br, done));
        return method;
    }

    /// <summary>
    /// The same, reached by an unconditional branch, and storing what it is handed.
    /// </summary>
    private static MethodDefUser Jumping(ModuleDef module, out Instruction head)
    {
        var method = Hosting(module);
        var state = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(state);
        var instructions = method.Body.Instructions;
        var done = Instruction.Create(OpCodes.Ret);
        var work = Instruction.Create(OpCodes.Nop);
        head = Instruction.Create(OpCodes.Stloc, state);

        instructions.Add(Instruction.Create(OpCodes.Br, work));
        instructions.Add(head);
        instructions.Add(Instruction.Create(OpCodes.Br, done));
        instructions.Add(done);
        instructions.Add(work);
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        instructions.Add(Instruction.Create(OpCodes.Br, head));
        return method;
    }

    private static MethodDefUser Hosting(ModuleDef module)
    {
        var assembly = new AssemblyDefUser("handoff", new Version(1, 0));
        if (assembly.Modules.Count == 0 && module.Assembly is null)
            assembly.Modules.Add(module);
        var type = module.Types.FirstOrDefault(candidate => candidate.Name == "Host");
        if (type is null)
        {
            type = new TypeDefUser("", "Host", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);
        }

        var method = new MethodDefUser(
            $"Flattened{type.Methods.Count}",
            MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32),
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        type.Methods.Add(method);
        return method;
    }
}
