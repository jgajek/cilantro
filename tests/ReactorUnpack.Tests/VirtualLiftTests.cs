using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers reading a recovered program back as IL, which is a report and never a rewrite.
/// </summary>
/// <remarks>
/// The programs here are written by hand rather than recovered from an engine, because what is
/// under test is the reading and not the recovery: a handwritten program can be given a jump table,
/// a call, and a deliberate contradiction, none of which a synthetic engine offers without becoming
/// a second implementation of the thing being tested.
/// </remarks>
public sealed class VirtualLiftTests
{
    private const int Push = 1;
    private const int Store = 2;
    private const int Load = 3;
    private const int Switch = 4;
    private const int Jump = 5;
    private const int Add = 6;
    private const int Mystery = 7;
    private const int Call = 8;

    /// <summary>
    /// A jump carrying a table of places is the operation that turns a flattened program back into
    /// blocks, and following every arm of it is the difference between reading a program and
    /// reading the handful of operations before its dispatcher.
    /// </summary>
    [Fact]
    public void AJumpCarryingATableOfPlacesIsReadAsASwitchAndAllOfItFollowed()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(7)),
            (Switch, new VirtualOperand.Table([3, 6])),
            (Jump, new VirtualOperand.Number(8)),
            (Push, new VirtualOperand.Number(1)),
            (Store, new VirtualOperand.Number(0)),
            (Jump, new VirtualOperand.Number(8)),
            (Push, new VirtualOperand.Number(2)),
            (Store, new VirtualOperand.Number(1)),
            (Push, new VirtualOperand.Number(3))
        ]);

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.Contains("switch     (3, 6)", lifted, StringComparison.Ordinal);
        Assert.Contains("reaches 9 of 9", lifted, StringComparison.Ordinal);
        Assert.Contains("at the same depth", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// An operation nothing established is written as what was counted about it. Rendering a guess
    /// in its place would be read as fact by everyone downstream of the file.
    /// </summary>
    [Fact]
    public void AnOperationWhoseMeaningIsUnknownIsMarkedRatherThanGuessedAt()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(7)),
            (Mystery, new VirtualOperand.None()),
            (Push, new VirtualOperand.Number(8))
        ]);

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.Contains("??         op 7", lifted, StringComparison.Ordinal);
        Assert.Contains("2 of 3 operations read as IL", lifted, StringComparison.Ordinal);
        Assert.Contains("an operation whose effect is unknown: 1", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// Two ways into the same place that disagree about how deep the stack is mean one of the
    /// readings is wrong, and the file has to say so: a listing that quietly picks one is a listing
    /// that has stopped being evidence.
    /// </summary>
    [Fact]
    public void TwoWaysIntoAPlaceThatDisagreeAboutTheStackAreReported()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(7)),
            (Switch, new VirtualOperand.Table([2, 3])),
            (Jump, new VirtualOperand.Number(4)),
            (Push, new VirtualOperand.Number(1)),
            (Store, new VirtualOperand.Number(0))
        ]);

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.Contains("two different depths", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// A call has no fixed arity, which is how it was recognized, but in any one place the method
    /// it names has a perfectly definite one. Reading it there is what lets the walk carry on
    /// through the calls instead of stopping at the first of them.
    /// </summary>
    [Fact]
    public void ACallTakesItsArityFromTheMethodItNames()
    {
        using var context = Module();
        var called = context.Module.Types
            .SelectMany(type => type.Methods)
            .First(method => method.Name == "Takes");
        var program = Program(context, [
            (Push, new VirtualOperand.Number(1)),
            (Push, new VirtualOperand.Number(2)),
            (Call, new VirtualOperand.Number(called.MDToken.ToInt32())),
            (Push, new VirtualOperand.Number(3)),
            (Store, new VirtualOperand.Number(0))
        ]);

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.Contains("call       ", lifted, StringComparison.Ordinal);
        Assert.Contains("Takes", lifted, StringComparison.Ordinal);
        Assert.Contains("reaches 5 of 5", lifted, StringComparison.Ordinal);
        Assert.Contains("at the same depth", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// An operation nothing could measure is still pinned by everything around it, and being able
    /// to say what it must do is the difference between checking most of a program and all of it.
    /// </summary>
    [Fact]
    public void AnOperationNothingMeasuredIsSolvedForFromTheRestOfTheProgram()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(5)),
            (Switch, new VirtualOperand.Table([6])),
            (Push, new VirtualOperand.Number(6)),
            (Mystery, new VirtualOperand.None()),
            (Jump, new VirtualOperand.Number(6)),
            (Push, new VirtualOperand.Number(0)),
            (Push, new VirtualOperand.Number(1))
        ]);

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.Contains("op 7 -1 on the stack", lifted, StringComparison.Ordinal);
        Assert.Contains("-1 on the stack, forced by the program", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// An operation two paths pin differently has not been solved for, and saying nothing is the
    /// only honest answer: a number that is wrong somewhere is worse than no number at all.
    /// </summary>
    [Fact]
    public void AnOperationThePathsPinTwoWaysIsLeftUnsolved()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(5)),
            (Switch, new VirtualOperand.Table([4, 6])),
            (Push, new VirtualOperand.Number(6)),
            (Jump, new VirtualOperand.Number(8)),
            (Mystery, new VirtualOperand.None()),
            (Jump, new VirtualOperand.Number(8)),
            (Mystery, new VirtualOperand.None()),
            (Push, new VirtualOperand.Number(1)),
            (Push, new VirtualOperand.Number(2))
        ]);

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.DoesNotContain("forced by the program", lifted, StringComparison.Ordinal);
    }

    private static VirtualProgram Program(
        ArtifactContext context,
        IReadOnlyList<(int Opcode, VirtualOperand Operand)> operations)
    {
        var stub = context.Module.Types.SelectMany(type => type.Methods).First(method => method.Name == "Stub");
        var method = new VirtualizedMethod(stub, stub, 0, 0);
        var instructions = operations
            .Select((operation, index) =>
                new VirtualInstruction(index, operation.Opcode, operation.Operand))
            .ToList();
        return new VirtualProgram(method, "Synthetic.Instruction", instructions)
        {
            Operations = new Dictionary<int, VirtualOperation>
            {
                [Push] = new(Push, 0, 1, "pushes its operand"),
                [Store] = new(Store, 1, 0, "stores where its operand indexes"),
                [Load] = new(Load, 0, 1, "loads what its operand indexes"),
                [Switch] = new(Switch, 1, 0, "branch if"),
                [Jump] = new(Jump, 0, 0, "branch"),
                [Add] = new(Add, 2, 1, "add"),
                [Call] = new(Call, 0, 0, "calls the method it names") { Measured = false }
            },
            TargetIsOperand = new HashSet<int> { Jump, Switch }
        };
    }

    /// <summary>A module with a stub to hang a program on and a method for a call to name.</summary>
    private static ArtifactContext Module() => SyntheticContext.Build(module =>
    {
        var type = SyntheticContext.AddType(module, "Held");
        type.Methods.Add(Empty(module, "Stub"));
        var takes = Empty(module, "Takes");
        takes.MethodSig.Params.Add(module.CorLibTypes.Int32);
        takes.MethodSig.Params.Add(module.CorLibTypes.Int32);
        takes.ParamDefs.Add(new ParamDefUser("left", 1));
        takes.ParamDefs.Add(new ParamDefUser("right", 2));
        type.Methods.Add(takes);
    });

    private static MethodDefUser Empty(ModuleDefUser module, string name)
    {
        var method = new MethodDefUser(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return method;
    }
}
