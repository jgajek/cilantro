using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

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
    private const int Throw = 9;
    private const int Make = 10;
    private const int Element = 11;

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
    /// An engine watched performing a call has measured the method rather than the operation, so an
    /// operation whose every operand names a method is read as a call and each site given the arity
    /// of the method there. Carrying the one measurement to every site instead reads the rest of
    /// them wrong, which is what happened in the middle of a protector's own signature check.
    /// </summary>
    [Fact]
    public void AnOperationWhoseEveryOperandNamesAMethodIsReadAsACallOfIt()
    {
        using var context = Module();
        var methods = context.Module.Types.SelectMany(type => type.Methods).ToArray();
        var takes = methods.First(method => method.Name == "Takes");
        var gives = methods.First(method => method.Name == "Gives");
        var program = Measured(
            Program(context, [
                (Push, new VirtualOperand.Number(1)),
                (Push, new VirtualOperand.Number(2)),
                (Mystery, new VirtualOperand.Number(takes.MDToken.ToInt32())),
                (Mystery, new VirtualOperand.Number(gives.MDToken.ToInt32())),
                (Store, new VirtualOperand.Number(0))
            ]),
            pops: 0,
            pushes: 1);

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.Contains(
            "1 operation(s) are read as calls of the method they name",
            lifted,
            StringComparison.Ordinal);
        Assert.Contains("call       ", lifted, StringComparison.Ordinal);
        Assert.Contains("reaches 5 of 5", lifted, StringComparison.Ordinal);
        Assert.Contains("at the same depth", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// The names alone are not enough. Where no method the operation names would leave the stack the
    /// way the operation was watched leaving it, the operation is something else that happens to
    /// carry a token, and it stays unread.
    /// </summary>
    [Fact]
    public void AnOperationNoMethodItNamesAccountsForIsNotReadAsACall()
    {
        using var context = Module();
        var methods = context.Module.Types.SelectMany(type => type.Methods).ToArray();
        var takes = methods.First(method => method.Name == "Takes");
        var gives = methods.First(method => method.Name == "Gives");
        var program = Measured(
            Program(context, [
                (Push, new VirtualOperand.Number(1)),
                (Push, new VirtualOperand.Number(2)),
                (Mystery, new VirtualOperand.Number(takes.MDToken.ToInt32())),
                (Mystery, new VirtualOperand.Number(gives.MDToken.ToInt32())),
                (Store, new VirtualOperand.Number(0))
            ]),
            pops: 2,
            pushes: 1);

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.DoesNotContain("read as calls of the method they name", lifted, StringComparison.Ordinal);
        Assert.Contains("??         op 7", lifted, StringComparison.Ordinal);
    }

    /// <summary>The same program with the mystery operation watched taking and leaving what it says.</summary>
    private static VirtualProgram Measured(VirtualProgram program, int pops, int pushes) =>
        program with
        {
            Operations = new Dictionary<int, VirtualOperation>(program.Operations)
            {
                [Mystery] = new(Mystery, pops, pushes, null)
            }
        };

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

    /// <summary>
    /// An operation the walk never arrives at is either dead code or somewhere the reading cannot
    /// yet go, and which of the two it is decides whether the listing is complete. Where the walk
    /// was never once at a loss, it followed everything there was to follow, and what is left over
    /// is unreachable — a fact about the program rather than a hole in the report.
    /// </summary>
    [Fact]
    public void WhatNoPathArrivesAtIsCalledDeadWhereTheWalkWasNeverAtALoss()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(5)),
            (Jump, new VirtualOperand.Number(3)),
            (Push, new VirtualOperand.Number(9)),
            (Push, new VirtualOperand.Number(1))
        ]);

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.Contains("reaches 3 of 4", lifted, StringComparison.Ordinal);
        Assert.Contains("1 operation(s) nothing in the program reaches", lifted, StringComparison.Ordinal);
        Assert.DoesNotContain("no path arrives at", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// Where the walk did stop somewhere, what it did not arrive at may only be past the place it
    /// stopped, and calling that dead would be claiming a completeness the reading does not have.
    /// </summary>
    [Fact]
    public void WhatNoPathArrivesAtIsLeftOpenWhereTheWalkStopped()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(5)),
            (Mystery, new VirtualOperand.None()),
            (Jump, new VirtualOperand.Number(4)),
            (Push, new VirtualOperand.Number(9)),
            (Push, new VirtualOperand.Number(1))
        ]);

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.Contains("no path arrives at", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// A handler is entered by a throw with the exception on the stack, which no ordinary path
    /// models, so the operations it covers are reached no other way. The region says which places
    /// it covers without saying what each of them is, and the walk decides that for itself: the
    /// place nothing else arrives at is walked as a handler, and kept because the depths agree.
    /// </summary>
    [Fact]
    public void WhatOnlyAThrowArrivesAtIsWalkedAsAHandler()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(5)),
            (Store, new VirtualOperand.Number(0)),
            (Jump, new VirtualOperand.Number(5)),
            (Store, new VirtualOperand.Number(1)),
            (Jump, new VirtualOperand.Number(5)),
            (Push, new VirtualOperand.Number(9))
        ]) with
        {
            Regions = [new VirtualRegion([3, 4], 0, null)]
        };

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.Contains("reaches 6 of 6", lifted, StringComparison.Ordinal);
        Assert.Contains(
            "1 place(s) a guarded region covers are walked as handlers as well, entered with the " +
                "exception on the stack: 3",
            lifted,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A region's places are not labelled, so one of them is where the try begins rather than the
    /// handler, and entering that with an exception on the stack would put a value in the listing
    /// that is not there. The walk only keeps an entry the rest of the program agrees with.
    /// </summary>
    [Fact]
    public void APlaceTheWalkAlreadyArrivesAtIsNotEnteredAsAHandler()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(5)),
            (Store, new VirtualOperand.Number(0)),
            (Push, new VirtualOperand.Number(7))
        ]) with
        {
            Regions = [new VirtualRegion([1, 2], 0, null)]
        };

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.Contains("reaches 3 of 3", lifted, StringComparison.Ordinal);
        Assert.DoesNotContain("walked as handlers", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// An operation that throws ends the path it is on. Reading it as one that merely takes a value
    /// would walk the operations after it as though a throw had not happened.
    /// </summary>
    [Fact]
    public void AThrowIsWrittenAsOneAndEndsThePathItIsOn()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(5)),
            (Throw, new VirtualOperand.None()),
            (Push, new VirtualOperand.Number(7))
        ]);

        var lifted = string.Join("\n", VirtualLift.Render(program, context.Module));

        Assert.Contains("throw", lifted, StringComparison.Ordinal);
        Assert.Contains(
            "1 operation(s) nothing in the program reaches", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// Where a clause was found paired with what holds it, the listing says which range is the try
    /// and which the handler rather than giving the numbers in the order the engine keeps them.
    /// </summary>
    [Fact]
    public void APairedRegionIsSaidAsATryAndAHandler()
    {
        var told = new VirtualRegion([3, 4], 0, "System.Exception")
        {
            Guarded = (1, 2),
            Handled = (3, 4)
        };

        Assert.Equal(
            "operations 1-2 guarded, handled at 3-4, kind 0, catching System.Exception",
            told.Describe());
        Assert.Equal(
            "over operations 3, 4, kind 0, catching System.Exception",
            new VirtualRegion([3, 4], 0, "System.Exception").Describe());
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
                [Call] = new(Call, 0, 0, "calls the method it names") { Measured = false },
                [Throw] = new(Throw, 1, 0, VirtualSemantics.Throwing),

                // A measured operation that leaves an array but the trials could not name, and one
                // the trials never measured at all but marked as wanting an array beneath an index.
                [Make] = new(Make, 1, 1, null) { Pushed = "System.Int32[]" },
                [Element] = new(Element, 0, 0, null)
                {
                    Measured = false,
                    Needs = "an array beneath an index"
                }
            },
            TargetIsOperand = new HashSet<int> { Jump, Switch }
        };
    }

    /// <summary>A module with a stub to hang a program on and a method for a call to name.</summary>
    /// <summary>
    /// An operation nothing could perform is still readable where the program pins its effect and
    /// its operand names a field: one takes a value and leaves nothing, the other says where the
    /// value went, and neither says it alone.
    /// </summary>
    [Fact]
    public void AnOperationTheProgramPinsAndWhoseOperandNamesAFieldIsReadAsAStore()
    {
        using var context = Module();
        var field = context.Module.Types
            .SelectMany(type => type.Fields)
            .First(one => one.Name == "Kept");
        var program = Program(context, [
            (Push, new VirtualOperand.Number(5)),
            (Switch, new VirtualOperand.Table([6])),
            (Push, new VirtualOperand.Number(6)),
            (Mystery, new VirtualOperand.Number(field.MDToken.ToInt32())),
            (Jump, new VirtualOperand.Number(6)),
            (Push, new VirtualOperand.Number(0)),
            (Push, new VirtualOperand.Number(1))
        ]);

        var settled = VirtualProgramRecovery.Settled(program, context.Module);
        var lifted = string.Join(
            "\n",
            VirtualLift.Render(program with { Operations = settled }, context.Module));

        Assert.Equal("writes the static field it names", settled[Mystery].Name);
        Assert.Contains("stsfld", lifted, StringComparison.Ordinal);
        Assert.Contains("7 of 7 operations read as IL", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// The same operand, where nothing pins the operation's effect, says nothing: an operation
    /// naming a field could as easily be reading it as writing it.
    /// </summary>
    [Fact]
    public void AnOperationNamingAFieldIsNotReadAsAStoreOnTheNameAlone()
    {
        using var context = Module();
        var field = context.Module.Types
            .SelectMany(type => type.Fields)
            .First(one => one.Name == "Kept");
        var program = Program(context, [
            (Push, new VirtualOperand.Number(7)),
            (Mystery, new VirtualOperand.Number(field.MDToken.ToInt32())),
            (Push, new VirtualOperand.Number(8))
        ]);

        var settled = VirtualProgramRecovery.Settled(program, context.Module);

        Assert.False(settled.TryGetValue(Mystery, out var read) && read.Identified);
    }

    /// <summary>
    /// An operation that leaves an array of the very type its operand names is making that array,
    /// however the framework built it out of sight of the watching: the type it names and the type
    /// of array it leaves are the same, which no operation that merely mentioned one would arrange.
    /// </summary>
    [Fact]
    public void AnOperationLeavingAnArrayOfTheTypeItNamesIsReadAsMakingOne()
    {
        using var context = Module();
        var held = context.Module.Types.First(one => one.Name == "Held");
        var program = Program(context, [
            (Push, new VirtualOperand.Number(4)),
            (Make, new VirtualOperand.Number(held.MDToken.ToInt32()))
        ]);
        program = program with
        {
            Operations = new Dictionary<int, VirtualOperation>(program.Operations)
            {
                [Make] = new(Make, 1, 1, null) { Pushed = held.FullName + "[]" }
            }
        };

        var settled = VirtualProgramRecovery.Settled(program, context.Module);
        var lifted = string.Join(
            "\n",
            VirtualLift.Render(program with { Operations = settled }, context.Module));

        Assert.Equal("makes an array of the type it names", settled[Make].Name);
        Assert.Contains("newarr", lifted, StringComparison.Ordinal);
    }

    /// <summary>
    /// An operation the trials could not measure — because wrapping what it read faulted on a value
    /// they made rather than the program did — but which wanted an array and faulted once given one,
    /// is read as reading an element where the walk forces it to take one more than it leaves.
    /// </summary>
    [Fact]
    public void AnOperationThatWantedAnArrayAndFaultedIsReadAsReadingAnElement()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(5)),
            (Switch, new VirtualOperand.Table([6])),
            (Push, new VirtualOperand.Number(6)),
            (Element, new VirtualOperand.None()),
            (Jump, new VirtualOperand.Number(6)),
            (Push, new VirtualOperand.Number(0)),
            (Push, new VirtualOperand.Number(1))
        ]);

        var settled = VirtualProgramRecovery.Settled(program, context.Module);
        var lifted = string.Join(
            "\n",
            VirtualLift.Render(program with { Operations = settled }, context.Module));

        Assert.Equal(-1, settled[Element].Net);
        Assert.Equal("reads an array element", settled[Element].Name);
        Assert.Contains("ldelem", lifted, StringComparison.Ordinal);
    }

    private static ArtifactContext Module() => SyntheticContext.Build(module =>
    {
        var type = SyntheticContext.AddType(module, "Held");
        type.Fields.Add(new FieldDefUser(
            "Kept",
            new FieldSig(module.CorLibTypes.Int32),
            FieldAttributes.Public | FieldAttributes.Static));
        type.Methods.Add(Empty(module, "Stub"));
        var takes = Empty(module, "Takes");
        takes.MethodSig.Params.Add(module.CorLibTypes.Int32);
        takes.MethodSig.Params.Add(module.CorLibTypes.Int32);
        takes.ParamDefs.Add(new ParamDefUser("left", 1));
        takes.ParamDefs.Add(new ParamDefUser("right", 2));
        type.Methods.Add(takes);
        var gives = new MethodDefUser(
            "Gives",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        gives.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
        gives.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type.Methods.Add(gives);
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
