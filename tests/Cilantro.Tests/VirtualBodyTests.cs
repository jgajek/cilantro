using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

/// <summary>
/// Covers building a method body out of a recovered program, which is the one thing the tool
/// writes that it cannot prove and so is held to refusing wherever it is unsure.
/// </summary>
/// <remarks>
/// The programs here are written by hand for the same reason the reading's are: what is under test
/// is the lowering, and a program written by hand can be given a dead block, a contradiction and a
/// return reached with nothing on the stack, which is what the lowering has to get right.
/// </remarks>
public sealed class VirtualBodyTests
{
    private const int Push = 1;
    private const int Store = 2;
    private const int Load = 3;
    private const int Jump = 5;
    private const int Add = 6;
    private const int Mystery = 7;
    private const int Throw = 8;
    private const int Return = 9;

    /// <summary>
    /// The engine keeps every value as an object, so the body does too: a constant is boxed where
    /// it is made and converted where it is used, and nothing is assumed about its width.
    /// </summary>
    [Fact]
    public void ValuesAreCarriedAsObjectsAndConvertedOnlyWhereTheyAreUsed()
    {
        using var context = Module();
        var built = Build(context, [
            (Push, new VirtualOperand.Number(2)),
            (Push, new VirtualOperand.Number(3)),
            (Add, new VirtualOperand.None()),
            (Store, new VirtualOperand.Number(0)),
            (Return, new VirtualOperand.None())
        ]);

        Assert.Null(built.Refused);
        Assert.NotNull(built.Body);
        var said = Written(built.Body!);
        Assert.Contains("ldc.i4 2, box System.Int32", said, StringComparison.Ordinal);
        Assert.Contains("System.Convert::ToInt32", said, StringComparison.Ordinal);
        Assert.Contains("add, box System.Int32, stloc", said, StringComparison.Ordinal);
        Assert.All(
            built.Body!.Variables,
            local => Assert.Equal("System.Object", local.Type.FullName));
    }

    /// <summary>
    /// An operation nothing established stops the whole body. A body that is right everywhere but
    /// one instruction runs the wrong code, and no reader of it can tell which instruction it was.
    /// </summary>
    [Fact]
    public void AnOperationNothingEstablishedRefusesTheWholeBody()
    {
        using var context = Module();
        var built = Build(context, [
            (Push, new VirtualOperand.Number(2)),
            (Mystery, new VirtualOperand.Number(11)),
            (Return, new VirtualOperand.None())
        ]);

        Assert.Null(built.Body);
        Assert.Contains("operation 1", built.Refused, StringComparison.Ordinal);
        Assert.Contains("nothing established what it does", built.Refused, StringComparison.Ordinal);
    }

    /// <summary>
    /// Where no path arrives, there is no stack to work on, and writing the operation out anyway
    /// would be writing something whose meaning depends on a stack nobody can name.
    /// </summary>
    [Fact]
    public void WhatNoPathArrivesAtThrowsRatherThanPretendingToAStack()
    {
        using var context = Module();
        var built = Build(context, [
            (Push, new VirtualOperand.Number(1)),
            (Jump, new VirtualOperand.Number(3)),
            (Store, new VirtualOperand.Number(0)),
            (Return, new VirtualOperand.None())
        ]);

        Assert.Null(built.Refused);
        Assert.Contains("nothing reaches", string.Join(" ", built.Notes), StringComparison.Ordinal);
        Assert.Contains("ldnull, throw", Written(built.Body!), StringComparison.Ordinal);
    }

    /// <summary>
    /// A return is written to take a value only where the program leaves one there. The same
    /// operation is reached from blocks that leave nothing, and popping there takes what is not
    /// on the stack.
    /// </summary>
    [Fact]
    public void AReturnReachedWithNothingOnTheStackTakesNothing()
    {
        using var context = Module();
        var built = Build(context, [
            (Return, new VirtualOperand.None())
        ]);

        Assert.Null(built.Refused);
        Assert.Equal("ret", Written(built.Body!).Split(',')[0].Trim());
    }

    /// <summary>
    /// Where nothing paired a clause with the code it guards, which of its numbers is where the try
    /// begins is unknown, and a body that puts the handler in the wrong place runs the wrong code
    /// exactly when something has already gone wrong.
    /// </summary>
    [Fact]
    public void AGuardedRegionIsRefusedRatherThanGuessedAt()
    {
        using var context = Module();
        var program = Program(context, [
            (Push, new VirtualOperand.Number(1)),
            (Return, new VirtualOperand.None())
        ]) with
        {
            Regions = [new VirtualRegion([0, 1], 0, null)]
        };

        var built = VirtualBody.Build(program, context.Module, Stub(context));

        Assert.Null(built.Body);
        Assert.Contains("guarded region", built.Refused, StringComparison.Ordinal);
    }

    /// <summary>
    /// Where the pairing did say which range is which, the region becomes what it stands for: a
    /// catch handler over the operations it guards, and jumps out of it written as leaves, which is
    /// the only way the runtime will accept a body that has one.
    /// </summary>
    [Fact]
    public void AGuardedRegionThatWasToldApartBecomesACatchHandler()
    {
        using var context = Module();
        var built = VirtualBody.Build(Guarded(context), context.Module, Stub(context));

        Assert.Null(built.Refused);
        var body = built.Body!;
        var clause = Assert.Single(body.ExceptionHandlers);
        Assert.Equal(ExceptionHandlerType.Catch, clause.HandlerType);
        Assert.Equal("System.Exception", clause.CatchType.FullName);

        // The try ends where the handler begins, and the handler ends at the operation both of them
        // leave to, which is what the ranges say and what the instructions have to agree with.
        Assert.Same(clause.TryEnd, clause.HandlerStart);
        Assert.Equal(2, body.Instructions.Count(one => one.OpCode == OpCodes.Leave));
        Assert.DoesNotContain(body.Instructions, one => one.OpCode == OpCodes.Br);
        Assert.Contains("guarded region(s) became catch handlers", string.Join(" ", built.Notes),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A try that runs on into whatever follows it is not something the runtime will load, and a
    /// reading in which one does has the end of the region in the wrong place.
    /// </summary>
    [Fact]
    public void ARegionWhoseTryRunsOnIsRefused()
    {
        using var context = Module();
        var program = Guarded(context);
        program = program with
        {
            Regions = [((VirtualRegion)program.Regions[0]) with { Guarded = (1, 1) }]
        };

        var built = VirtualBody.Build(program, context.Module, Stub(context));

        Assert.Null(built.Body);
        Assert.Contains("runs on into what follows", built.Refused, StringComparison.Ordinal);
    }

    /// <summary>
    /// An operation that throws the value it takes is written as the throw it is, with the cast the
    /// lowering needs to say that an object is an exception.
    /// </summary>
    [Fact]
    public void AThrowIsWrittenAsOne()
    {
        using var context = Module();
        var built = Build(context, [
            (Push, new VirtualOperand.Number(1)),
            (Throw, new VirtualOperand.None()),
            (Return, new VirtualOperand.None())
        ]);

        Assert.Null(built.Refused);
        Assert.Contains(
            "castclass System.Exception, throw",
            Written(built.Body!),
            StringComparison.Ordinal);
    }

    /// <summary>A program with one region, whose try and handler the pairing told apart.</summary>
    private static VirtualProgram Guarded(ArtifactContext context) =>
        Program(context, [
            (Push, new VirtualOperand.Number(1)),
            (Store, new VirtualOperand.Number(0)),
            (Jump, new VirtualOperand.Number(5)),
            (Store, new VirtualOperand.Number(0)),
            (Jump, new VirtualOperand.Number(5)),
            (Return, new VirtualOperand.None())
        ]) with
        {
            Regions =
            [
                new VirtualRegion([3, 4], 0, "System.Exception")
                {
                    Guarded = (1, 2),
                    Handled = (3, 4)
                }
            ]
        };

    /// <summary>
    /// A jump lands on the first instruction of the operation it names, and not on whatever the
    /// lowering of the operation before it happened to end with.
    /// </summary>
    [Fact]
    public void AJumpLandsOnTheOperationItNames()
    {
        using var context = Module();
        var built = Build(context, [
            (Push, new VirtualOperand.Number(1)),
            (Jump, new VirtualOperand.Number(2)),
            (Return, new VirtualOperand.None())
        ]);

        Assert.Null(built.Refused);
        var body = built.Body!;
        var jump = body.Instructions.First(instruction => instruction.OpCode == OpCodes.Br);
        var landed = Assert.IsAssignableFrom<Instruction>(jump.Operand);
        var at = body.Instructions.IndexOf(landed);
        Assert.True(at >= 0);

        // The return it names is reached with a value on the stack, so its lowering begins by
        // dropping that value. Landing on the return itself would leave the value behind.
        Assert.Equal(OpCodes.Pop, landed.OpCode);
        Assert.Equal(OpCodes.Ret, body.Instructions[at + 1].OpCode);
    }

    private static VirtualBody.Attempt Build(
        ArtifactContext context,
        IReadOnlyList<(int Opcode, VirtualOperand Operand)> operations) =>
        VirtualBody.Build(Program(context, operations), context.Module, Stub(context));

    /// <summary>The emitted body as one line, which is what an assertion can read.</summary>
    private static string Written(CilBody body) => string.Join(
        ", ",
        body.Instructions.Select(instruction => instruction.Operand switch
        {
            null => instruction.OpCode.Name,
            Local local => $"{instruction.OpCode.Name} {local.Name}",
            Instruction => instruction.OpCode.Name,
            IList<Instruction> => instruction.OpCode.Name,
            var operand => $"{instruction.OpCode.Name} {operand}"
        }));

    private static MethodDef Stub(ArtifactContext context) => context.Module.Types
        .SelectMany(type => type.Methods)
        .First(method => method.Name == "Stub");

    private static VirtualProgram Program(
        ArtifactContext context,
        IReadOnlyList<(int Opcode, VirtualOperand Operand)> operations)
    {
        var stub = Stub(context);
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
                [Jump] = new(Jump, 0, 0, "branch"),
                [Add] = new(Add, 2, 1, "add"),
                [Throw] = new(Throw, 1, 0, VirtualSemantics.Throwing),
                [Return] = new(Return, 1, 0, "returns the value it takes"),
                [Mystery] = new(Mystery, 1, 1, null)
            },
            TargetIsOperand = new HashSet<int> { Jump }
        };
    }

    private static ArtifactContext Module() => SyntheticContext.Build(module =>
    {
        var type = SyntheticContext.AddType(module, "Held");
        var stub = new MethodDefUser(
            "Stub",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        stub.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type.Methods.Add(stub);
    });
}
