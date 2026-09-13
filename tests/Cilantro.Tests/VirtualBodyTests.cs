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
    private const int EndFinally = 10;

    /// <summary>
    /// An operation measured to take one value and read as the IL for taking two, which is the
    /// reading contradicting itself about the operation without contradicting itself about where
    /// the path goes.
    /// </summary>
    private const int Contradictory = 11;

    /// <summary>
    /// A value whose type every path agrees on is held as that type, so the body reads as the
    /// arithmetic it is rather than as the packing around it.
    /// </summary>
    /// <remarks>
    /// The engine itself keeps everything as an object, and writing the body that way was faithful
    /// but nearly unreadable: these five operations came out as eleven instructions, of which two
    /// boxed, two called <c>Convert.ToInt32</c>, and two moved values into and out of a scratch
    /// local so the one beneath the top could be reached. None of that was a guess being corrected
    /// — the reading had already established that the operation makes an int32 — it was a fact the
    /// body threw away before it was written.
    /// </remarks>
    [Fact]
    public void ValuesAreHeldAsTheTypeEveryPathAgreesOn()
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
        Assert.Contains("ldc.i4 2, ldc.i4 3, add, stloc", said, StringComparison.Ordinal);
        Assert.DoesNotContain("box", said, StringComparison.Ordinal);
        Assert.DoesNotContain("System.Convert", said, StringComparison.Ordinal);
        // The slot says what it holds, in its type and in its name, so a reader of the rebuilt
        // method is not left converting an object to find out.
        var slot = Assert.Single(built.Body!.Variables);
        Assert.Equal("System.Int32", slot.Type.FullName);
        Assert.Equal("Int32Slot0", slot.Name);
    }

    /// <summary>
    /// A slot that holds two different kinds of thing is an object, which is what the engine had,
    /// and every value going into it is boxed as before.
    /// </summary>
    /// <remarks>
    /// This is the check that the typing claims nothing it has not established. One store puts a
    /// number in the slot and the other puts whatever was in a slot nothing can name the contents
    /// of, and nothing says those are the same kind of thing, so the slot stays as it was.
    /// </remarks>
    [Fact]
    public void ASlotFedTwoDifferentKindsOfThingStaysAnObject()
    {
        using var context = Module();
        var built = Build(context, [
            (Push, new VirtualOperand.Number(7)),
            (Store, new VirtualOperand.Number(0)),
            (Load, new VirtualOperand.Number(1)),
            (Store, new VirtualOperand.Number(0)),
            (Return, new VirtualOperand.None())
        ]);

        Assert.Null(built.Refused);
        Assert.All(
            built.Body!.Variables,
            local => Assert.Equal("System.Object", local.Type.FullName));
        Assert.Contains("box System.Int32", Written(built.Body!), StringComparison.Ordinal);
    }

    /// <summary>
    /// A slot holds what is written to it, whether or not the writing comes before the reading.
    /// </summary>
    /// <remarks>
    /// Here slot 0 is read before its one store, and it is still a number. Requiring the store to
    /// come first was tried and it cost almost everything: in a flattened program every block is
    /// entered from the dispatcher, so as far as the control flow can tell any slot a block reads
    /// at its start might not have been written yet, and thirteen slots came out as one. What the
    /// looser rule gives up is bounded and small — the read here is the engine handing on a null
    /// where a slot declared as a number hands on a zero — and the engine's own conversions turn
    /// that null into the same zero at every use that converts it.
    ///
    /// A slot nothing writes at all is a different matter and stays an object, because an object
    /// is all there is to declare it as.
    /// </remarks>
    [Fact]
    public void ASlotHoldsWhatIsWrittenToItWhicheverComesFirst()
    {
        using var context = Module();
        var built = Build(context, [
            (Load, new VirtualOperand.Number(0)),
            (Store, new VirtualOperand.Number(1)),
            (Push, new VirtualOperand.Number(5)),
            (Store, new VirtualOperand.Number(0)),
            (Return, new VirtualOperand.None())
        ]);

        Assert.Null(built.Refused);
        Assert.All(
            built.Body!.Variables,
            local => Assert.Equal("System.Int32", local.Type.FullName));
        Assert.Equal(["Int32Slot0", "Int32Slot1"], built.Body!.Variables
            .Select(local => local.Name).Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// A slot nothing writes stays an object, and what reads it is made to convert.
    /// </summary>
    /// <remarks>
    /// This is the shape that caught the walk out. A slot nothing writes claims nothing, and
    /// claiming nothing is not the same as claiming an object: agreement is pushed backwards, so a
    /// load claiming nothing took on whatever its reader wanted — a number, here, for the add —
    /// while the body still declared the slot as the object it had nothing better to call it. The
    /// load then put an object where the add had been promised a number, which no reader and no
    /// verifier of the result would accept. So the slots are grounded before the types are used.
    /// </remarks>
    [Fact]
    public void ASlotNothingWritesStaysAnObjectAndWhatReadsItConverts()
    {
        using var context = Module();
        var built = Build(context, [
            (Load, new VirtualOperand.Number(7)),
            (Push, new VirtualOperand.Number(3)),
            (Add, new VirtualOperand.None()),
            (Store, new VirtualOperand.Number(0)),
            (Return, new VirtualOperand.None())
        ]);

        Assert.Null(built.Refused);
        var read = Assert.Single(built.Body!.Variables, local => local.Name == "slot7");
        Assert.Equal("System.Object", read.Type.FullName);
        Assert.Contains(
            "System.Convert::ToInt32", Written(built.Body!), StringComparison.Ordinal);
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
        // Counted as well as written, because a body to be run rather than read is refused over it:
        // an operation nothing arrives at is work the body would drop instead of doing.
        Assert.Equal(1, built.Unreached);
    }

    /// <summary>
    /// An operation the reading contradicts itself around throws, rather than being written as
    /// read into a body whose stack then disagrees with itself.
    /// </summary>
    /// <remarks>
    /// The contradiction is between the arity the operation was measured at, which is what the
    /// depth walk carried forward, and the arity of the IL it was read as, which is what the body
    /// would write. Writing it as read put both readings into one method: the instructions leave
    /// one depth and the walk has everything after them at another, so two paths meet at a depth
    /// they do not agree on. Nothing catches that — the module loads and it verifies — but a
    /// decompiler reading such a method says so and then guesses, and the guess is what an analyst
    /// reads. Throwing keeps the one operation the reading cannot place from costing the reader the
    /// method around it, which on the reactor7 probe was 314 dispatcher jumps that could not be
    /// made direct while the body's stack was in dispute.
    /// </remarks>
    [Fact]
    public void AnOperationTheReadingContradictsItselfAroundThrowsRatherThanDisputingTheStack()
    {
        using var context = Module();
        var built = Build(context, [
            (Push, new VirtualOperand.Number(1)),
            (Push, new VirtualOperand.Number(2)),
            (Contradictory, new VirtualOperand.None()),
            (Return, new VirtualOperand.None())
        ]);

        Assert.Null(built.Refused);
        Assert.Equal(1, built.Distrusted);
        Assert.Contains(
            "stands in the body as a throw",
            string.Join(" ", built.Notes),
            StringComparison.Ordinal);
        Assert.Contains("ldnull, throw", Written(built.Body!), StringComparison.Ordinal);

        // The point of the throw, and the thing that was wrong before it: whatever the reading of
        // the one operation was, the method written out of it has one depth at every place two
        // paths meet.
        var stub = Stub(context);
        stub.Body = built.Body!;
        var walked = EvaluationStackAnalyzer.Analyze(stub);
        Assert.True(walked.Valid, string.Join("; ", walked.Diagnostics));
    }

    [Fact]
    public void AReadingThatArrivesEverywhereLeavesNothingUnreached()
    {
        using var context = Module();
        var built = Build(context, [
            (Push, new VirtualOperand.Number(1)),
            (Store, new VirtualOperand.Number(0)),
            (Return, new VirtualOperand.None())
        ]);

        Assert.Null(built.Refused);
        Assert.Equal(0, built.Unreached);
        Assert.Equal(0, built.Distrusted);
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
        Assert.Contains("guarded region(s) became handlers", string.Join(" ", built.Notes),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A clause that names no type is a finally, and the operation the engine ends it with — one
    /// nothing measured but that changes the engine's state at the last place of a typeless
    /// handler — is that end. It becomes a finally handler closed by <c>endfinally</c>, which is
    /// the only shape the runtime accepts a finally in.
    /// </summary>
    [Fact]
    public void ATypelessRegionBecomesAFinallyClosedByEndfinally()
    {
        using var context = Module();
        var built = VirtualBody.Build(Finally(context), context.Module, Stub(context));

        Assert.Null(built.Refused);
        var body = built.Body!;
        var clause = Assert.Single(body.ExceptionHandlers);
        Assert.Equal(ExceptionHandlerType.Finally, clause.HandlerType);
        Assert.Null(clause.CatchType);
        Assert.Contains(body.Instructions, one => one.OpCode == OpCodes.Endfinally);
    }

    /// <summary>
    /// CoreCLR's clause class still has a Type field on a finally, and the machine stores a
    /// placeholder there when it cannot name what is caught. That placeholder is not a type the
    /// module can put on a catch clause; the region is the same finally a typeless clause is.
    /// </summary>
    [Fact]
    public void APlaceholderCatchNameIsWrittenAsAFinally()
    {
        using var context = Module();
        var program = Finally(context);
        program = program with
        {
            Regions =
            [
                ((VirtualRegion)program.Regions[0]) with { Caught = "something unnamed" }
            ]
        };

        var built = VirtualBody.Build(program, context.Module, Stub(context));

        Assert.Null(built.Refused);
        var clause = Assert.Single(built.Body!.ExceptionHandlers);
        Assert.Equal(ExceptionHandlerType.Finally, clause.HandlerType);
        Assert.Null(clause.CatchType);
    }

    /// <summary>A program with one finally, whose handler the engine ends with its own operation.</summary>
    private static VirtualProgram Finally(ArtifactContext context)
    {
        var program = Program(context, [
            (Push, new VirtualOperand.Number(1)),
            (Store, new VirtualOperand.Number(0)),
            (Jump, new VirtualOperand.Number(4)),
            (EndFinally, new VirtualOperand.None()),
            (Return, new VirtualOperand.None())
        ]);
        return program with
        {
            Operations = new Dictionary<int, VirtualOperation>(program.Operations)
            {
                // The end of a finally takes and leaves nothing and only changes engine state. The
                // recovery names it from where it sits; here it is named the same way directly, the
                // synthetic program not being built through the recovery that would do so.
                [EndFinally] = new(EndFinally, 0, 0, VirtualSemantics.Ending) { TouchesState = true }
            },
            // The clause names no type (a finally) and its handler-kind flag, last of its numbers,
            // is 2 — the runtime's own value for a finally.
            Regions =
            [
                new VirtualRegion([3, 3, 0, 2], 0, null)
                {
                    Guarded = (1, 2),
                    Handled = (3, 3)
                }
            ]
        };
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
                [Mystery] = new(Mystery, 1, 1, null),
                [Contradictory] = new(Contradictory, 1, 1, "add")
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
