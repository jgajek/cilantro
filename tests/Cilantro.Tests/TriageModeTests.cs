using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

/// <summary>
/// Covers the difference between a run that assumes its way past what it cannot read and one that
/// refuses to.
/// </summary>
/// <remarks>
/// Two properties hold the whole arrangement up. The first is that a call nobody can follow costs the
/// run only what that call would have produced, rather than everything behind it — which is what makes
/// an unfamiliar sample yield something. The second is that an unknown may be carried but may not
/// become a value: the moment a branch, an index or a length would have to be invented, the run stops
/// in both modes. Without the second, the first would be a machine that reads whichever path it
/// guessed at, which is worse than reading nothing.
/// </remarks>
public sealed class TriageModeTests
{
    /// <summary>
    /// The common case: a call that hands nothing back cost the frame nothing, so the frame goes on.
    /// </summary>
    [Fact]
    public void ACallThatHandsNothingBackIsSteppedOver()
    {
        using var module = BlockerTests.NewModule();
        var (unfollowable, signature) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.Void);
        var method = Runs(module, unfollowable, module.CorLibTypes.Int32);
        var machine = Triage();

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(9, result.Value.AsInt32());
        Assert.Empty(machine.State.Blockers.Blockers);
        var continued = Assert.Single(machine.State.Blockers.Continuations);
        Assert.Equal(BlockerKind.UnmodeledCall, continued.Kind);
        Assert.Equal(signature, continued.Key);
        Assert.Contains(signature, continued.Declare, StringComparison.Ordinal);
    }

    /// <summary>
    /// A call that returns something returns something unknown, which is the honest answer: the tool
    /// did not read the call, so it does not know, and it says so rather than picking a value.
    /// </summary>
    /// <remarks>
    /// The frame carries the unknown as far as its own return, at which point the caller is told the
    /// result is not known — this frame is the whole run here, so that is what the run says. A frame
    /// whose result nothing uses completes, which is the case that matters and is covered above.
    /// </remarks>
    [Fact]
    public void ACallThatReturnsSomethingReturnsSomethingUnknown()
    {
        using var module = BlockerTests.NewModule();
        var (method, _) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.Int32);
        var machine = Triage();

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Unknown, result.Status);
        Assert.False(result.Value.IsKnown);
        Assert.Contains(
            "was not followed",
            machine.State.Provenance.Render(result.Value.ProvenanceId),
            StringComparison.Ordinal);
        Assert.Single(machine.State.Blockers.Continuations);
    }

    /// <summary>
    /// The line: an unknown that would have to become a decision stops the run in either mode, because
    /// choosing one of the two paths would be reading a program the sample does not contain.
    /// </summary>
    [Fact]
    public void AnUnknownFromASteppedCallStillCannotBecomeADecision()
    {
        using var module = BlockerTests.NewModule();
        var (unfollowable, _) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.Boolean);
        var method = BlockerTests.NewMethod(
            module, "Decide", MethodSig.CreateStatic(module.CorLibTypes.Int32));
        var body = method.Body.Instructions;
        var landing = Instruction.Create(OpCodes.Ldc_I4_1);
        body.Add(Instruction.Create(OpCodes.Call, unfollowable));
        body.Add(Instruction.Create(OpCodes.Brtrue, landing));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        body.Add(Instruction.Create(OpCodes.Ret));
        body.Add(landing);
        body.Add(Instruction.Create(OpCodes.Ret));
        var machine = Triage();

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Unknown, result.Status);
        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(BlockerKind.UnknownValue, blocker.Kind);
    }

    /// <summary>
    /// Nor may it become an index. There is no such thing as the unknownth element of an array, and
    /// before calls were stepped over this coerced an unknown to zero's worth of nothing and reported
    /// an honest gap as a fault in the interpreted program.
    /// </summary>
    [Fact]
    public void AnUnknownFromASteppedCallStillCannotBecomeAnIndex()
    {
        using var module = BlockerTests.NewModule();
        var (unfollowable, _) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.Int32);
        var method = BlockerTests.NewMethod(
            module, "Read", MethodSig.CreateStatic(module.CorLibTypes.Int32));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldc_I4_4));
        body.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Int32.ToTypeDefOrRef()));
        body.Add(Instruction.Create(OpCodes.Call, unfollowable));
        body.Add(Instruction.Create(OpCodes.Ldelem_I4));
        body.Add(Instruction.Create(OpCodes.Ret));
        var machine = Triage();

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Unknown, result.Status);
        Assert.Contains("array index is unknown", result.Diagnostic, StringComparison.Ordinal);
        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(BlockerKind.UnknownValue, blocker.Kind);
        Assert.Null(blocker.Declare);
    }

    /// <summary>
    /// Asked for rigour, the same frame stops where it always did, and the stop still names the
    /// declaration that would answer it.
    /// </summary>
    [Fact]
    public void AskedForRigourTheSameCallStopsTheFrame()
    {
        using var module = BlockerTests.NewModule();
        var (unfollowable, signature) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.Void);
        var method = Runs(module, unfollowable, module.CorLibTypes.Int32);
        var machine = Strict();

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Unsupported, result.Status);
        Assert.Empty(machine.State.Blockers.Continuations);
        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(BlockerKind.UnmodeledCall, blocker.Kind);
        Assert.Equal(signature, blocker.Key);
    }

    /// <summary>
    /// A platform call that does something rather than merely reporting a fact is stepped over too, and
    /// is still recorded as a boundary rather than a gap: what lies past it is the operating system, not
    /// a model somebody forgot to write.
    /// </summary>
    [Fact]
    public void APlatformCallIsSteppedOverAndStillReadsAsABoundary()
    {
        using var module = BlockerTests.NewModule();
        var machine = Triage();

        var result = machine.Execute(CallsNative(module, "user32.dll", "GetWindowText"));

        Assert.Equal(StaticExecutionStatus.Unknown, result.Status);
        Assert.False(result.Value.IsKnown);
        var continued = Assert.Single(machine.State.Blockers.Continuations);
        Assert.Equal(BlockerKind.PlatformCall, continued.Kind);
        Assert.Equal("user32.dll!GetWindowText", continued.Key);
    }

    /// <summary>
    /// A question about the machine that nobody has answered stops the run in either mode, because the
    /// only way past it is a value, and a value is exactly what the tool will not make up.
    /// </summary>
    /// <remarks>
    /// This is the difference between the two things triage does. Not reading a call costs the run what
    /// the call would have returned and nothing else, and an unknown is an honest account of that.
    /// Answering "what does this registry value hold" with an invention would put bytes nobody has seen
    /// into the reading, and the reading is the whole product.
    /// </remarks>
    [Fact]
    public void AQuestionAboutTheMachineNobodyAnsweredIsStillAStop()
    {
        using var module = BlockerTests.NewModule();
        var machine = new StaticMachine();
        machine.State.RegisterRunEnvironment(new RunEnvironment(
            new HostEnvironment(HostProfile.Parse("""{ "facts": { } }""", "sparse")),
            strict: false));

        var result = machine.Execute(CallsNative(module, "kernel32.dll", "GetTickCount"));

        Assert.Equal(StaticExecutionStatus.Unsupported, result.Status);
        Assert.Empty(machine.State.Blockers.Continuations);
        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(BlockerKind.UnstatedFact, blocker.Kind);
        Assert.Equal("native:kernel32!GetTickCount", blocker.Key);
    }

    /// <summary>
    /// What somebody said a call does beats what the tool would have assumed about it, because the
    /// declaration is consulted first and an assumption is only ever the last resort.
    /// </summary>
    [Fact]
    public void ADeclarationBeatsAnAssumption()
    {
        using var module = BlockerTests.NewModule();
        var (method, signature) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.Int32);
        var machine = new StaticMachine();
        machine.State.RegisterRunEnvironment(new RunEnvironment(
            declarations: RunDeclarations
                .Parse($$"""{ "calls": { "{{signature}}": { "returns": 7 } } }""", "test")
                .Allowing(true),
            strict: false));

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(7, result.Value.AsInt32());
        Assert.Empty(machine.State.Blockers.Continuations);
    }

    /// <summary>
    /// A call the tool declined to read is recorded as something the frame did, so that the pass which
    /// removes loader frames it can prove do nothing cannot reach that conclusion about a frame whose
    /// calls nobody read.
    /// </summary>
    [Fact]
    public void ASteppedCallIsStillSomethingTheFrameDid()
    {
        using var module = BlockerTests.NewModule();
        var (unfollowable, signature) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.Void);
        var machine = Triage();

        machine.Execute(Runs(module, unfollowable, module.CorLibTypes.Int32));

        var evidence = machine.State.LoaderEvidence;
        Assert.Contains(
            $"stepped over {signature}",
            evidence.Effects.SelectMany(effect => effect.Value.Registrations),
            StringComparer.Ordinal);
        Assert.Contains(
            evidence.Observations,
            observation => observation.Kind == LoaderObservationKind.SteppedCall &&
                observation.Detail.StartsWith(signature, StringComparison.Ordinal));
    }

    /// <summary>
    /// The same call met on four paths is one thing to know about the run, counted rather than listed,
    /// which is also what keeps the account of a run identical between the two runs of it the tool
    /// compares.
    /// </summary>
    [Fact]
    public void TheSameSteppedCallIsCountedRatherThanListedAgain()
    {
        using var module = BlockerTests.NewModule();
        var (unfollowable, _) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.Void);
        var method = BlockerTests.NewMethod(
            module, "Twice", MethodSig.CreateStatic(module.CorLibTypes.Void));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Call, unfollowable));
        body.Add(Instruction.Create(OpCodes.Call, unfollowable));
        body.Add(Instruction.Create(OpCodes.Ret));
        var machine = Triage();

        machine.Execute(method);

        var continued = Assert.Single(machine.State.Blockers.Continuations);
        Assert.Equal(2, continued.Times);
    }

    /// <summary>
    /// A cast the hierarchy in hand cannot settle answers no, and says that it did.
    /// </summary>
    /// <remarks>
    /// The reason this is worth a test of its own is that the wrong answer here is invisible where it
    /// happens. The program asked whether one of its own objects is a given type, took the no as a fact
    /// and carried on, so the run continues down a path the program never takes and fails somewhere
    /// with no visible connection to the test — a field read on the null, hundreds of thousands of
    /// steps later, reading exactly like the program rejecting its own state. This is how the string
    /// table on two of the profiled samples came to look unreadable.
    /// </remarks>
    [Fact]
    public void ACastTheHierarchyCannotSettleSaysSo()
    {
        using var module = BlockerTests.NewModule();
        var (kind, of) = Hierarchy(module);
        var machine = Triage();

        var result = machine.Execute(Asks(module, of, kind));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(StaticValueKind.Null, result.Value.Kind);
        var continued = Assert.Single(machine.State.Blockers.Continuations);
        Assert.Equal(BlockerKind.UnknownValue, continued.Kind);
        Assert.Equal("isinst:Tests.Derived->Tests.Base", continued.Key);
    }

    /// <summary>
    /// Told which module it is reading, the machine settles the same cast and hands the object back.
    /// </summary>
    [Fact]
    public void ToldTheModuleTheSameCastSucceedsAndIsNotReported()
    {
        using var module = BlockerTests.NewModule();
        var (kind, of) = Hierarchy(module);
        var machine = Triage();
        machine.State.RegisterModuleMetadata(module);

        var result = machine.Execute(Asks(module, of, kind));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(StaticValueKind.HeapReference, result.Value.Kind);
        Assert.Empty(machine.State.Blockers.Continuations);
    }

    /// <summary>
    /// A cast the hierarchy does answer no to is the program's own logic and is not reported.
    /// </summary>
    /// <remarks>
    /// Which is what keeps the disclosure worth reading. An interpreter engine asks an object which of
    /// its dozen instruction kinds it is and is told no eleven times on the way to the twelfth; listing
    /// those would bury the one case that means the tool is at its limit under the eleven that mean
    /// nothing at all.
    /// </remarks>
    [Fact]
    public void ACastTheHierarchyAnswersNoToIsNotReported()
    {
        using var module = BlockerTests.NewModule();
        var (_, of) = Hierarchy(module);
        var unrelated = Declare(module, "Stranger", module.CorLibTypes.Object.TypeDefOrRef);
        var machine = Triage();
        machine.State.RegisterModuleMetadata(module);

        var result = machine.Execute(Asks(module, of, unrelated));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(StaticValueKind.Null, result.Value.Kind);
        Assert.Empty(machine.State.Blockers.Continuations);
    }

    /// <summary>
    /// Asked for rigour, a cast it cannot settle stops the run rather than answering it.
    /// </summary>
    [Fact]
    public void AskedForRigourACastItCannotSettleStopsTheFrame()
    {
        using var module = BlockerTests.NewModule();
        var (kind, of) = Hierarchy(module);
        var machine = Strict();

        var result = machine.Execute(Asks(module, of, kind));

        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
        Assert.Empty(machine.State.Blockers.Continuations);
        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(BlockerKind.UnknownValue, blocker.Kind);
        Assert.Equal("isinst:Tests.Derived->Tests.Base", blocker.Key);
    }

    /// <summary>
    /// The two things a triage run does to the assembly for the reader's sake, and a strict run
    /// does not: it renames what the protector generated, and it builds the virtualized methods
    /// back into a copy of their own.
    /// </summary>
    /// <remarks>
    /// Neither is the protector's own output, which is why rigour declines them and why a triage run
    /// wants them: one is a name nobody wrote, the other is the tool's reading of a program. Saying
    /// so by mode rather than by flag is the point — the analyst who reaches for this first should
    /// not have to know either option exists, and the one who reaches for rigour should not have to
    /// remember to turn them off.
    /// </remarks>
    [Fact]
    public void ATriageRunRenamesAndBuildsBackWhereARigorousOneDoesNeither()
    {
        Assert.True(new PipelineOptions().Renames);
        Assert.True(new PipelineOptions().Devirtualizes);
        Assert.False(new PipelineOptions(Strict: true).Renames);
        Assert.False(new PipelineOptions(Strict: true).Devirtualizes);
    }

    /// <summary>
    /// Said outright, either way, in either mode: the mode decides only what was left unsaid.
    /// </summary>
    [Fact]
    public void WhatTheRunWasToldToDoOutweighsWhatItsModeWouldHaveChosen()
    {
        Assert.True(new PipelineOptions(Strict: true, RenameSymbols: true).Renames);
        Assert.True(new PipelineOptions(Strict: true, Devirtualize: true).Devirtualizes);
        Assert.False(new PipelineOptions(RenameSymbols: false).Renames);
        Assert.False(new PipelineOptions(Devirtualize: false).Devirtualizes);
    }

    /// <summary>A base class and a constructor for something derived from it.</summary>
    private static (TypeDefUser Kind, MethodDef Of) Hierarchy(ModuleDefUser module)
    {
        var kind = Declare(module, "Base", module.CorLibTypes.Object.TypeDefOrRef);
        var derived = Declare(module, "Derived", kind);
        return (kind, derived.FindInstanceConstructors().First());
    }

    /// <summary>A type with a constructor that does nothing, so an instance of it can be made.</summary>
    private static TypeDefUser Declare(ModuleDefUser module, string name, ITypeDefOrRef under)
    {
        var declared = new TypeDefUser("Tests", name, under);
        module.Types.Add(declared);
        var constructor = new MethodDefUser(
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        constructor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        declared.Methods.Add(constructor);
        return declared;
    }

    /// <summary>A frame that makes one object and asks whether it is a given kind of thing.</summary>
    private static MethodDefUser Asks(ModuleDefUser module, MethodDef of, TypeDef kind)
    {
        var method = BlockerTests.NewMethod(
            module, $"Is{kind.Name}", MethodSig.CreateStatic(module.CorLibTypes.Object));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Newobj, of));
        body.Add(Instruction.Create(OpCodes.Isinst, kind));
        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    /// <summary>A frame that calls something and then returns a constant of its own.</summary>
    private static MethodDefUser Runs(ModuleDefUser module, IMethod call, TypeSig returns)
    {
        var method = BlockerTests.NewMethod(module, "Body", MethodSig.CreateStatic(returns));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Call, call));
        body.Add(Instruction.Create(OpCodes.Ldc_I4, 9));
        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static MethodDefUser CallsNative(ModuleDefUser module, string library, string entry)
    {
        var declaring = module.Types.FirstOrDefault(item => item.Name == "Program") ??
            new TypeDefUser("Tests", "Program", module.CorLibTypes.Object.TypeDefOrRef);
        if (!module.Types.Contains(declaring))
            module.Types.Add(declaring);
        var imported = new MethodDefUser(
            entry,
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            MethodImplAttributes.PreserveSig,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl)
        {
            ImplMap = new ImplMapUser(new ModuleRefUser(module, library), entry, 0)
        };
        declaring.Methods.Add(imported);
        var method = BlockerTests.NewMethod(
            module, $"Call{entry}", MethodSig.CreateStatic(module.CorLibTypes.Int32));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, imported));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static StaticMachine Triage() => In(strict: false);

    private static StaticMachine Strict() => In(strict: true);

    private static StaticMachine In(bool strict)
    {
        var machine = new StaticMachine();
        machine.State.RegisterRunEnvironment(new RunEnvironment(strict: strict));
        return machine;
    }
}
