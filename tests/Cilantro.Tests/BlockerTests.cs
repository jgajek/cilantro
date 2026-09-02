using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

/// <summary>
/// Covers the account a run keeps of what stopped it.
/// </summary>
/// <remarks>
/// One property matters more than any single entry: a stop has to name the thing that would get past
/// it, or say plainly that nothing written in a file will. Whoever reads these — a person deciding
/// whether to state a fact, or a program deciding whether to try again — is choosing between two
/// actions, and a refusal that does not distinguish them leaves them guessing at the tool's internals.
/// </remarks>
public sealed class BlockerTests
{
    /// <summary>
    /// The commonest stop of all, and the one with the plainest remedy: nobody said what the machine
    /// looks like.
    /// </summary>
    /// <remarks>
    /// Given a profile that is explicitly sparse, so that the test keeps asking what it is asking. What
    /// the built-in default holds is a separate decision, and one that has already changed once.
    /// </remarks>
    [Fact]
    public void AQuestionNobodyAnsweredIsRecordedWithTheFactThatWouldAnswerIt()
    {
        using var module = NewModule();
        var machine = Sparse();

        machine.Execute(Calls(module, "System", "Environment", "get_MachineName",
            module.CorLibTypes.String));

        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(BlockerKind.UnstatedFact, blocker.Kind);
        Assert.Equal("env:MachineName", blocker.Key);
        Assert.Contains("\"facts\"", blocker.Declare, StringComparison.Ordinal);
        Assert.Contains("env:MachineName", blocker.Declare, StringComparison.Ordinal);
    }

    /// <summary>
    /// Stating the fact does not merely change the answer; it takes the stop off the list, which is
    /// what makes the list something an agent can work through until it is empty.
    /// </summary>
    [Fact]
    public void AStatedFactLeavesNothingToGetPast()
    {
        using var module = NewModule();
        var machine = new StaticMachine();
        machine.State.RegisterHostEnvironment(new HostEnvironment(HostProfile.Parse(
            """{ "facts": { "env:MachineName": "DESKTOP-7QK2" } }""",
            "test")));

        var result = machine.Execute(Calls(
            module, "System", "Environment", "get_MachineName", module.CorLibTypes.String));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Empty(machine.State.Blockers.Blockers);
    }

    /// <summary>
    /// A call nothing models is keyed by the signature the machine spells, because that spelling is
    /// what goes in the declarations file and retyping it from a diagnostic is where mistakes happen.
    /// </summary>
    [Fact]
    public void ACallNothingModelsIsRecordedUnderTheSignatureThatWouldDeclareIt()
    {
        using var module = NewModule();
        var (method, signature) = CallsUnmodeled(module, module.CorLibTypes.String);
        var machine = new StaticMachine();

        machine.Execute(method);

        var blocker = Assert.Single(
            machine.State.Blockers.Blockers,
            entry => entry.Kind == BlockerKind.UnmodeledCall);
        Assert.Equal(signature, blocker.Key);
        Assert.Contains(signature, blocker.Declare, StringComparison.Ordinal);
        Assert.Contains("--allow-declared-calls", blocker.Declare, StringComparison.Ordinal);
    }

    /// <summary>
    /// A platform call is recorded under the entry point it leaves for, because that is what the
    /// reader recognises: a sample stops at <c>kernel32!CreateFileW</c>, not at whichever wrapper
    /// declared it.
    /// </summary>
    [Fact]
    public void APlatformCallIsRecordedUnderTheEntryPointItLeavesFor()
    {
        using var module = NewModule();
        var machine = new StaticMachine();

        machine.Execute(CallsNative(module, "kernel32.dll", "CreateFileW"));

        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(BlockerKind.PlatformCall, blocker.Kind);
        Assert.Equal("kernel32.dll!CreateFileW", blocker.Key);
    }

    /// <summary>
    /// A run that spent its budget says which budget and how much of it there was, so that raising it
    /// is a decision rather than a guess.
    /// </summary>
    [Fact]
    public void ARunThatSpentItsStepsSaysWhichBudgetToRaise()
    {
        using var module = NewModule();
        var machine = new StaticMachine(new StaticMachineLimits(MaximumSteps: 16));

        var result = machine.Execute(Loops(module));

        Assert.Equal(StaticExecutionStatus.StepLimitExceeded, result.Status);
        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(BlockerKind.Budget, blocker.Kind);
        Assert.Equal("steps", blocker.Key);
        Assert.Contains("16", blocker.Detail, StringComparison.Ordinal);
        Assert.Contains("\"steps\"", blocker.Declare, StringComparison.Ordinal);
    }

    /// <summary>
    /// A budget is the one stop the tool can answer on its own, so it answers it: the remedy carries
    /// a figure rather than an instruction to think of one.
    /// </summary>
    /// <remarks>
    /// The figure is worth pinning down, because it is what makes a caller that keeps applying what
    /// it is told converge instead of creeping up by one. A step budget does not merely double from
    /// whatever it was refused at: doubling out of a small ceiling spends several whole runs of the
    /// tool reaching a figure that was predictable from the start, so the first retry goes straight
    /// to one worth making.
    /// </remarks>
    [Fact]
    public void ABudgetStopCarriesAFigureAnAgentCanApplyUnchanged()
    {
        using var module = NewModule();
        var machine = new StaticMachine(new StaticMachineLimits(MaximumSteps: 16));

        machine.Execute(Loops(module));

        var remedy = Assert.Single(machine.State.Blockers.Blockers).Remedy;
        Assert.NotNull(remedy);
        Assert.Equal("budgets", remedy.Section);
        Assert.Equal("steps", remedy.Name);
        Assert.Equal("10000000", remedy.Value.Text);
        Assert.Null(remedy.Wants);
        Assert.Null(remedy.Flag);
    }

    /// <summary>
    /// Past the figure a first retry is worth making, doubling takes over again, so a module that
    /// needs more than it still converges rather than being told the same number twice.
    /// </summary>
    [Fact]
    public void AStepBudgetAlreadyWorthRetryingDoublesInstead() =>
        Assert.Equal("24000000", Declaring.Budget("steps", 12_000_000).Value.Text);

    /// <summary>
    /// Only steps start off the bottom. The other budgets are counted in units where ten million
    /// would be a nonsense: a recursion depth of ten million is not a depth anyone meant to ask for.
    /// </summary>
    [Fact]
    public void TheOtherBudgetsStillOnlyDouble()
    {
        Assert.Equal("128", Declaring.Budget("depth", 64).Value.Text);
        Assert.Equal("536870912", Declaring.Budget("allocatedBytes", 268_435_456).Value.Text);
    }

    /// <summary>
    /// A fact is the opposite case: the tool knows where the answer goes and cannot know the answer,
    /// and the two halves are told apart rather than run together in a sentence.
    /// </summary>
    [Fact]
    public void AFactStopSaysWhereTheAnswerGoesAndThatOnlyTheCallerHasIt()
    {
        using var module = NewModule();
        var machine = Sparse();

        machine.Execute(Calls(module, "System", "Environment", "get_MachineName",
            module.CorLibTypes.String));

        var remedy = Assert.Single(machine.State.Blockers.Blockers).Remedy;
        Assert.NotNull(remedy);
        Assert.Equal("facts", remedy.Section);
        Assert.Equal("env:MachineName", remedy.Name);
        Assert.Equal("null", remedy.Value.Text);
        Assert.NotNull(remedy.Wants);
    }

    /// <summary>
    /// A call that hands something back names the type of it, because an agent inventing a value has
    /// to know what kind of value the run will accept, and a wrong one is refused a run later.
    /// </summary>
    [Fact]
    public void ACallStopNamesTheTypeTheCallerHasToInvent()
    {
        using var module = NewModule();
        var (method, signature) = CallsUnmodeled(module, module.CorLibTypes.String);
        var machine = new StaticMachine();

        machine.Execute(method);

        var remedy = Assert.Single(
            machine.State.Blockers.Blockers,
            entry => entry.Kind == BlockerKind.UnmodeledCall).Remedy;
        Assert.NotNull(remedy);
        Assert.Equal("calls", remedy.Section);
        Assert.Equal(signature, remedy.Name);
        Assert.Equal("{ \"returns\": null }", remedy.Value.Text);
        Assert.Equal("System.String", remedy.Wants);
        Assert.Equal("--allow-declared-calls", remedy.Flag);
    }

    /// <summary>
    /// A call that hands nothing back can be answered outright, and is: there is no decision left in
    /// declaring that a method returning void did nothing.
    /// </summary>
    [Fact]
    public void ACallThatHandsNothingBackIsAnsweredInFull()
    {
        using var module = NewModule();
        var (method, _) = CallsUnmodeled(module, module.CorLibTypes.Void);
        var machine = new StaticMachine();

        machine.Execute(method);

        var remedy = Assert.Single(
            machine.State.Blockers.Blockers,
            entry => entry.Kind == BlockerKind.UnmodeledCall).Remedy;
        Assert.NotNull(remedy);
        Assert.Equal("{ \"inert\": true }", remedy.Value.Text);
        Assert.Null(remedy.Wants);
    }

    /// <summary>
    /// The sentence a person reads is the same statement as the value a program applies, so that
    /// acting on one and acting on the other cannot come to different files.
    /// </summary>
    [Fact]
    public void WhatIsPrintedAndWhatIsAppliedAreTheOneStatement()
    {
        var supplied = Declaring.Fact("registry:HKEY_CURRENT_USER\\Software\\X!blob");
        var complete = Declaring.Budget("steps", 750_000);

        Assert.Equal(
            "\"facts\": { \"registry:HKEY_CURRENT_USER\\\\Software\\\\X!blob\": <value> }",
            supplied.Describe());
        Assert.Equal("\"budgets\": { \"steps\": 10000000 }", complete.Describe());
    }

    /// <summary>
    /// An instruction the machine does not run cannot be declared away, and saying so is the useful
    /// answer: the next step is a change to the tool.
    /// </summary>
    [Fact]
    public void AnInstructionTheMachineDoesNotRunOffersNoDeclaration()
    {
        using var module = NewModule();
        var method = NewMethod(module, "Vararg", MethodSig.CreateStatic(module.CorLibTypes.Object));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Arglist));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        var machine = new StaticMachine();

        machine.Execute(method);

        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(BlockerKind.UnsupportedInstruction, blocker.Kind);
        Assert.Equal("arglist", blocker.Key);
        Assert.Null(blocker.Declare);
    }

    /// <summary>A method with nothing in it is a gap in the file rather than in the tool.</summary>
    [Fact]
    public void AMethodWithNoBodyIsRecordedAsOne()
    {
        using var module = NewModule();
        var method = new MethodDefUser(
            "Missing",
            MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.Abstract
        };
        module.Types.Add(new TypeDefUser("Tests", "Hollow", module.CorLibTypes.Object.TypeDefOrRef));
        module.Types[^1].Methods.Add(method);
        var machine = new StaticMachine();

        machine.Execute(method);

        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(BlockerKind.UnsupportedBody, blocker.Kind);
        Assert.Null(blocker.Declare);
    }

    /// <summary>
    /// A decision the machine could not make offers no remedy of its own and says why: the value it
    /// turned on was never produced, and the refusal that declined to produce it is the one to act on.
    /// </summary>
    [Fact]
    public void ABranchOnSomethingUnknownPointsAtTheEarlierRefusal()
    {
        using var module = NewModule();
        var method = NewMethod(module, "Decide", MethodSig.CreateStatic(
            module.CorLibTypes.Int32, module.CorLibTypes.Int32));
        var body = method.Body.Instructions;
        var landing = Instruction.Create(OpCodes.Ldc_I4_1);
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Brtrue, landing));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        body.Add(Instruction.Create(OpCodes.Ret));
        body.Add(landing);
        body.Add(Instruction.Create(OpCodes.Ret));
        var machine = new StaticMachine();

        machine.Execute(method, [StaticValue.Unknown]);

        var blocker = Assert.Single(
            machine.State.Blockers.Blockers,
            entry => entry.Kind == BlockerKind.UnknownValue);
        Assert.Null(blocker.Declare);
        Assert.Contains("earlier", blocker.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A throw nothing caught is the program's own decision rather than a gap in the tool, and it is
    /// recorded where it reached the top rather than at every frame it passed through.
    /// </summary>
    [Fact]
    public void AThrowNothingCaughtIsRecordedAsThePrograms()
    {
        using var module = NewModule();
        var method = NewMethod(module, "Refuse", MethodSig.CreateStatic(module.CorLibTypes.Void));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Throw));
        var machine = new StaticMachine();

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Threw, result.Status);
        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(BlockerKind.Threw, blocker.Kind);
        Assert.Null(blocker.Declare);
    }

    /// <summary>
    /// A throw a trial provoked is the trial working, not what stopped the run.
    /// </summary>
    /// <remarks>
    /// Virtualization reads an opcode by handing the engine's factory a stack the program never
    /// built and watching it refuse. That refusal is often a throw. Recording it as a stop would
    /// print the tool's own questions under BLOCKED, which is how a finished recovery of a
    /// virtualized method came to look like a crash.
    /// </remarks>
    [Fact]
    public void AThrowATrialProvokedIsNotWhatStoppedTheRun()
    {
        using var module = NewModule();
        var method = NewMethod(module, "Refuse", MethodSig.CreateStatic(module.CorLibTypes.Void));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Throw));
        var machine = new StaticMachine();

        using (machine.State.Blockers.Trying())
            Assert.Equal(StaticExecutionStatus.Threw, machine.Execute(method).Status);

        Assert.Empty(machine.State.Blockers.Blockers);
        Assert.Empty(machine.State.Blockers.Continuations);
    }

    /// <summary>
    /// The same stop met twice is one entry with a count, because a loader that asks the same thing a
    /// hundred times has told the reader everything the first time.
    /// </summary>
    [Fact]
    public void TheSameStopMetTwiceIsCountedRatherThanListedTwice()
    {
        using var module = NewModule();
        var machine = new StaticMachine();
        var method = Calls(
            module, "System", "Environment", "get_MachineName", module.CorLibTypes.String);

        machine.Execute(method);
        machine.Execute(method);

        var blocker = Assert.Single(machine.State.Blockers.Blockers);
        Assert.Equal(2, blocker.Times);
    }

    /// <summary>
    /// Two runs of the same thing produce the same account of it, because the tool interprets
    /// everything twice and compares, and an account that varied would be the thing that made two
    /// identical runs disagree.
    /// </summary>
    [Fact]
    public void TwoRunsAgreeOnWhatStoppedThem()
    {
        using var module = NewModule();
        var method = Calls(
            module, "System", "Environment", "get_UserName", module.CorLibTypes.String);
        var (unmodeled, _) = CallsUnmodeled(module, module.CorLibTypes.String);

        var first = new StaticMachine();
        first.Execute(method);
        first.Execute(unmodeled);
        var second = new StaticMachine();
        second.Execute(method);
        second.Execute(unmodeled);

        Assert.Equal(
            first.State.Blockers.Blockers.Select(blocker => (blocker.Kind, blocker.Key)),
            second.State.Blockers.Blockers.Select(blocker => (blocker.Kind, blocker.Key)));
    }

    /// <summary>
    /// A run has one environment and every machine in it shares it, which is what makes a fact stated
    /// once answered everywhere and a stop recorded once wherever it was met. Method-body recovery and
    /// string-table recovery used to build machines that saw neither.
    /// </summary>
    [Fact]
    public void EveryMachineInARunSharesOneEnvironment()
    {
        using var context = SyntheticContext.Build(module =>
            SyntheticContext.AddType(module, "Holder"));

        var environment = BootstrapMachine.Environment(context);

        Assert.Same(environment, BootstrapMachine.Environment(context));
        Assert.True(BootstrapMachine.TrySeed(context, 1_000, out var machine, out _));
        Assert.Same(environment, machine!.State.Environment);
        Assert.Same(environment.Blockers, machine.State.Blockers);
    }

    /// <summary>
    /// A stop met inside a pass lands in the run's ledger, so what an analyst reads afterwards is the
    /// account of the run rather than of whichever machine happened to notice first.
    /// </summary>
    [Fact]
    public void AStopMetInsideAPassLandsInTheRunsLedger()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            var asks = new MethodDefUser(
                "Named",
                MethodSig.CreateStatic(module.CorLibTypes.String))
            {
                Attributes = MethodAttributes.Public | MethodAttributes.Static,
                Body = new CilBody()
            };
            // A literal of its own is what makes the pass look at a method at all, since a method
            // that carries none is not shaped like a decoder.
            asks.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "prefix-"));
            asks.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            asks.Body.Instructions.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(
                module,
                "get_MachineName",
                MethodSig.CreateStatic(module.CorLibTypes.String),
                new TypeRefUser(
                    module, "System", "Environment", module.CorLibTypes.AssemblyRef))));
            asks.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(asks);
            var uses = new MethodDefUser(
                "Uses",
                MethodSig.CreateStatic(module.CorLibTypes.String))
            {
                Attributes = MethodAttributes.Public | MethodAttributes.Static,
                Body = new CilBody()
            };
            uses.Body.Instructions.Add(Instruction.Create(OpCodes.Call, asks));
            uses.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(uses);
        });
        context.SetFact(
            "reactor.structure",
            new ReactorStructureFacts(
                DelegateProxyCount: 0,
                DeadCallPrefixCount: 0,
                DispatcherMethodCount: 0,
                MethodStubCount: 0,
                StringResolverCount: 0,
                HighEntropyResourceCount: 0,
                VirtualizedMethodCount: 0,
                ReferencesClrJit: false,
                HasRuntimeModulePointerAccess: false,
                Capabilities: ReactorCapability.ProtectedStrings,
                Confidence: 1.0,
                Generation: "reactor6"));
        // The run says outright what it knows and what it will do about a gap, so that what reaches the
        // ledger is a consequence of the refusal under test rather than of a default.
        context.SetFact(
            BootstrapMachine.RunEnvironmentFact,
            new RunEnvironment(
                new HostEnvironment(HostProfile.Parse("""{ "facts": { } }""", "sparse")),
                strict: true));

        new ConstantStringPass().Run(context);

        Assert.Contains(
            BootstrapMachine.Environment(context).Blockers.Blockers,
            blocker => blocker.Kind == BlockerKind.UnstatedFact &&
                blocker.Key == "env:MachineName");
    }

    /// <summary>
    /// A machine told the least a profile can say, and told to refuse rather than assume.
    /// </summary>
    /// <remarks>
    /// Both halves are stated rather than inherited from the defaults. A test about how a refusal reads
    /// should not depend on the tool defaulting to refusing, since it no longer does.
    /// </remarks>
    private static StaticMachine Sparse()
    {
        var machine = new StaticMachine();
        machine.State.RegisterRunEnvironment(new RunEnvironment(
            new HostEnvironment(HostProfile.Parse("""{ "facts": { } }""", "sparse")),
            strict: true));
        return machine;
    }

    /// <summary>A method whose whole body is one call of a framework member and a return.</summary>
    private static MethodDefUser Calls(
        ModuleDefUser module,
        string space,
        string type,
        string member,
        TypeSig returns)
    {
        var declaring = new TypeRefUser(module, space, type, module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, $"Call{member}", MethodSig.CreateStatic(returns));
        method.Body.Instructions.Add(Instruction.Create(
            OpCodes.Call,
            new MemberRefUser(module, member, MethodSig.CreateStatic(returns), declaring)));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    /// <summary>
    /// A method that calls something nothing models, together with the signature it is known by.
    /// </summary>
    internal static (MethodDefUser Method, string Signature) CallsUnmodeled(
        ModuleDefUser module,
        TypeSig returns)
    {
        var declaring = new TypeRefUser(
            module, "Vendor.Support", "Licence", module.CorLibTypes.AssemblyRef);
        var member = new MemberRefUser(
            module, "Check", MethodSig.CreateStatic(returns), declaring);
        var method = NewMethod(module, "Ask", MethodSig.CreateStatic(returns));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, member));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return (method, member.FullName);
    }

    /// <summary>A method that goes round for ever, so that it can only end in a budget.</summary>
    private static MethodDefUser Loops(ModuleDefUser module)
    {
        var method = NewMethod(module, "Spin", MethodSig.CreateStatic(module.CorLibTypes.Void));
        var body = method.Body.Instructions;
        var again = Instruction.Create(OpCodes.Nop);
        body.Add(again);
        body.Add(Instruction.Create(OpCodes.Br, again));
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
        var method = NewMethod(
            module, $"Call{entry}", MethodSig.CreateStatic(module.CorLibTypes.Int32));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, imported));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    internal static ModuleDefUser NewModule()
    {
        var module = new ModuleDefUser("blockers.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("blockers", new Version(1, 0));
        assembly.Modules.Add(module);
        return module;
    }

    internal static MethodDefUser NewMethod(ModuleDef module, string name, MethodSig signature)
    {
        var method = new MethodDefUser(name, signature)
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        var type = module.Types.FirstOrDefault(item => item.Name == "Program");
        if (type is null)
        {
            type = new TypeDefUser("Tests", "Program", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);
        }

        type.Methods.Add(method);
        return method;
    }
}
