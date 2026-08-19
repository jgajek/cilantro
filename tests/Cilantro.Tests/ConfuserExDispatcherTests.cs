using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;

namespace Cilantro.Tests;

public sealed class ConfuserExDispatcherTests
{
    private const int Key = 0x5A5A5A5A;

    [Fact]
    public void ResolvesStackThreadedDispatcherAndRedirectsBothEdges()
    {
        using var fixture = CreateFlattened();

        var analysis = new ConfuserExDispatcherAnalyzer().Analyze(fixture.Method);

        Assert.Equal(DispatcherQualification.Qualified, analysis.Qualification);
        Assert.Equal(1, analysis.Plan!.Dispatchers);
        Assert.Equal(2, analysis.Plan.Rewrites.Count);
        Assert.Equal(0, analysis.Plan.ResidualEdges);

        var result = new DispatcherDeobfuscationPass().Rewrite(fixture.Method);

        Assert.Equal(DispatcherQualification.Qualified, result.Qualification);
        Assert.Equal(2, result.ChangedEdges);

        // The entry pushed a state selecting case 1, so it becomes a jump straight there.
        Assert.Equal(OpCodes.Br, fixture.EntryPush.OpCode);
        Assert.Same(fixture.Case1, fixture.EntryPush.Operand);

        // Case 1 computes a state selecting case 0, so its own jump goes straight there and the
        // arithmetic that produced the state is erased.
        Assert.Equal(OpCodes.Br, fixture.TransitionBranch.OpCode);
        Assert.Same(fixture.Case0, fixture.TransitionBranch.Operand);
        Assert.All(fixture.TransitionExpression,
            instruction => Assert.Equal(OpCodes.Nop, instruction.OpCode));

        // Nothing reaches the dispatcher once both its edges go straight to their case, and its own
        // arithmetic consumes a state that is no longer pushed, so leaving it would leave a method
        // that does not verify.
        Assert.Equal(OpCodes.Nop, fixture.Switch.OpCode);
    }

    /// <summary>
    /// Two paths sharing the jump into a dispatcher is what a branch in the original program becomes
    /// once flattened, so each path is resolved where it computed its own state.
    /// </summary>
    [Fact]
    public void RedirectsEachPathIntoAFragmentTwoStatesShare()
    {
        using var fixture = CreateTwoStateEdge();

        var analysis = new ConfuserExDispatcherAnalyzer().Analyze(fixture.Method);

        Assert.Equal(DispatcherQualification.Qualified, analysis.Qualification);
        Assert.Equal(2, analysis.Plan!.Rewrites.Count);
        Assert.Equal(0, analysis.Plan.ResidualEdges);

        // The shared jump is not what gets redirected; the two pushes behind it are.
        Assert.DoesNotContain(fixture.Ingress, analysis.Plan.Rewrites.Select(edge => edge.Branch));

        var result = new DispatcherDeobfuscationPass().Rewrite(fixture.Method);

        Assert.Equal(DispatcherQualification.Qualified, result.Qualification);
        Assert.Equal(OpCodes.Br, fixture.EntryPush.OpCode);
    }

    /// <summary>
    /// One unprovable edge no longer costs the method its provable ones.
    /// </summary>
    [Fact]
    public void RedirectsTheProvableEdgeAndLeavesTheSharedOneToItsDispatcher()
    {
        using var fixture = CreatePartiallyResolvable();

        var analysis = new ConfuserExDispatcherAnalyzer().Analyze(fixture.Method);

        Assert.Equal(DispatcherQualification.Qualified, analysis.Qualification);
        Assert.Single(analysis.Plan!.Rewrites);
        Assert.Equal(1, analysis.Plan.ResidualEdges);
        Assert.Equal(
            1,
            analysis.Plan.Declines[ConfuserExEdgeDecline.SharedFragment]);

        var result = new DispatcherDeobfuscationPass().Rewrite(fixture.Method);

        Assert.Equal(DispatcherQualification.Qualified, result.Qualification);
        Assert.Equal(1, result.ChangedEdges);

        // The entry edge goes straight to its case.
        Assert.Equal(OpCodes.Br, fixture.EntryPush.OpCode);
        Assert.Same(fixture.Case1, fixture.EntryPush.Operand);

        // The edge two states share still goes through the dispatcher, which is why the dispatcher
        // is still there to be gone through. It hands over the state it computed in the variable the
        // dispatcher now reads instead of on the stack.
        var instructions = fixture.Method.Body.Instructions;
        Assert.Equal(OpCodes.Stloc, fixture.Ingress.OpCode);
        var handover = instructions[instructions.IndexOf(fixture.Ingress) + 1];
        Assert.Equal(OpCodes.Br, handover.OpCode);
        Assert.Same(fixture.DispatcherKey, handover.Operand);
        Assert.Equal(OpCodes.Switch, fixture.Switch.OpCode);
    }

    /// <summary>
    /// The dispatcher takes its state from a variable once an edge is redirected past it, because
    /// the redirected edge was the one forward path that made jumping back to it legal.
    /// </summary>
    [Fact]
    public void HandsTheDispatcherItsStateInAVariableWhenAnEdgeIsRedirectedPastIt()
    {
        using var fixture = CreatePartiallyResolvable();

        var analysis = new ConfuserExDispatcherAnalyzer().Analyze(fixture.Method);
        var relocation = Assert.Single(analysis.Plan!.Relocations);

        Assert.Same(fixture.DispatcherKey, relocation.Head);
        Assert.Equal(Key, relocation.Key);
        Assert.Contains(fixture.Ingress, relocation.Branches);

        new DispatcherDeobfuscationPass().Rewrite(fixture.Method);

        // The head becomes the load, the key moves behind it, and the surviving jump stores the
        // state it computed rather than leaving it on the stack.
        var instructions = fixture.Method.Body.Instructions;
        Assert.Equal(OpCodes.Ldloc, fixture.DispatcherKey.OpCode);
        var entry = Assert.IsType<Local>(fixture.DispatcherKey.Operand);
        Assert.Equal(OpCodes.Ldc_I4, instructions[instructions.IndexOf(fixture.DispatcherKey) + 1].OpCode);
        Assert.Equal(OpCodes.Stloc, fixture.Ingress.OpCode);
        Assert.Same(entry, fixture.Ingress.Operand);
        Assert.Equal(OpCodes.Br, instructions[instructions.IndexOf(fixture.Ingress) + 1].OpCode);
    }

    /// <summary>
    /// Where the state outlives the arithmetic, the redirect has to make the assignment the
    /// dispatcher would have made, or the surviving read sees whatever was there before.
    /// </summary>
    [Fact]
    public void AssignsTheStateWhenSomethingStillReadsIt()
    {
        using var fixture = CreateFlattenedWithSurvivingStateRead();

        var analysis = new ConfuserExDispatcherAnalyzer().Analyze(fixture.Method);

        Assert.Equal(DispatcherQualification.Qualified, analysis.Qualification);
        Assert.Equal(2, analysis.Plan!.Rewrites.Count);
        Assert.All(analysis.Plan.Rewrites,
            rewrite => Assert.Same(fixture.State, rewrite.RestoredStateLocal));

        var result = new DispatcherDeobfuscationPass().Rewrite(fixture.Method);

        Assert.Equal(DispatcherQualification.Qualified, result.Qualification);

        // The entry pushed the state selecting case 1, so it becomes that state's assignment
        // followed by a jump there, rather than the jump alone.
        AssertAssigns(fixture.Method, fixture.EntryPush, 1, fixture.State, fixture.Case1);

        // The fragment's own transition does the same for case 0, and the arithmetic that computed
        // the state it pushed is gone.
        AssertAssigns(fixture.Method, fixture.TransitionBranch, 0, fixture.State, fixture.Case0);
        Assert.All(fixture.TransitionExpression,
            instruction => Assert.Equal(OpCodes.Nop, instruction.OpCode));
    }

    /// <summary>
    /// Two states can pick the same case, since the case comes from a remainder. That is enough to
    /// redirect the edge but not enough to assign the state, so where the state is read it is left.
    /// </summary>
    [Fact]
    public void DeclinesWhenTwoStatesShareACaseAndTheStateIsRead()
    {
        using var fixture = CreateSharedCaseWithSurvivingStateRead();

        var analysis = new ConfuserExDispatcherAnalyzer().Analyze(fixture.Method);

        Assert.Equal(1, analysis.Plan!.Declines[ConfuserExEdgeDecline.VaryingState]);
        Assert.Contains(analysis.Diagnostics,
            diagnostic => diagnostic.Contains("no one value to assign", StringComparison.Ordinal));

        // The two entry edges each settle on one state, so they are redirected and assign it, while
        // the edge whose state was not settled is left rather than being guessed at.
        Assert.Equal(2, analysis.Plan.Rewrites.Count);
        Assert.All(analysis.Plan.Rewrites,
            rewrite => Assert.Same(fixture.State, rewrite.RestoredStateLocal));
        Assert.DoesNotContain(fixture.Ingress, analysis.Plan.Rewrites.Select(edge => edge.Branch));

        var result = new DispatcherDeobfuscationPass().Rewrite(fixture.Method);

        Assert.Equal(DispatcherQualification.Qualified, result.Qualification);
        Assert.Equal(2, result.ChangedEdges);
    }

    /// <summary>
    /// Asserts that an edge became <c>ldc.i4 state; stloc state; br target</c> in place.
    /// </summary>
    private static void AssertAssigns(
        MethodDef method,
        Instruction edge,
        int state,
        Local local,
        Instruction target)
    {
        var instructions = method.Body.Instructions;
        var at = instructions.IndexOf(edge);
        Assert.Equal(OpCodes.Ldc_I4, edge.OpCode);
        Assert.Equal(state, edge.Operand);
        Assert.Equal(OpCodes.Stloc, instructions[at + 1].OpCode);
        Assert.Same(local, instructions[at + 1].Operand);
        Assert.Equal(OpCodes.Br, instructions[at + 2].OpCode);
        Assert.Same(target, instructions[at + 2].Operand);
    }

    [Fact]
    public void DeclinesWhenTheStateLocalAddressEscapes()
    {
        using var fixture = CreateFlattened();
        var instructions = fixture.Method.Body.Instructions;
        var caseIndex = instructions.IndexOf(fixture.Case1);
        instructions.Insert(caseIndex + 1, Instruction.Create(OpCodes.Ldloca, fixture.State));
        instructions.Insert(caseIndex + 2, Instruction.Create(OpCodes.Pop));

        var analysis = new ConfuserExDispatcherAnalyzer().Analyze(fixture.Method);

        Assert.Equal(DispatcherQualification.Ambiguous, analysis.Qualification);
        Assert.Contains(analysis.Diagnostics,
            diagnostic => diagnostic.Contains("address taken", StringComparison.Ordinal));
    }

    [Fact]
    public void IgnoresASwitchWithoutTheConfuserExShape()
    {
        using var fixture = CreatePlainSwitch();

        var analysis = new ConfuserExDispatcherAnalyzer().Analyze(fixture.Method);

        Assert.Equal(DispatcherQualification.NotCandidate, analysis.Qualification);
        Assert.Null(analysis.Plan);
    }

    /// <summary>
    /// Mirrors ConfuserEx's flattener: the next state arrives on the evaluation stack, the
    /// dispatcher mixes it with a key and picks a case by remainder, and each fragment derives the
    /// next state from the one the dispatcher stored.
    /// </summary>
    private static Fixture CreateFlattened()
    {
        var (module, method, state) = CreateMethod();

        // A pushed value of (1 ^ Key) makes the dispatcher store state 1, which selects case 1.
        var entryPush = Instruction.Create(OpCodes.Ldc_I4, 1 ^ Key);
        var dispatcherKey = Instruction.Create(OpCodes.Ldc_I4, Key);
        var case0 = Instruction.Create(OpCodes.Ret);
        var case1 = Instruction.Create(OpCodes.Nop);
        var case2 = Instruction.Create(OpCodes.Ret);
        var dispatcherSwitch = Instruction.Create(OpCodes.Switch, new[] { case0, case1, case2 });

        // (state * 1) ^ (Key ^ 1) is Key when state is 1, and a pushed Key stores state 0, so this
        // fragment selects case 0.
        var expression = new[]
        {
            Instruction.Create(OpCodes.Ldloc, state),
            Instruction.Create(OpCodes.Ldc_I4_1),
            Instruction.Create(OpCodes.Mul),
            Instruction.Create(OpCodes.Ldc_I4, Key ^ 1),
            Instruction.Create(OpCodes.Xor)
        };
        var transitionBranch = Instruction.Create(OpCodes.Br, dispatcherKey);

        var instructions = method.Body.Instructions;
        instructions.Add(entryPush);
        instructions.Add(dispatcherKey);
        instructions.Add(Instruction.Create(OpCodes.Xor));
        instructions.Add(Instruction.Create(OpCodes.Dup));
        instructions.Add(Instruction.Create(OpCodes.Stloc, state));
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_3));
        instructions.Add(Instruction.Create(OpCodes.Rem_Un));
        instructions.Add(dispatcherSwitch);
        instructions.Add(case0);
        instructions.Add(case1);
        foreach (var instruction in expression)
            instructions.Add(instruction);
        instructions.Add(transitionBranch);
        instructions.Add(case2);

        return new Fixture(module, method, state, entryPush, dispatcherKey, dispatcherSwitch,
            case0, case1, expression, transitionBranch, transitionBranch);
    }

    /// <summary>
    /// Two paths push different states and share the jump into the dispatcher, so that jump has no
    /// single case to be redirected to.
    /// </summary>
    private static Fixture CreateTwoStateEdge()
    {
        var (module, method, state) = CreateMethod();

        var secondPush = Instruction.Create(OpCodes.Ldc_I4, 2 ^ Key);
        var dispatcherKey = Instruction.Create(OpCodes.Ldc_I4, Key);
        var ingress = Instruction.Create(OpCodes.Br, dispatcherKey);
        var case0 = Instruction.Create(OpCodes.Ret);
        var case1 = Instruction.Create(OpCodes.Ret);
        var case2 = Instruction.Create(OpCodes.Ret);
        var dispatcherSwitch = Instruction.Create(OpCodes.Switch, new[] { case0, case1, case2 });

        var instructions = method.Body.Instructions;
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        instructions.Add(Instruction.Create(OpCodes.Brtrue, secondPush));
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 1 ^ Key));
        instructions.Add(Instruction.Create(OpCodes.Br, ingress));
        instructions.Add(secondPush);
        instructions.Add(ingress);
        instructions.Add(dispatcherKey);
        instructions.Add(Instruction.Create(OpCodes.Xor));
        instructions.Add(Instruction.Create(OpCodes.Dup));
        instructions.Add(Instruction.Create(OpCodes.Stloc, state));
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_3));
        instructions.Add(Instruction.Create(OpCodes.Rem_Un));
        instructions.Add(dispatcherSwitch);
        instructions.Add(case0);
        instructions.Add(case1);
        instructions.Add(case2);

        return new Fixture(module, method, state, secondPush, dispatcherKey, dispatcherSwitch,
            case0, case1, [], ingress, ingress);
    }

    /// <summary>
    /// A method with one edge whose state is settled and one edge two states share, so that what
    /// happens to each of them can be told apart.
    /// </summary>
    /// <remarks>
    /// The two states meet before either has finished being computed, so neither the shared jump nor
    /// the last thing to push is attributable to one path. That is what puts this edge out of reach
    /// where a merge of two finished states would not be.
    /// </remarks>
    private static Fixture CreatePartiallyResolvable()
    {
        var (module, method, state) = CreateMethod();

        var entryPush = Instruction.Create(OpCodes.Ldc_I4, 1 ^ Key);
        var dispatcherKey = Instruction.Create(OpCodes.Ldc_I4, Key);
        var case0 = Instruction.Create(OpCodes.Ret);
        var case1 = Instruction.Create(OpCodes.Ldc_I4_0);
        var case2 = Instruction.Create(OpCodes.Ret);
        var dispatcherSwitch = Instruction.Create(OpCodes.Switch, new[] { case0, case1, case2 });
        var secondPush = Instruction.Create(OpCodes.Ldc_I4, 2 ^ Key ^ 7);
        var merge = Instruction.Create(OpCodes.Ldc_I4_7);
        var shared = Instruction.Create(OpCodes.Br, dispatcherKey);

        var instructions = method.Body.Instructions;
        instructions.Add(entryPush);
        instructions.Add(dispatcherKey);
        instructions.Add(Instruction.Create(OpCodes.Xor));
        instructions.Add(Instruction.Create(OpCodes.Dup));
        instructions.Add(Instruction.Create(OpCodes.Stloc, state));
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_3));
        instructions.Add(Instruction.Create(OpCodes.Rem_Un));
        instructions.Add(dispatcherSwitch);
        instructions.Add(case0);
        // Both arms of the branch push half of a state and finish computing it together, one
        // selecting case 1 and one case 2. The shared jump has two states, and so does the last
        // instruction to push, so neither of them names a single path.
        instructions.Add(case1);
        instructions.Add(Instruction.Create(OpCodes.Brtrue, secondPush));
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 1 ^ Key ^ 7));
        instructions.Add(Instruction.Create(OpCodes.Br, merge));
        instructions.Add(secondPush);
        instructions.Add(merge);
        instructions.Add(Instruction.Create(OpCodes.Xor));
        instructions.Add(shared);
        instructions.Add(case2);

        return new Fixture(module, method, state, entryPush, dispatcherKey, dispatcherSwitch,
            case0, case1, [], shared, shared);
    }

    /// <summary>
    /// As <see cref="CreateFlattened"/>, but a fragment reads the state outside the arithmetic that
    /// a redirect would erase, so the redirects have to assign it.
    /// </summary>
    private static Fixture CreateFlattenedWithSurvivingStateRead()
    {
        var (module, method, state) = CreateMethod();

        var entryPush = Instruction.Create(OpCodes.Ldc_I4, 1 ^ Key);
        var dispatcherKey = Instruction.Create(OpCodes.Ldc_I4, Key);
        var case0 = Instruction.Create(OpCodes.Ret);
        var case1 = Instruction.Create(OpCodes.Ldloc, state);
        var case2 = Instruction.Create(OpCodes.Ret);
        var dispatcherSwitch = Instruction.Create(OpCodes.Switch, new[] { case0, case1, case2 });
        var transitionPush = Instruction.Create(OpCodes.Ldc_I4, 0 ^ Key);
        var transitionBranch = Instruction.Create(OpCodes.Br, dispatcherKey);

        var instructions = method.Body.Instructions;
        instructions.Add(entryPush);
        instructions.Add(dispatcherKey);
        instructions.Add(Instruction.Create(OpCodes.Xor));
        instructions.Add(Instruction.Create(OpCodes.Dup));
        instructions.Add(Instruction.Create(OpCodes.Stloc, state));
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_3));
        instructions.Add(Instruction.Create(OpCodes.Rem_Un));
        instructions.Add(dispatcherSwitch);
        instructions.Add(case0);
        // The read is what makes the assignment necessary: it is not part of the state expression,
        // so no redirect erases it.
        instructions.Add(case1);
        instructions.Add(Instruction.Create(OpCodes.Pop));
        instructions.Add(transitionPush);
        instructions.Add(transitionBranch);
        instructions.Add(case2);

        return new Fixture(module, method, state, entryPush, dispatcherKey, dispatcherSwitch,
            case0, case1, [transitionPush], transitionBranch, transitionBranch);
    }

    /// <summary>
    /// A fragment entered with two states whose remainders coincide, so the case it leaves for is
    /// settled while the state that chose it is not, with the state read somewhere that survives.
    /// </summary>
    /// <remarks>
    /// States 1 and 4 both leave remainder 1 against three cases, so both enter case 1. Case 1
    /// transitions on <c>state ^ Key</c>, which the dispatcher's own key undoes, so it selects case
    /// 1 again from either state: one case, two states. The two entry edges each get their own jump
    /// into the dispatcher rather than sharing one, since a shared jump would be declined for being
    /// jumped to before the states were ever compared.
    /// </remarks>
    private static Fixture CreateSharedCaseWithSurvivingStateRead()
    {
        var (module, method, state) = CreateMethod();

        var dispatcherKey = Instruction.Create(OpCodes.Ldc_I4, Key);
        var case0 = Instruction.Create(OpCodes.Ldloc, state);
        var case1 = Instruction.Create(OpCodes.Ldloc, state);
        var case2 = Instruction.Create(OpCodes.Ret);
        var dispatcherSwitch = Instruction.Create(OpCodes.Switch, new[] { case0, case1, case2 });
        var firstPush = Instruction.Create(OpCodes.Ldc_I4, 1 ^ Key);
        var secondPush = Instruction.Create(OpCodes.Ldc_I4, 4 ^ Key);
        var shared = Instruction.Create(OpCodes.Br, dispatcherKey);

        var instructions = method.Body.Instructions;
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        instructions.Add(Instruction.Create(OpCodes.Brtrue, secondPush));
        instructions.Add(firstPush);
        instructions.Add(Instruction.Create(OpCodes.Br, dispatcherKey));
        instructions.Add(secondPush);
        instructions.Add(Instruction.Create(OpCodes.Br, dispatcherKey));
        instructions.Add(dispatcherKey);
        instructions.Add(Instruction.Create(OpCodes.Xor));
        instructions.Add(Instruction.Create(OpCodes.Dup));
        instructions.Add(Instruction.Create(OpCodes.Stloc, state));
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_3));
        instructions.Add(Instruction.Create(OpCodes.Rem_Un));
        instructions.Add(dispatcherSwitch);
        // Read outside any state expression, which is what makes assigning the state necessary.
        instructions.Add(case0);
        instructions.Add(Instruction.Create(OpCodes.Pop));
        instructions.Add(Instruction.Create(OpCodes.Ret));
        instructions.Add(case1);
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4, Key));
        instructions.Add(Instruction.Create(OpCodes.Xor));
        instructions.Add(shared);
        instructions.Add(case2);

        return new Fixture(module, method, state, firstPush, dispatcherKey, dispatcherSwitch,
            case0, case1, [], shared, shared);
    }

    private static Fixture CreatePlainSwitch()
    {
        var (module, method, state) = CreateMethod();
        var case0 = Instruction.Create(OpCodes.Ret);
        var case1 = Instruction.Create(OpCodes.Ret);
        var dispatcherSwitch = Instruction.Create(OpCodes.Switch, new[] { case0, case1 });

        var instructions = method.Body.Instructions;
        instructions.Add(Instruction.Create(OpCodes.Ldloc, state));
        instructions.Add(dispatcherSwitch);
        instructions.Add(case0);
        instructions.Add(case1);

        return new Fixture(module, method, state, case0, case0, dispatcherSwitch, case0, case1,
            [], case0, case0);
    }

    private static (ModuleDefUser Module, MethodDef Method, Local State) CreateMethod()
    {
        var module = new ModuleDefUser("confuserex-dispatcher.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("confuserex-dispatcher", new Version(1, 0));
        assembly.Modules.Add(module);
        var type = new TypeDefUser("", "Fixture", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);

        var method = new MethodDefUser(
            "Flattened",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static);
        method.Body = new CilBody { InitLocals = true };
        var state = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(state);
        type.Methods.Add(method);
        return (module, method, state);
    }

    private sealed record Fixture(
        ModuleDefUser Module,
        MethodDef Method,
        Local State,
        Instruction EntryPush,
        Instruction DispatcherKey,
        Instruction Switch,
        Instruction Case0,
        Instruction Case1,
        IReadOnlyList<Instruction> TransitionExpression,
        Instruction TransitionBranch,
        Instruction Ingress) : IDisposable
    {
        public void Dispose() => Module.Dispose();
    }
}
