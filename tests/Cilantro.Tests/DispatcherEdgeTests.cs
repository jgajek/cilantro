using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Tests;

/// <summary>
/// Covers proving the jumps into a dispatcher one at a time, which is what
/// <see cref="DispatcherAnalyzer.AnalyzePartial"/> does for the methods the whole-method proof in
/// <see cref="DispatcherAnalyzer.Analyze"/> cannot close.
/// </summary>
/// <remarks>
/// The whole-method proof had been reporting nothing on real Reactor output — zero of three on one
/// sample, zero of forty-four on another — and the reasons were all the same kind: it looks for one
/// exact shape, a block reading an int32 variable and switching on it, entered only by blocks that
/// assign that variable a constant and jump. Reactor writes three variations on that shape which
/// the proof called no dispatcher at all, and each is a test below: the state arrives on the
/// evaluation stack rather than in a variable, the switch is over the state less an offset, and the
/// block assigning the state runs off its end into the dispatcher instead of jumping to it.
/// </remarks>
public sealed class DispatcherEdgeTests
{
    /// <summary>
    /// Reactor's usual dispatcher is entered with the state pushed rather than stored, which the
    /// whole-method proof does not recognize at all. It is still a dispatcher, and a block that
    /// pushes a constant into it still has one destination.
    /// </summary>
    [Fact]
    public void ProvesAJumpIntoADispatcherFedFromTheStack()
    {
        var method = Flattened(Dispatch.FromStack, bias: 0, fallsThrough: false);

        var result = new DispatcherAnalyzer().AnalyzePartial(method);

        Assert.True(result.IsQualified);
        var edge = Assert.Single(result.Plan!.Rewrites);
        Assert.Equal(1, edge.State);
        Assert.Same(Cases(method)[1], edge.Target);
        // Nothing is put back on the stack, so what pushed the state goes with the jump.
        Assert.NotEmpty(edge.RemovedInstructions);
        Assert.Null(edge.RestoredStateLocal);
    }

    /// <summary>
    /// The states a flattener numbers blocks with do not start at zero, so the dispatcher subtracts
    /// where they do start. The offset belongs to the index, not to the value assigned.
    /// </summary>
    [Fact]
    public void AppliesTheDispatchersOffsetToTheConstantAnEdgeAssigns()
    {
        var method = Flattened(Dispatch.FromLocal, bias: 40, fallsThrough: false);

        var result = new DispatcherAnalyzer().AnalyzePartial(method);

        var edge = Assert.Single(result.Plan!.Rewrites);
        // The block assigns 41 and the dispatcher switches on the state less 40, so the case taken
        // is the second, not the forty-second — which does not exist.
        Assert.Equal(41, edge.State);
        Assert.Same(Cases(method)[1], edge.Target);
    }

    /// <summary>
    /// A block laid out directly above the dispatcher reaches it by running off its end. That is
    /// the same handover as a jump, and the instruction that becomes the jump is the last one the
    /// block already has.
    /// </summary>
    [Fact]
    public void ProvesAnEdgeThatFallsIntoTheDispatcherRatherThanJumping()
    {
        var method = Flattened(Dispatch.FromLocal, bias: 0, fallsThrough: true);

        var result = new DispatcherAnalyzer().AnalyzePartial(method);

        var edge = Assert.Single(result.Plan!.Rewrites);
        Assert.Same(Cases(method)[1], edge.Target);
    }

    /// <summary>
    /// Where the state is a variable, the redirect assigns it on the way past. The dispatcher it
    /// skips is what would have done that, and it is left standing for the edges still going
    /// through it, so anything reading the variable has to find what it would have found.
    /// </summary>
    [Fact]
    public void ARedirectPastADispatcherStillAssignsTheStateItSkips()
    {
        var method = Flattened(Dispatch.FromLocal, bias: 0, fallsThrough: false);

        var result = new DispatcherAnalyzer().AnalyzePartial(method);

        var edge = Assert.Single(result.Plan!.Rewrites);
        Assert.Same(method.Body.Variables[0], edge.RestoredStateLocal);
    }

    /// <summary>
    /// A state naming no case is not an unproven edge. A switch handed one falls through to
    /// whatever follows it, so where the jump goes is settled either way.
    /// </summary>
    [Fact]
    public void AStateOutsideTheCasesGoesWhereTheSwitchWouldHaveFallen()
    {
        var method = Flattened(Dispatch.FromLocal, bias: 0, fallsThrough: false, state: 9);

        var result = new DispatcherAnalyzer().AnalyzePartial(method);

        var edge = Assert.Single(result.Plan!.Rewrites);
        var instructions = method.Body.Instructions;
        var after = instructions[instructions.IndexOf(Switch(method)) + 1];
        Assert.Same(after, edge.Target);
    }

    /// <summary>
    /// An edge whose state is not a constant is left going through the dispatcher, and said to be,
    /// so the shortfall is a named limit rather than a number with nothing behind it.
    /// </summary>
    [Fact]
    public void AnEdgeWhoseStateIsNotConstantIsLeftAloneAndAccountedFor()
    {
        var method = Flattened(Dispatch.FromLocal, bias: 0, fallsThrough: false);
        // The argument stands where the constant did, so nothing can say which case is taken.
        var instructions = method.Body.Instructions;
        var constant = instructions.First(instruction =>
            instruction.OpCode.Code is Code.Ldc_I4 or Code.Ldc_I4_1);
        constant.OpCode = OpCodes.Ldarg_0;
        constant.Operand = null;

        var result = new DispatcherAnalyzer().AnalyzePartial(method);

        Assert.False(result.IsQualified);
        Assert.Equal(
            1,
            result.Plan?.Declines.GetValueOrDefault(DispatcherEdgeDecline.UnprovenExpression) ?? 1);
    }

    private enum Dispatch
    {
        FromLocal,
        FromStack
    }

    private static IList<Instruction> Cases(MethodDefUser method) =>
        (IList<Instruction>)Switch(method).Operand;

    private static Instruction Switch(MethodDefUser method) =>
        method.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Switch);

    /// <summary>
    /// A method with one dispatcher and one block handing over to it, in whichever of the shapes
    /// the test is about.
    /// </summary>
    private static MethodDefUser Flattened(
        Dispatch dispatch,
        int bias,
        bool fallsThrough,
        int? state = null)
    {
        var module = new ModuleDefUser("Fixture", Guid.NewGuid());
        var method = new MethodDefUser(
            "Flattened",
            MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Assembly | MethodAttributes.Static,
            ImplAttributes = MethodImplAttributes.IL | MethodImplAttributes.Managed,
            Body = new CilBody()
        };
        var type = new TypeDefUser("Host") { Attributes = TypeAttributes.Class };
        type.Methods.Add(method);
        module.Types.Add(type);

        var local = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(local);

        var case0 = Instruction.Create(OpCodes.Ret);
        var case1 = Instruction.Create(OpCodes.Ret);
        var fallthrough = Instruction.Create(OpCodes.Ret);
        var head = dispatch == Dispatch.FromLocal
            ? Instruction.Create(OpCodes.Ldloc, local)
            : (bias == 0 ? null : Instruction.Create(OpCodes.Ldc_I4, bias));
        var switchInstruction = Instruction.Create(OpCodes.Switch, new[] { case0, case1 });

        var instructions = method.Body.Instructions;
        // The block that hands over: it computes the state, and either jumps or runs off its end.
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4, state ?? (1 + bias)));
        if (dispatch == Dispatch.FromLocal)
            instructions.Add(Instruction.Create(OpCodes.Stloc, local));

        // The dispatcher's first instruction, which is what a jump into it has to target.
        var entry = head ?? switchInstruction;
        if (!fallsThrough)
            instructions.Add(Instruction.Create(OpCodes.Br, entry));

        if (head is not null)
            instructions.Add(head);
        if (bias != 0 && dispatch == Dispatch.FromLocal)
        {
            instructions.Add(Instruction.Create(OpCodes.Ldc_I4, bias));
            instructions.Add(Instruction.Create(OpCodes.Sub));
        }
        else if (bias != 0)
        {
            instructions.Add(Instruction.Create(OpCodes.Sub));
        }

        instructions.Add(switchInstruction);
        instructions.Add(fallthrough);
        instructions.Add(case0);
        instructions.Add(case1);

        if (fallsThrough)
        {
            // A dispatcher only reached by falling into it is not a block of its own, and is not
            // what a flattener produces either: something else always jumps to it. This one hands
            // over a state nothing can resolve, so it stands as the second way in without being a
            // second provable edge.
            instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            instructions.Add(Instruction.Create(OpCodes.Stloc, local));
            instructions.Add(Instruction.Create(OpCodes.Br, entry));
        }

        method.Body.UpdateInstructionOffsets();
        return method;
    }
}
