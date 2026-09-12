using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Tests;

/// <summary>
/// Covers what <see cref="EvaluationStackAnalyzer"/> takes each instruction to do to the stack.
/// </summary>
/// <remarks>
/// This is read as a precondition rather than as a report: the dispatcher rewrite asks whether a
/// method's stack is consistent before it will touch it, and preserves the method when the answer
/// is no. So an instruction modelled wrongly does not produce a wrong number in a report, it
/// quietly withdraws the rewrite from every method containing that instruction. Two were, and
/// between them they cover array stores and every exit from a try or catch, which is most of the
/// methods anybody would want unflattened.
///
/// The cases below are the shapes that exposed them, kept because both bugs were invisible except
/// where two paths meet: a wrong depth on its own is just a wrong number, and only a merge turns it
/// into a verdict.
/// </remarks>
public sealed class StackAnalysisTests
{
    /// <summary>
    /// A store into an array takes the array, the index and the value, and leaves nothing.
    /// </summary>
    /// <remarks>
    /// The typed forms — <c>stelem.i4</c> and the rest — were modelled. The one carrying a type
    /// token was not, and fell through to being taken to leave all three where they were, so every
    /// array store raised the modelled depth by three for the remainder of the method. The
    /// unprotected build of one of the corpus libraries was called unverifiable for this reason,
    /// which is as clear a statement as there is that the analysis, not the module, was wrong.
    /// </remarks>
    [Fact]
    public void AStoreIntoAnArrayTakesTheArrayTheIndexAndTheValueOffTheStack()
    {
        using var module = Module();
        var method = Static(
            module,
            "Store",
            new SZArraySig(module.CorLibTypes.Object),
            module.CorLibTypes.Boolean);
        var instructions = method.Body.Instructions;
        var join = Instruction.Create(OpCodes.Ret);

        // One path stores into the array and one skips it, so the two meet at the return with
        // whatever the store was taken to have left behind.
        instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
        instructions.Add(Instruction.Create(OpCodes.Brfalse, join));
        instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        instructions.Add(Instruction.Create(OpCodes.Ldnull));
        instructions.Add(Instruction.Create(OpCodes.Stelem, module.CorLibTypes.Object.ToTypeDefOrRef()));
        instructions.Add(join);

        var result = EvaluationStackAnalyzer.Analyze(method);

        Assert.True(result.Valid, string.Join("; ", result.Diagnostics));
        // Three at its deepest, and nothing left standing on either path into the return.
        Assert.Equal(3, result.MaximumDepth);
    }

    /// <summary>
    /// Leaving a protected region empties the stack rather than taking a fixed count off it.
    /// </summary>
    /// <remarks>
    /// ECMA-335 III.3.55. Carrying the depth across a <c>leave</c> instead made any try whose
    /// guarded expression was part-evaluated at the exit disagree with every other path to the same
    /// destination, which is the ordinary shape of a <c>catch</c> around an expression.
    /// </remarks>
    [Fact]
    public void LeavingAProtectedRegionEmptiesTheStack()
    {
        using var module = Module();
        var method = Static(module, "Guarded", module.CorLibTypes.Boolean);
        var instructions = method.Body.Instructions;
        var join = Instruction.Create(OpCodes.Ret);
        var guarded = Instruction.Create(OpCodes.Ldc_I4_1);
        var handler = Instruction.Create(OpCodes.Endfinally);

        // A path that reaches the return without entering the region at all, so that what the
        // region's exit is taken to leave behind has something to disagree with.
        instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        instructions.Add(Instruction.Create(OpCodes.Brtrue, join));
        instructions.Add(guarded);
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_2));
        // Two values still on the stack, which leaving discards.
        instructions.Add(Instruction.Create(OpCodes.Leave, join));
        instructions.Add(handler);
        instructions.Add(join);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
        {
            TryStart = guarded,
            TryEnd = handler,
            HandlerStart = handler,
            HandlerEnd = join
        });

        var result = EvaluationStackAnalyzer.Analyze(method);

        Assert.True(result.Valid, string.Join("; ", result.Diagnostics));
    }

    private static ModuleDefUser Module() =>
        new("stack.dll") { Kind = ModuleKind.Dll, RuntimeVersion = "v4.0.30319" };

    private static MethodDefUser Static(
        ModuleDefUser module,
        string name,
        params TypeSig[] parameters)
    {
        var method = new MethodDefUser(
            name, MethodSig.CreateStatic(module.CorLibTypes.Void, parameters))
        {
            Body = new CilBody()
        };
        return method;
    }
}
