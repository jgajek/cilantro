using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Passes;

/// <summary>
/// Reads what a field nothing writes must hold, and writes that into the code that reads it.
/// </summary>
/// <remarks>
/// Reactor builds its opaque predicates out of a singleton it declares and never assigns. Every
/// guard reached through one is therefore decidable — the reference is null, so a comparison
/// against null is true and a dereference of it throws — but until something decides them the
/// state machine they sit in cannot be decided either. The jumps into a dispatcher can be proved
/// one at a time and made direct, which is what the earlier pass does, yet no whole-method proof
/// closes and the method stays a switch inside a loop with the arms still wired together through
/// predicates nobody has read.
///
/// Two rewrites follow from <see cref="UnwrittenFields"/>, and both leave the program doing exactly
/// what it did.
///
/// A read of the field becomes the value the field holds. This is the same rewrite the loader-state
/// folding does, from a different proof: that one knows what initialization put in the field, this
/// one knows nothing ever put anything in it.
///
/// A dereference of the field becomes the throw it already was. <c>ldfld</c> on null raises
/// <see cref="NullReferenceException"/>, and so does <c>throw</c> on null, so replacing one with
/// the other keeps both the exception and the type of it while saying plainly that nothing past
/// this point runs. That is what lets the arm be deleted: the instructions after it are no longer
/// reachable, and the dispatcher edge leading to it no longer leads anywhere the state machine has
/// to account for. A dereference the code can also arrive at by a jump is left alone, because then
/// the null is not what is necessarily on the stack when it runs.
///
/// The conclusion is a reading rather than a proof — reflection can name a field without the module
/// showing which — so a strict run does not draw it, and the count of reflective writes that could
/// have been the exception is reported either way.
/// </remarks>
public sealed class UnwrittenFieldFoldingPass : DeobfuscationPass
{
    public override string Name => "unwritten-field-folding";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery"];

    /// <summary>How many static fields were proven to hold what the runtime left in them.</summary>
    internal const string ProvenFact = "fields.unwrittenProven";

    /// <summary>How many reads of one became the value it holds.</summary>
    internal const string FoldedFact = "fields.unwrittenReadsFolded";

    /// <summary>How many dereferences of a null one were written as the throw they were.</summary>
    internal const string ThrownFact = "fields.nullDereferencesNamed";

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!context.TryGetFact<bool>("options.foldUnwrittenState", out var enabled) || !enabled)
        {
            return (PassStatus.Success, 0,
                ["Fields were left as they read, this run drawing nothing from what writes them."]);
        }

        var unwritten = UnwrittenFields.Prove(context.Module);
        context.SetFact(ProvenFact, unwritten.Count);
        if (unwritten.Refusal is { } refusal)
            return (PassStatus.Success, 0, [refusal]);
        if (unwritten.Count == 0)
        {
            return (PassStatus.Success, 0,
                ["Every static field this module reads is written somewhere in it."]);
        }

        var folded = 0;
        var thrown = 0;
        using (var transaction = new InstructionMutationTransaction())
        {
            var bodies = context.Module.GetTypes()
                .SelectMany(type => type.Methods)
                .Where(method => method.HasBody)
                .ToArray();

            foreach (var method in bodies)
            {
                foreach (var instruction in method.Body.Instructions)
                {
                    if (instruction.OpCode.Code != Code.Ldsfld ||
                        instruction.Operand is not IField read ||
                        !unwritten.Holds(read) ||
                        Held(read) is not var (opcode, operand))
                    {
                        continue;
                    }
                    transaction.Capture(instruction);
                    instruction.OpCode = opcode;
                    instruction.Operand = operand;
                    folded++;
                    context.AddChange(new ChangeRecord(
                        Name,
                        "fold-unwritten-field-read",
                        $"{method.MDToken} IL_{instruction.Offset:X4}",
                        $"{read.Name} is never written, so it reads as " +
                        $"{(opcode == OpCodes.Ldnull ? "null" : "zero")}."));
                }
            }

            // The nulls are all in place before anything is concluded from one, so a dereference is
            // judged against the whole module's reading rather than the part of it walked so far.
            foreach (var method in bodies)
            {
                var instructions = method.Body.Instructions;
                var entered = Entered(method);
                for (var index = 1; index < instructions.Count; index++)
                {
                    var instruction = instructions[index];
                    if (instructions[index - 1].OpCode.Code != Code.Ldnull ||
                        instruction.OpCode.Code is not (Code.Ldfld or Code.Ldflda) ||
                        entered.Contains(instruction))
                    {
                        continue;
                    }
                    transaction.Capture(instruction);
                    instruction.OpCode = OpCodes.Throw;
                    instruction.Operand = null;
                    thrown++;
                    context.AddChange(new ChangeRecord(
                        Name,
                        "name-null-dereference",
                        $"{method.MDToken} IL_{instruction.Offset:X4}",
                        "Reading a field of a reference that is never assigned throws, and is " +
                        "written as the throw it was."));
                }
            }

            var verification = AssemblyVerifier.Verify(context.Module);
            if (!verification.Passed)
            {
                transaction.Rollback();
                return (PassStatus.Partial, 0,
                [
                    "Reading the unwritten fields as what they hold did not verify, and was undone."
                ]);
            }
            transaction.Commit();
        }

        context.SetFact(FoldedFact, folded);
        context.SetFact(ThrownFact, thrown);

        return (PassStatus.Success, folded + thrown,
        [
            $"Read {unwritten.Count} static field(s) nothing in this module writes as the value " +
            $"the runtime left in them, at {folded} load(s), of which {thrown} dereference(s) of " +
            "one holding null were written as the throw they already were."
        ]);
    }

    /// <summary>
    /// The value a field of this type holds before anything writes it, where one instruction can
    /// say it. A struct and a pointer take more than one and are left alone.
    /// </summary>
    private static (OpCode OpCode, object? Operand)? Held(IField field) =>
        field.FieldSig?.Type?.RemovePinnedAndModifiers()?.ElementType switch
        {
            ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1 or
                ElementType.I2 or ElementType.U2 or ElementType.I4 or ElementType.U4 =>
                (OpCodes.Ldc_I4_0, null),
            ElementType.I8 or ElementType.U8 => (OpCodes.Ldc_I8, 0L),
            ElementType.R4 => (OpCodes.Ldc_R4, 0f),
            ElementType.R8 => (OpCodes.Ldc_R8, 0d),
            ElementType.String or ElementType.Object or ElementType.Class or ElementType.Array or
                ElementType.SZArray => (OpCodes.Ldnull, null),
            _ => null
        };

    /// <summary>Every instruction the code can arrive at other than by falling into it.</summary>
    private static HashSet<Instruction> Entered(MethodDef method)
    {
        var entered = new HashSet<Instruction>();
        foreach (var instruction in method.Body.Instructions)
        {
            switch (instruction.Operand)
            {
                case Instruction target:
                    entered.Add(target);
                    break;
                case IList<Instruction> table:
                    foreach (var target in table)
                        entered.Add(target);
                    break;
            }
        }
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            foreach (var edge in new[]
                {
                    handler.TryStart, handler.TryEnd, handler.HandlerStart, handler.HandlerEnd,
                    handler.FilterStart
                })
            {
                if (edge is not null)
                    entered.Add(edge);
            }
        }
        return entered;
    }
}
