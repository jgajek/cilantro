using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Replaces reads of proven loader-initialized state with the constants they always produce.
/// </summary>
/// <remarks>
/// Reactor guards ordinary application code with conditions of the form "load the state singleton,
/// load one of its integer fields, branch". The field is written once by the loader and never
/// again, so the branch has a fixed outcome, but nothing in the method body reveals it. Substituting
/// the proven constant turns each guard into a constant branch, which control-flow completion then
/// folds and whose dead arm it deletes. That is what makes the surrounding scaffolding unreferenced
/// and therefore removable.
///
/// A value proven at load time is only a constant for the whole program if nothing can write the
/// field afterwards, so each field must pass a write-safety proof before any of its reads are
/// folded: every writer must lie inside the initialization closure, no method in that closure may be
/// callable from outside it, and the field's address must never be taken. A field failing any of
/// these keeps all of its reads. The pass also refuses entirely when the module can write fields
/// reflectively, because no call-graph argument bounds that.
/// </remarks>
public sealed class GlobalPredicateFoldingPass : DeobfuscationPass
{
    public override string Name => "global-predicate-folding";
    public override IReadOnlyCollection<string> Dependencies => ["global-state-capture"];

    /// <remarks>
    /// Every outcome short of success leaves the module byte-for-byte as it was: the write-safety
    /// proof runs before any rewrite, and a rewrite that fails verification is rolled back and
    /// reported as a failure, which the pipeline treats as fatal separately. Declining to fold is
    /// therefore a missed simplification rather than a half-transformed module, and withholding an
    /// otherwise verified assembly over it would trade a real result for a cosmetic one.
    /// </remarks>
    public override bool GatesEmission => false;

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (!context.TryGetFact<CapturedGlobalState>("globals.state", out var state) || state is null)
            return (PassStatus.Success, 0, ["No loader-initialized state was proven to fold."]);

        var safety = FieldWriteSafety.Analyze(context.Module);
        if (safety.Refusal is not null)
            return (PassStatus.Unsupported, 0, [safety.Refusal, "No read site was modified."]);

        var instance = state.InstanceFields
            .Where(entry => safety.IsWriteOnceDuringInitialization(entry.Key))
            .ToDictionary(entry => entry.Key, entry => entry.Value);
        var statics = state.StaticFields
            .Where(entry => safety.IsWriteOnceDuringInitialization(entry.Key))
            .ToDictionary(entry => entry.Key, entry => entry.Value);
        var rejected = state.Count - instance.Count - statics.Count;
        if (instance.Count == 0 && statics.Count == 0)
        {
            return (PassStatus.Success, 0,
                [$"None of the {state.Count} proven field(s) survived the write-safety proof."]);
        }

        var changes = 0;
        var methodsRewritten = 0;
        using var transaction = new InstructionMutationTransaction();
        foreach (var method in context.Module.GetTypes()
                     .SelectMany(type => type.Methods)
                     .Where(method => method.HasBody && method.Body.Instructions.Count != 0))
        {
            var folded = FoldReads(method, instance, statics, transaction);
            if (folded == 0)
                continue;
            changes += folded;
            methodsRewritten++;
            context.AddChange(new ChangeRecord(
                Name,
                "fold-global-state-read",
                $"{method.MDToken} {method.FullName}",
                $"Folded {folded} read(s) of proven loader-initialized state."));
        }

        if (changes == 0)
        {
            return (PassStatus.Success, 0,
                [$"No read site matched the {instance.Count + statics.Count} write-safe field(s)."]);
        }

        var verification = AssemblyVerifier.Verify(context.Module);
        if (!verification.Passed)
        {
            transaction.Rollback();
            return (PassStatus.Failed, 0,
                ["Folding loader-initialized state failed verification and was rolled back."]);
        }

        transaction.Commit();
        return (PassStatus.Success, changes,
        [
            $"Folded {changes} read(s) of loader-initialized state across {methodsRewritten} method(s).",
            $"Used {instance.Count} instance and {statics.Count} static write-safe field(s); " +
            $"{rejected} proven field(s) were rejected as not write-once."
        ]);
    }

    /// <summary>
    /// Rewrites the two read shapes Reactor emits, leaving the evaluation stack unchanged.
    /// </summary>
    /// <remarks>
    /// A static read is one instruction and swaps directly for the constant. An instance read is the
    /// pair "load the singleton, load its field", which pushes exactly one value overall; replacing
    /// the pair with "nop, load constant" pushes the same one value, so the rewrite is stack-neutral
    /// whether or not control flow enters at the first instruction. It is refused when the field
    /// load is itself a branch target or an exception boundary, because flow arriving there would
    /// not have pushed the singleton the original instruction consumed.
    /// </remarks>
    private static int FoldReads(
        MethodDef method,
        Dictionary<uint, int> instanceFields,
        Dictionary<uint, int> staticFields,
        InstructionMutationTransaction transaction)
    {
        var instructions = method.Body.Instructions;
        var entryPoints = CollectEntryPoints(method);
        var folded = 0;
        for (var index = 0; index < instructions.Count; index++)
        {
            var instruction = instructions[index];
            if (instruction.Operand is not IField field)
                continue;
            var token = field.ResolveFieldDef()?.MDToken.Raw ?? field.MDToken.Raw;

            if (instruction.OpCode.Code == Code.Ldsfld &&
                staticFields.TryGetValue(token, out var staticValue))
            {
                transaction.Capture(instruction);
                Load(instruction, staticValue);
                folded++;
                continue;
            }

            if (instruction.OpCode.Code != Code.Ldfld ||
                index == 0 ||
                !instanceFields.TryGetValue(token, out var value) ||
                entryPoints.Contains(instruction))
            {
                continue;
            }

            var producer = instructions[index - 1];
            if (!IsSideEffectFreeReferenceLoad(producer))
                continue;
            transaction.Capture(producer);
            transaction.Capture(instruction);
            producer.OpCode = OpCodes.Nop;
            producer.Operand = null;
            Load(instruction, value);
            folded++;
        }
        return folded;

        static void Load(Instruction instruction, int value)
        {
            instruction.OpCode = OpCodes.Ldc_I4;
            instruction.Operand = value;
        }
    }

    /// <summary>
    /// Whether an instruction pushes an object reference without observable effect, so removing it
    /// removes nothing else.
    /// </summary>
    /// <remarks>
    /// Reactor reaches the singleton either directly through its static field or through a getter
    /// that does nothing but return that field. The getter is accepted only after reading its body
    /// and confirming it is exactly that, so a getter with any other content is left alone.
    /// </remarks>
    private static bool IsSideEffectFreeReferenceLoad(Instruction instruction)
    {
        if (instruction.OpCode.Code == Code.Ldsfld)
            return true;
        if (instruction.OpCode.Code != Code.Call ||
            instruction.Operand is not IMethod called ||
            called.ResolveMethodDef() is not { HasBody: true } getter ||
            getter.MethodSig?.Params.Count != 0)
        {
            return false;
        }

        var body = getter.Body.Instructions
            .Where(item => item.OpCode.Code != Code.Nop)
            .ToArray();
        return body.Length == 2 &&
            body[0].OpCode.Code == Code.Ldsfld &&
            body[1].OpCode.Code == Code.Ret;
    }

    /// <summary>
    /// Instructions control flow can reach other than by falling through the previous one.
    /// </summary>
    private static HashSet<Instruction> CollectEntryPoints(MethodDef method)
    {
        var entryPoints = new HashSet<Instruction>();
        foreach (var instruction in method.Body.Instructions)
        {
            switch (instruction.Operand)
            {
                case Instruction target:
                    entryPoints.Add(target);
                    break;
                case IList<Instruction> targets:
                    foreach (var target in targets)
                        entryPoints.Add(target);
                    break;
            }
        }

        foreach (var handler in method.Body.ExceptionHandlers)
        {
            Add(handler.TryStart);
            Add(handler.TryEnd);
            Add(handler.HandlerStart);
            Add(handler.HandlerEnd);
            Add(handler.FilterStart);
        }
        return entryPoints;

        void Add(Instruction? boundary)
        {
            if (boundary is not null)
                entryPoints.Add(boundary);
        }
    }
}
