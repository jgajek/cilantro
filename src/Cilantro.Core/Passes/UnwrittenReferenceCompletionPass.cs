using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Passes;

/// <summary>Makes proven null returns explicit without removing initialization effects.</summary>
public sealed class UnwrittenReferenceCompletionPass : DeobfuscationPass
{
    public override string Name => "unwritten-reference-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["runtime-cleanup"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.foldUnwrittenState", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Unwritten-state assumptions are disabled."]);
        var proof = UnwrittenFields.Prove(context.Module);
        if (proof.Refusal is { } refusal) return (PassStatus.Success, 0, [refusal]);
        using var batch = new BodyMutationBatch();
        var changed = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods))
        {
            if (!method.IsStatic || !method.HasBody || method.HasGenericParameters ||
                method.DeclaringType.HasGenericParameters || method.MethodSig.Params.Count != 0 ||
                method.Body.ExceptionHandlers.Count != 0 || !Reference(method.ReturnType)) continue;
            var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            if (il.Length != 2 || il[0].OpCode.Code != Code.Ldsfld || il[1].OpCode.Code != Code.Ret ||
                il[0].Operand is not IField field || field.ResolveFieldDef() is not { IsStatic: true } definition ||
                definition.Module != context.Module || !Reference(field.FieldSig.Type) || !proof.Holds(field)) continue;
            batch.Capture(method);
            var at = method.Body.Instructions.IndexOf(il[0]);
            // Retain both the getter invocation and the read at their original locations:
            // either declaring type can initialize, produce observable effects, or throw.
            method.Body.Instructions.Insert(at + 1, OpCodes.Pop.ToInstruction());
            method.Body.Instructions.Insert(at + 2, OpCodes.Ldnull.ToInstruction());
            method.Body.KeepOldMaxStack = false;
            changed++;
            batch.RecordChange(context, new ChangeRecord(Name, "expose-unwritten-null-return", method.FullName,
                "Made the proven null return explicit, retaining the field read and initialization effects."));
        }
        if (!AssemblyVerifier.Verify(context.Module).Passed)
            return (PassStatus.Partial, 0, ["Null-return completion failed verification and was rolled back."]);
        batch.Commit();
        return (PassStatus.Success, changed, [$"Made {changed} proven null return(s) explicit, preserving initialization effects."]);
    }

    private static bool Reference(TypeSig type) => type.ElementType is
        ElementType.Class or ElementType.Object or ElementType.String or ElementType.Array or ElementType.SZArray;
}
