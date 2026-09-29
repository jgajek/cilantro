using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Passes;

/// <summary>Exposes late-proven singleton guards without discarding their initialization triggers.</summary>
public sealed class UnwrittenGuardCompletionPass : DeobfuscationPass
{
    public override string Name => "unwritten-guards-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["runtime-cleanup"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.foldUnwrittenState", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Unwritten-state assumptions are disabled."]);
        var proof = UnwrittenFields.Prove(context.Module);
        if (proof.Refusal is { } refusal) return (PassStatus.Success, 0, [refusal]);
        var guards = context.Module.GetTypes().SelectMany(t => t.Methods)
            .Select(m => (Method: m, Value: Guard(m, proof)))
            .Where(p => p.Value is not null).ToDictionary(p => p.Method, p => p.Value!.Value);
        if (guards.Count == 0) return (PassStatus.Success, 0, ["No late-proven singleton guards were found."]);
        using var batch = new BodyMutationBatch();
        var sites = 0;
        var folded = 0;
        var removed = 0;
        var simplified = 0;
        var paths = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            var il = method.Body.Instructions;
            var changed = false;
            for (var at = 0; at < il.Count; at++)
            {
                if (il[at].OpCode.Code != Code.Call || il[at].Operand is not IMethod called ||
                    called is MethodSpec || called.ResolveMethodDef() is not { } helper ||
                    !guards.TryGetValue(helper, out var value)) continue;
                var next = at + 1;
                while (next < il.Count && il[next].OpCode.Code == Code.Nop) next++;
                if (next == il.Count || il[next].OpCode.Code is not (Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S))
                    continue;
                batch.Capture(method);
                // Keep the call and the field read inside it: either can trigger initialization
                // or throw. Only the returned value is replaced, under the unwritten-field reading.
                il.Insert(at + 1, OpCodes.Pop.ToInstruction());
                il.Insert(at + 2, value ? OpCodes.Ldc_I4_1.ToInstruction() : OpCodes.Ldnull.ToInstruction());
                at += 2;
                sites++;
                changed = true;
                batch.RecordChange(context, new ChangeRecord(Name, "expose-unwritten-guard", method.FullName,
                    $"Retained {helper.FullName} and its initialization effects; exposed its {(value ? "true" : "null")} result."));
            }
            if (!changed) continue;
            method.Body.SimplifyBranches();
            method.Body.KeepOldMaxStack = false;
            var methodSimplified = false;
            for (var round = 0; round < 64; round++)
            {
                if (ControlFlowCompletionPass.TryComplete(method) is { } completed)
                {
                    folded += completed.Folded;
                    removed += completed.Removed;
                    methodSimplified |= completed.Folded + completed.Removed != 0;
                }
                var redirected = DispatcherPathPass.Rewrite(method);
                if (redirected == 0) break;
                paths += redirected;
            }
            if (methodSimplified) simplified++;
        }
        if (sites == 0) return (PassStatus.Success, 0, ["No proven singleton result directly guards a branch."]);
        if (!AssemblyVerifier.Verify(context.Module).Passed)
            return (PassStatus.Partial, 0, ["Guard completion failed structural verification; all changes were rolled back."]);
        batch.Commit();
        Accumulate("cfg.constantBranchesFolded", folded);
        Accumulate("cfg.unreachableInstructionsRemoved", removed);
        Accumulate("cfg.methodsSimplified", simplified);
        return (PassStatus.Success, sites,
            [$"Exposed {sites} singleton guard result(s), retaining helper calls and initialization effects; redirected {paths} dispatcher paths, folded {folded} branches and removed {removed} unreachable instructions."]);

        void Accumulate(string key, int count)
        {
            context.TryGetFact<int>(key, out var previous);
            context.SetFact(key, previous + count);
        }
    }

    // false means a null reference; true means the Boolean result of comparing it with null.
    private static bool? Guard(MethodDef method, UnwrittenFields proof)
    {
        if (!method.IsStatic || !method.HasBody || method.HasGenericParameters || method.DeclaringType.HasGenericParameters ||
            method.MethodSig.Params.Count != 0 || method.Body.ExceptionHandlers.Count != 0) return null;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Length is not (2 or 4) || il[0].OpCode.Code != Code.Ldsfld ||
            il[0].Operand is not IField field || field.ResolveFieldDef() is not { IsStatic: true } definition ||
            definition.Module != method.Module || !proof.Holds(field) ||
            field.FieldSig?.Type.ElementType is not (ElementType.Class or ElementType.Object or ElementType.String or ElementType.Array or ElementType.SZArray))
            return null;
        if (il.Length == 2 && il[1].OpCode.Code == Code.Ret &&
            method.ReturnType.ElementType is ElementType.Class or ElementType.Object or ElementType.String or ElementType.Array or ElementType.SZArray)
            return false;
        return il.Length == 4 && il[1].OpCode.Code == Code.Ldnull && il[2].OpCode.Code == Code.Ceq &&
            il[3].OpCode.Code == Code.Ret && method.ReturnType.ElementType == ElementType.Boolean ? true : null;
    }
}
