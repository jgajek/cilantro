using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Passes;

/// <summary>Exposes constant short-local reads used by Dotfuscator's dispatchers.</summary>
public sealed class DotfuscatorControlFlowPass : DeobfuscationPass
{
    public override string Name => "dotfuscator-control-flow";
    public override IReadOnlyCollection<string> Dependencies => ["dotfuscator-detection", "control-flow-completion"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<DotfuscatorStructureFacts>("dotfuscator.structure", out var facts) || facts?.IsDotfuscator != true)
            return (PassStatus.Success, 0, ["No Dotfuscator short-local normalization required."]);
        var total = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
        {
            var changed = Rewrite(method);
            if (changed == 0) continue;
            total += changed;
            context.AddChange(new(Name, "fold-short-local-read", method.FullName,
                $"Exposed {changed} constant signed-short read(s), retaining their original stores."));
        }
        return (PassStatus.Success, total, [$"Exposed {total} constant short-local reads for ordinary branch and dispatcher recovery."]);
    }

    internal static int Rewrite(MethodDef method)
    {
        using var transaction = new BodyMutationTransaction(method);
        var before = EvaluationStackAnalyzer.Analyze(method);
        if (!before.Valid) return 0;
        var graph = ControlFlowGraph.Build(method);
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        var targets = il.SelectMany(i => i.Operand is Instruction one ? new[] { one } :
            i.Operand is IList<Instruction> many ? many : []).ToHashSet();
        var changed = 0;
        for (var at = 1; at + 1 < il.Length; at++)
        {
            if (il[at].OpCode.Code is not (Code.Ldloca or Code.Ldloca_S) ||
                il[at].GetLocal(method.Body.Variables) is not { Type.ElementType: ElementType.I2 } local ||
                il[at + 1].OpCode.Code != Code.Ldind_I2 || targets.Contains(il[at]) || targets.Contains(il[at + 1])) continue;
            var store = at - 1;
            if (store < 1 || !il[store].IsStloc() || il[store].GetLocal(method.Body.Variables) != local ||
                !graph.HaveIdenticalExceptionRegions(il[store], il[at + 1]) ||
                Enumerable.Range(store + 1, at - store).Any(index => targets.Contains(il[index])) ||
                graph.BlockOf(il[store]) != graph.BlockOf(il[at + 1])) continue;
            int value;
            if (il[store - 1].IsLdcI4() && graph.BlockOf(il[store - 1]) == graph.BlockOf(il[store])) value = il[store - 1].GetLdcI4Value();
            else if (store >= 3 && il[store - 1].OpCode.Code is Code.Div or Code.Mul &&
                il[store - 2].IsLdcI4() && il[store - 3].IsLdcI4())
            {
                var left = il[store - 3].GetLdcI4Value();
                var right = il[store - 2].GetLdcI4Value();
                if (il[store - 1].OpCode.Code == Code.Div && (right == 0 || left == int.MinValue && right == -1) ||
                    graph.BlockOf(il[store - 3]) != graph.BlockOf(il[store])) continue;
                value = il[store - 1].OpCode.Code == Code.Div ? left / right : unchecked(left * right);
            }
            else continue;
            il[at].OpCode = OpCodes.Ldc_I4;
            il[at].Operand = (int)unchecked((short)value);
            il[at + 1].OpCode = OpCodes.Nop;
            il[at + 1].Operand = null;
            // A proven short value survives both conversions and the following
            // int32 store on either native width. Expose that int32 state directly.
            if (at + 4 < il.Length && il[at + 2].OpCode.Code == Code.Conv_I2 &&
                il[at + 3].OpCode.Code == Code.Conv_I && il[at + 4].IsStloc() &&
                il[at + 4].GetLocal(method.Body.Variables)?.Type.ElementType == ElementType.I4 &&
                graph.BlockOf(il[at]) == graph.BlockOf(il[at + 4]))
            {
                il[at + 2].OpCode = OpCodes.Nop;
                il[at + 2].Operand = null;
                il[at + 3].OpCode = OpCodes.Nop;
                il[at + 3].Operand = null;
            }
            changed++;
        }
        if (changed == 0 || !EvaluationStackAnalyzer.Analyze(method).Valid) return 0;
        transaction.Commit();
        return changed;
    }
}
