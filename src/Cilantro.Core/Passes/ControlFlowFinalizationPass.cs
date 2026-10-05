using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Passes;

/// <summary>Consumes constant helpers and dispatcher edges exposed by late recovery.</summary>
public sealed class ControlFlowFinalizationPass : DeobfuscationPass
{
    public override string Name => "control-flow-finalization";
    public override IReadOnlyCollection<string> Dependencies => ["reactor-guards-completion"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        Dictionary<MethodDef, MethodBehaviour.Constant> Catalog() => methods
            .Where(m => !m.Body.HasExceptionHandlers && !m.DeclaringType.HasGenericParameters)
            .Select(m => (Method: m, Constant: MethodBehaviour.AsConstant(m)))
            .Where(p => p.Constant is not null).ToDictionary(p => p.Method, p => p.Constant!.Value);
        var helpers = Catalog();
        var pending = methods;
        var total = 0;
        var rolledBack = 0;
        var bounded = 0;
        while (pending.Length != 0)
        {
            foreach (var method in pending)
            {
                using var transaction = new BodyMutationTransaction(method);
                var oldStack = EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count;
                var oldForward = ForwardScan.Unnameable(method);
                var changed = 0;
                var il = method.Body.Instructions;
                for (var at = 0; at < il.Count; at++)
                {
                    if (il[at].OpCode.Code != Code.Call || il[at].Operand is not IMethod called || called is MethodSpec ||
                        called.ResolveMethodDef() is not { } helper || !helpers.TryGetValue(helper, out var constant)) continue;
                    var next = at + 1;
                    while (next < il.Count && il[next].OpCode.Code == Code.Nop) next++;
                    if (next < il.Count && il[next].OpCode.Code == Code.Pop) continue;
                    // Keep the call's type-initialization trigger and exceptions. Only its
                    // proven return value is exposed; no application call is executed here.
                    il.Insert(++at, OpCodes.Pop.ToInstruction());
                    il.Insert(++at, constant switch
                    {
                        MethodBehaviour.Constant.True => OpCodes.Ldc_I4_1.ToInstruction(),
                        MethodBehaviour.Constant.False => OpCodes.Ldc_I4_0.ToInstruction(),
                        _ => OpCodes.Ldnull.ToInstruction()
                    });
                    changed++;
                }
                for (var round = 0; round < 64; round++)
                {
                    var completion = ControlFlowCompletionPass.TryComplete(method);
                    if (completion is { } result) changed += result.Folded + result.Removed;
                    var edges = new DispatcherDeobfuscationPass().Rewrite(method).ChangedEdges;
                    edges += DispatcherPathPass.Rewrite(method, preserveEffects: true);
                    changed += edges;
                    if (edges == 0) break;
                    if (round == 63) bounded++;
                }
                if (ControlFlowCompletionPass.TryComplete(method) is { } last)
                    changed += last.Folded + last.Removed;
                foreach (var head in ForwardScan.Unnamed(method))
                    if (StackHandoff.Repair(method, head)) changed++;
                method.Body.SimplifyBranches();
                method.Body.OptimizeBranches();
                if (EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count > oldStack || ForwardScan.Unnameable(method) > oldForward)
                {
                    rolledBack++;
                    continue;
                }
                transaction.Commit();
                if (changed == 0) continue;
                total += changed;
                context.AddChange(new ChangeRecord(Name, "finalize-control-flow", method.FullName,
                    $"Applied {changed} proven simplification(s), preserving helper calls and unknown switch selectors."));
            }
            // A helper can become constant only after its own cleanup. Revisit its
            // callers regardless of metadata order. Each helper enters the catalog
            // once, so this worklist terminates without repeatedly sweeping the module.
            var discovered = Catalog().Where(p => !helpers.ContainsKey(p.Key)).ToDictionary();
            foreach (var pair in discovered) helpers.Add(pair.Key, pair.Value);
            pending = discovered.Count == 0 ? [] : methods.Where(m => m.Body.Instructions.Any(i =>
                i.OpCode.Code == Code.Call && i.Operand is IMethod called && called is not MethodSpec &&
                called.ResolveMethodDef() is { } target && discovered.ContainsKey(target))).ToArray();
        }
        return (PassStatus.Success, total,
            [$"Applied {total} late control-flow simplification(s); rolled back {rolledBack} method(s) at verification and reached the round bound in {bounded} method(s)."]);
    }
}
