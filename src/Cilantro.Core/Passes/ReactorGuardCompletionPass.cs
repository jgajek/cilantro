using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Passes;

/// <summary>Removes reconstructed Reactor guard decisions under the protector-cleanup contract.</summary>
public sealed class ReactorGuardCompletionPass : DeobfuscationPass
{
    public override string Name => "reactor-guards-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["dispatcher-effects-completion"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Protector metadata cleanup is disabled; guard pools retained."]);
        var pools = ReactorGuardPool.Find(context.Module);
        var replaced = 0;
        var refused = 0;
        var removedFields = 0;
        foreach (var pool in pools)
        {
            // A single small helper retains the original ldsfld initialization trigger
            // and ldfld null check, including recursive entry during the cctor's prefix.
            // Neither a captured value nor successful initialization on another trial
            // justifies dropping those effects.
            var touch = pool.Owner.Methods.FirstOrDefault(m => IsTouch(m, pool));
            var added = touch is null;
            if (touch is null)
            {
                var name = "EnsureProtectorInitialized";
                while (pool.Owner.Methods.Any(m => m.Name == name)) name += "_";
                touch = new MethodDefUser(name, MethodSig.CreateStatic(context.Module.CorLibTypes.Void),
                    MethodAttributes.Assembly | MethodAttributes.Static) { Body = new CilBody() };
                touch.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(pool.Root));
                touch.Body.Instructions.Add(OpCodes.Ldfld.ToInstruction(pool.Values.Keys.First()));
                touch.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                touch.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                pool.Owner.Methods.Add(touch);
            }
            var poolChanges = 0;
            foreach (var group in pool.Reads.Where(r => r.Method != touch).GroupBy(r => r.Method))
            {
                var method = group.Key;
                using var transaction = new BodyMutationTransaction(method);
                var oldStack = EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count;
                var oldForward = ForwardScan.Unnameable(method);
                foreach (var (_, root, read) in group)
                {
                    var value = pool.Values[((IField)read.Operand).ResolveFieldDef()!];
                    root.OpCode = OpCodes.Call; root.Operand = touch;
                    read.OpCode = OpCodes.Ldc_I4; read.Operand = value;
                }
                ControlFlowCompletionPass.TryComplete(method);
                RemoveRepeatedChecks(method, touch);
                ControlFlowCompletionPass.TryComplete(method);
                method.Body.SimplifyBranches();
                method.Body.OptimizeBranches();
                if (EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count > oldStack || ForwardScan.Unnameable(method) > oldForward)
                { refused++; continue; }
                transaction.Commit();
                poolChanges += group.Count();
                context.AddChange(new ChangeRecord(Name, "remove-reactor-guard", method.FullName,
                    $"Replaced {group.Count()} closed Reactor pool read(s) with reconstructed literals; retained initialization/null-check effects. " +
                    "Uses the protector-metadata cleanup contract, excluding computed reflection over that protector pool."));
            }
            if (poolChanges == 0 && added) pool.Owner.Methods.Remove(touch);
            else if (added)
            {
                context.TryGetFact<int>(VirtualizationRebuildPass.AddedMethodsFact, out var methodsAdded);
                context.SetFact(VirtualizationRebuildPass.AddedMethodsFact, methodsAdded + 1);
            }
            if (poolChanges != 0 && poolChanges == pool.Reads.Count(r => r.Method != touch))
            {
                // All application uses have been replaced. Physically remove the
                // identified protector metadata under the same cleanup contract; do
                // not leave apparently writable state whose values callers ignore.
                var construction = pool.Initializer.Body.Instructions.First(i => i.OpCode.Code == Code.Newobj);
                pool.Initializer.Body.Instructions.Clear();
                pool.Initializer.Body.Instructions.Add(construction);
                pool.Initializer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(pool.Root));
                pool.Initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                var done = OpCodes.Ret.ToInstruction();
                touch.Body.Instructions.Clear();
                touch.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(pool.Root));
                touch.Body.Instructions.Add(OpCodes.Brtrue.ToInstruction(done));
                touch.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                touch.Body.Instructions.Add(OpCodes.Throw.ToInstruction());
                touch.Body.Instructions.Add(done);
                foreach (var field in pool.Values.Keys) pool.Owner.Fields.Remove(field);
                removedFields += pool.Values.Count;
                context.AddChange(new ChangeRecord(Name, "remove-reactor-guard-fields", pool.Owner.FullName,
                    $"Removed {pool.Values.Count} reconstructed constant fields and their assignments; retained the original object publication and initializer prefix/suffix. " +
                    $"{touch.FullName} retains initialization and null-check exceptions. Removed field tokens: " +
                    string.Join(", ", pool.Values.Keys.Select(f => $"0x{f.MDToken.Raw:X8}")) + "."));
            }
            replaced += poolChanges;
        }
        context.TryGetFact<int>("cleanup.removedFieldCount", out var previousRemoved);
        context.SetFact("cleanup.removedFieldCount", previousRemoved + removedFields);
        context.SetFact("cfg.reactorGuardReadsReplaced", replaced);
        return (refused == 0 ? PassStatus.Success : PassStatus.Partial, replaced,
            [$"Removed {replaced} Reactor guard read(s) and {removedFields} protector integer field(s) in {pools.Count} closed reconstructed pool(s); retained initialization effects; rolled back {refused} method(s). " +
             "Computed reflection over the identified protector pool is excluded by protector-metadata cleanup; general field-write safety was not relaxed."]);
    }

    private static void RemoveRepeatedChecks(MethodDef method, MethodDef touch)
    {
        var graph = ControlFlowGraph.Build(method);
        var entries = method.Body.ExceptionHandlers.SelectMany(e => e.FilterStart is { } filter
            ? new[] { e.HandlerStart, filter } : new[] { e.HandlerStart }).ToHashSet();
        var known = graph.Blocks.ToDictionary(b => b, _ => false);
        bool Calls(Instruction i) => i.OpCode.Code == Code.Call && i.Operand is IMethod c && c.ResolveMethodDef() == touch;
        bool Incoming(BasicBlock b) => b != graph.Entry && !entries.Contains(b.First) && b.Predecessors.Count != 0 &&
            b.Predecessors.All(e => e.Kind != ControlFlowEdgeKind.Exception && known[e.Source]);
        var pending = new Queue<BasicBlock>(graph.Blocks);
        var queued = graph.Blocks.ToHashSet();
        while (pending.TryDequeue(out var block))
        {
            queued.Remove(block);
            if (known[block] || !(Incoming(block) || block.Instructions.Any(Calls))) continue;
            known[block] = true;
            foreach (var edge in block.Successors)
                if (queued.Add(edge.Target)) pending.Enqueue(edge.Target);
        }
        foreach (var block in graph.Blocks)
        {
            var checkedAlready = Incoming(block);
            foreach (var instruction in block.Instructions.Where(Calls))
            {
                if (checkedAlready) { instruction.OpCode = OpCodes.Nop; instruction.Operand = null; }
                checkedAlready = true;
            }
        }
    }

    private static bool IsTouch(MethodDef method, ReactorGuardPool pool)
    {
        if (!method.Name.String.StartsWith("EnsureProtectorInitialized", StringComparison.Ordinal) || !method.IsStatic ||
            !method.HasBody || method.HasGenericParameters || method.MethodSig.Params.Count != 0 ||
            method.ReturnType.ElementType != ElementType.Void || method.Body.HasExceptionHandlers) return false;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        return il.Length == 4 && il[0].OpCode.Code == Code.Ldsfld && il[0].Operand is IField root && root.ResolveFieldDef() == pool.Root &&
            il[1].OpCode.Code == Code.Ldfld && il[1].Operand is IField field && field.ResolveFieldDef() is { } definition && pool.Values.ContainsKey(definition) &&
            il[2].OpCode.Code == Code.Pop && il[3].OpCode.Code == Code.Ret;
    }
}
