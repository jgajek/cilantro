using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Passes;

/// <summary>Removes reconstructed Reactor guard decisions under the protector-cleanup contract.</summary>
public sealed class ReactorGuardCompletionPass : DeobfuscationPass
{
    internal const string CompletedPoolsFact = "cleanup.completedReactorPools";
    internal sealed record CompletedPool(TypeDef Owner, FieldDef Root, MethodDef Initializer, MethodDef Touch);
    public override string Name => "reactor-guards-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["dispatcher-effects-completion"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Protector metadata cleanup is disabled; guard pools retained."]);
        CompleteOrdinaryInitializers(context);
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
                    $"Replaced {group.Count()} closed Reactor pool read(s) with proven literals; retained initialization/null-check effects. " +
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
                if (!context.TryGetFact<List<CompletedPool>>(CompletedPoolsFact, out var completed) || completed is null)
                    context.SetFact(CompletedPoolsFact, completed = []);
                completed.Add(new(pool.Owner, pool.Root, pool.Initializer, touch));
                removedFields += pool.Values.Count;
                context.AddChange(new ChangeRecord(Name, "remove-reactor-guard-fields", pool.Owner.FullName,
                    $"Removed {pool.Values.Count} proven constant fields and their assignments; retained the original object publication and initializer prefix/suffix. " +
                    $"{touch.FullName} retains initialization and null-check exceptions. Removed field tokens: " +
                    string.Join(", ", pool.Values.Keys.Select(f => $"0x{f.MDToken.Raw:X8}")) + "."));
            }
            replaced += poolChanges;
        }
        context.TryGetFact<int>("cleanup.removedFieldCount", out var previousRemoved);
        context.SetFact("cleanup.removedFieldCount", previousRemoved + removedFields);
        context.SetFact("cfg.reactorGuardReadsReplaced", replaced);
        return (refused == 0 ? PassStatus.Success : PassStatus.Partial, replaced,
            [$"Removed {replaced} Reactor guard read(s) and {removedFields} protector integer field(s) in {pools.Count} closed Reactor pool(s); retained initialization effects; rolled back {refused} method(s). " +
             "Computed reflection over the identified protector pool is excluded by protector-metadata cleanup; general field-write safety was not relaxed."]);
    }

    private void CompleteOrdinaryInitializers(ArtifactContext context)
    {
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        foreach (var owner in context.Module.GetTypes().Where(ReactorGuardPool.IsOrdinaryPool))
        {
            // Only fold same-owner helper calls inside the pool initializer. Its
            // cctor is already running, so these reads add no initialization trigger.
            // General application field reasoning retains its reflection refusal.
            var nulls = owner.Fields.Where(f => f.IsStatic && !f.HasConstant && !f.HasFieldRVA &&
                f.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() == owner &&
                !methods.Any(m => m.Body.Instructions.Any(i => i.Operand is IField r && r.ResolveFieldDef() == f &&
                    i.OpCode.Code != Code.Ldsfld))).ToHashSet();
            var helpers = new Dictionary<MethodDef, bool>();
            foreach (var helper in owner.Methods.Where(m => m.HasBody && m.IsStatic && !m.HasGenericParameters &&
                m.MethodSig.Params.Count == 0 && !m.Body.HasExceptionHandlers))
            {
                var il = helper.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                if (il.Length < 2 || il[^1].OpCode.Code != Code.Ret) continue;
                // Earlier unwritten-state folding may already have replaced the
                // load with null. It remains a same-owner, effect-free helper.
                var loadsNull = il[0].OpCode.Code == Code.Ldnull ||
                    il[0].OpCode.Code == Code.Ldsfld && il[0].Operand is IField field &&
                    field.ResolveFieldDef() is { } definition && nulls.Contains(definition);
                if (!loadsNull)
                {
                    if (il.Length == 2 && il[0].IsLdcI4() && il[0].GetLdcI4Value() == 1 &&
                        helper.ReturnType.ElementType == ElementType.Boolean) helpers.Add(helper, true);
                    continue;
                }
                if (il.Length == 2 && helper.ReturnType.ToTypeDefOrRef()?.ResolveTypeDef() == owner) helpers.Add(helper, false);
                else if (il.Length == 4 && il[1].OpCode.Code == Code.Ldnull && il[2].OpCode.Code == Code.Ceq &&
                    helper.ReturnType.ElementType == ElementType.Boolean) helpers.Add(helper, true);
            }
            if (helpers.Count == 0) continue;
            foreach (var initializer in owner.Methods.Where(m => m.HasBody && m.IsStatic && !m.HasGenericParameters &&
                m.MethodSig.Params.Count == 0 && m.ReturnType.ElementType == ElementType.Void && !m.IsStaticConstructor))
            {
                using var transaction = new BodyMutationTransaction(initializer);
                var calls = 0;
                foreach (var i in initializer.Body.Instructions)
                {
                    if (i.OpCode.Code != Code.Call || i.Operand is not IMethod call || call is MethodSpec ||
                        call.ResolveMethodDef() is not { } helper || !helpers.TryGetValue(helper, out var value)) continue;
                    i.OpCode = value ? OpCodes.Ldc_I4_1 : OpCodes.Ldnull;
                    i.Operand = null;
                    calls++;
                }
                if (calls == 0 || ControlFlowCompletionPass.TryComplete(initializer) is null ||
                    // Reconstruction can put the writes in a lifted child while
                    // the original wrapper retains the guard calls. The same
                    // closed construction proof must include the edited wrapper.
                    !ReactorGuardPool.Find(context.Module, includeUnused: true).Any(p => p.InitializerChain.Contains(initializer))) continue;
                transaction.Commit();
                context.AddChange(new ChangeRecord(Name, "complete-reactor-pool-initializer", initializer.FullName,
                    $"Folded {calls} same-owner null-state helper calls after proving the Reactor pool's closed construction and uses."));
            }
        }
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
