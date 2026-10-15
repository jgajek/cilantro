using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Retires private numeric construction while retaining shared initialization.</summary>
public sealed class NumericInitializationCompletionPass : DeobfuscationPass
{
    internal const string ChangedFact = "numeric.initializationRetired";
    internal const string SharedTypesFact = "numeric.retainedSharedInitializers";
    public override string Name => "numeric-initialization-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["delegate-string-completion"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        context.SetFact(ChangedFact, false);
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<List<NumericTableRecoveryPass.InitializationBridge>>(
                NumericTableRecoveryPass.InitializationBridgesFact, out var bridges) || bridges is null)
            return (PassStatus.Success, 0, ["No recovered numeric initialization bridge requires retirement."]);
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToHashSet();
        var notes = new List<string>();
        var changed = 0;
        foreach (var group in bridges.Where(b => methods.Contains(b.Method)).GroupBy(b => b.Holder))
        {
            var holder = group.Key;
            var owner = holder.DeclaringType;
            if (owner.FindStaticConstructor() is not { HasBody: true } initializer ||
                MemberVisibility.IsExternallyVisible(owner) || owner.HasGenericParameters ||
                owner.Methods.Any(m => m.IsVirtual || m.HasOverrides) ||
                group.Any(b => !IsBridge(b.Method, holder))) continue;
            using var transaction = new BodyMutationBatch(group.Select(b => b.Method));
            foreach (var bridge in group) bridge.Method.Body = ReturnBody();
            // A surviving getter, metadata reference, field escape or constructor call
            // prevents retirement, including references from otherwise dead declarations.
            var unreferenced = RuntimeCleanupPass.ComputeUnreferenced(context.Module, [owner]).Contains(owner);
            transaction.Rollback();
            if (!unreferenced) { notes.Add($"{owner.FullName}: a numeric-holder consumer remains."); continue; }
            if (!NumericInitializationOwnership.TryProve(context, initializer, out var shared, out var reason, out var resources))
            { notes.Add($"{owner.FullName}: {reason}"); continue; }
            if (shared is not null && MayReenter(shared, owner, group.Select(b => b.Method).ToHashSet()))
            { notes.Add($"{owner.FullName}: shared initialization can re-enter the numeric holder."); continue; }
            using var edit = new BodyMutationBatch(group.Select(b => b.Method));
            foreach (var bridge in group)
            {
                bridge.Method.Body = ReturnBody();
                if (shared is not null)
                {
                    var trigger = new MemberRefUser(context.Module, "RunClassConstructor",
                        MethodSig.CreateStatic(context.Module.CorLibTypes.Void,
                            new ValueTypeSig(context.Module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))),
                        context.Module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers"));
                    bridge.Method.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(shared));
                    bridge.Method.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(trigger));
                }
                edit.RecordChange(context, new ChangeRecord(Name, "retire-numeric-initialization", bridge.Method.FullName,
                    $"Retired closed private numeric construction; retained initialization of {shared?.FullName ?? "no shared type"}."));
            }
            if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                    CilantroPipeline.BuildRewriteAllowance(context)).Passed)
            { notes.Add($"{owner.FullName}: retirement failed structural verification."); continue; }
            edit.Commit();
            if (shared is not null)
            {
                context.TryGetFact<IReadOnlySet<TypeDef>>(SharedTypesFact, out var retained);
                context.SetFact<IReadOnlySet<TypeDef>>(SharedTypesFact, new HashSet<TypeDef>(retained ?? new HashSet<TypeDef>()) { shared });
            }
            context.TryGetFact<IReadOnlyList<NumericResourceOwnership>>(NumericResourceOwnership.Fact, out var earlier);
            context.SetFact<IReadOnlyList<NumericResourceOwnership>>(NumericResourceOwnership.Fact,
                [.. earlier ?? [], .. resources.Select(resource => new NumericResourceOwnership(owner, resource))]);
            RecoveryOrphans.DeclareSubtree(context, owner.Methods);
            changed++;
        }
        context.SetFact(ChangedFact, changed != 0);
        return (PassStatus.Success, changed, [$"Retired {changed} private numeric initialization path(s).", .. notes.Take(8)]);
    }

    private static CilBody ReturnBody()
    {
        var body = new CilBody(); body.Instructions.Add(OpCodes.Ret.ToInstruction()); return body;
    }

    private static bool MayReenter(TypeDef shared, TypeDef owner, HashSet<MethodDef> bridges)
    {
        var pending = new Stack<MethodDef>(); pending.Push(shared.FindStaticConstructor());
        var seen = new HashSet<MethodDef>();
        while (pending.TryPop(out var method))
        {
            if (bridges.Contains(method) || method.DeclaringType == owner) return true;
            if (!seen.Add(method)) continue;
            if (seen.Count > 256 || !method.HasBody) return true;
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is IField field && field.ResolveFieldDef() is { } definition)
                {
                    if (definition.DeclaringType == owner) return true;
                    if (definition.DeclaringType.FindStaticConstructor() is { } init) pending.Push(init);
                }
                if (instruction.Operand is IMethod reference && reference.ResolveMethodDef() is { } target && target.Module == owner.Module)
                {
                    pending.Push(target);
                    if (target.DeclaringType.FindStaticConstructor() is { } init) pending.Push(init);
                }
            }
        }
        return false;
    }

    private static bool IsBridge(MethodDef method, FieldDef holder)
    {
        if (!method.IsStatic || !method.HasBody || method.Body.HasExceptionHandlers || method.MethodSig.Params.Count != 0 ||
            method.ReturnType.ElementType != ElementType.Void) return false;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        return il.Length == 3 && il[0].OpCode.Code == Code.Ldsfld &&
            (il[0].Operand as IField)?.ResolveFieldDef() == holder && il[1].OpCode.Code == Code.Pop && il[2].OpCode.Code == Code.Ret;
    }
}

/// <summary>Removes declarations made unused by numeric initialization retirement.</summary>
public sealed class NumericRuntimeCleanupPass : RuntimeCleanupPass
{
    public override string Name => "numeric-runtime-cleanup";
    public override IReadOnlyCollection<string> Dependencies => ["numeric-initialization-completion"];
    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context) =>
        context.TryGetFact<bool>(NumericInitializationCompletionPass.ChangedFact, out var changed) && changed
            ? base.Execute(context) : (PassStatus.Success, 0, ["No numeric initialization was retired."]);
}
