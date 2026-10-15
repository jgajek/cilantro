using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Deletes closed Reactor pools after their last application consumer has gone.</summary>
public sealed class UnusedReactorPoolRemovalPass : DeobfuscationPass
{
    public override string Name => "unused-reactor-pools";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["reactor-guards-completion"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Protector metadata cleanup is disabled."]);
        var candidates = ReactorGuardPool.Find(context.Module, includeUnused: true)
            .Where(pool => pool.Reads.Count == 0).Select(pool => pool.Owner).ToHashSet();
        using var bodyChanges = new BodyMutationBatch();
        var shimCalls = 0;
        if (context.TryGetFact<List<ReactorGuardCompletionPass.CompletedPool>>(
                ReactorGuardCompletionPass.CompletedPoolsFact, out var completed) && completed is not null)
            foreach (var pool in completed)
                if (TryElidePrivateInitialization(context, pool, bodyChanges, out var removedCalls))
                {
                    candidates.Add(pool.Owner);
                    shimCalls += removedCalls;
                }
        var removable = RuntimeCleanupPass.ComputeUnreferenced(context.Module, candidates);
        if (removable.Count == 0)
            return (PassStatus.Success, 0, ["No closed, unused Reactor pool is unreferenced by surviving declarations."]);

        var methods = removable.SelectMany(type => type.Methods).ToArray();
        var old = CilantroPipeline.BuildRewriteAllowance(context);
        var removedTokens = old.RemovedMethodTokenSet.Concat(methods.Where(m => m.Rid != 0).Select(m => m.MDToken.Raw)).ToHashSet();
        var removedApi = old.RemovedPublicApiSet.Concat(removable.SelectMany(ArtifactIdentitySnapshot.PublicApiEntries)).ToHashSet(StringComparer.Ordinal);
        var addedRemoved = methods.Count(m => m.Rid == 0);
        var fields = removable.Sum(type => type.Fields.Count);
        var allowance = old with
        {
            RemovedMethodTokens = removedTokens,
            RemovedPublicApi = removedApi,
            RemovedTypeCount = old.RemovedTypeCount + removable.Count,
            RemovedFieldCount = old.RemovedFieldCount + fields,
            AddedMethodCount = old.AddedMethodCount - addedRemoved
        };
        var detached = removable.Select(type =>
        {
            var owner = type.DeclaringType?.NestedTypes ?? context.Module.Types;
            return (Type: type, Owner: owner, Index: owner.IndexOf(type));
        }).ToArray();
        var committed = false;
        try
        {
            foreach (var item in detached) item.Owner.Remove(item.Type);
            var check = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, allowance);
            if (!check.Passed)
                return (PassStatus.Partial, 0, ["Unused-pool removal rolled back: " + string.Join("; ", check.Diagnostics)]);
            committed = true;
        }
        finally
        {
            if (!committed)
                foreach (var group in detached.GroupBy(item => item.Owner))
                    foreach (var item in group.OrderBy(item => item.Index)) item.Owner.Insert(item.Index, item.Type);
        }
        bodyChanges.Commit();
        context.SetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", removedTokens);
        context.SetFact<IReadOnlySet<string>>("cleanup.removedPublicApi", removedApi);
        context.SetFact("cleanup.removedTypeCount", allowance.RemovedTypeCount);
        context.SetFact("cleanup.removedFieldCount", allowance.RemovedFieldCount);
        context.TryGetFact<int>("cleanup.removedAddedMethodCount", out var priorAddedRemoved);
        context.SetFact("cleanup.removedAddedMethodCount", priorAddedRemoved + addedRemoved);
        foreach (var type in removable)
            context.AddChange(new(Name, "remove-unused-reactor-pool", type.FullName,
                $"Removed {type.Fields.Count} fields and {type.Methods.Count} methods after proving closed construction, no surviving external pool consumers, " +
                "no explicit metadata exposure and no references from surviving declarations. Computed reflection over protector metadata is excluded by the cleanup contract."));
        foreach (var method in methods.Where(ReadingMarker.Marks))
            context.AddChange(new(Name, "remove-orphaned-rebuilt-method", method.FullName,
                "Removed an exclusively owned initializer of a closed, wholly unused Reactor pool. " +
                $"Removed body fingerprint: {MethodBodySnapshot.Capture(method).Fingerprint}."));
        return (PassStatus.Success, removable.Count,
            [$"Removed {removable.Count} unused Reactor pool(s), {fields} fields and {methods.Length} methods, including {methods.Count(ReadingMarker.Marks)} reconstructed initializer(s); removed {shimCalls} private initialization shim call(s)."]);
    }

    private static bool TryElidePrivateInitialization(ArtifactContext context,
        ReactorGuardCompletionPass.CompletedPool pool, BodyMutationBatch outer, out int removedCalls)
    {
        removedCalls = 0;
        if (pool.Owner.Module != context.Module || !context.Module.GetTypes().Contains(pool.Owner)) return false;
        // A finalizer can make even a private allocation observable. Refuse any
        // virtual/explicit override rather than inferring its lifetime effects.
        if (pool.Owner.Methods.Any(m => m.IsVirtual || m.HasOverrides)) return false;
        static Instruction[] Body(MethodDef? method) => method is { HasBody: true } && !method.Body.HasExceptionHandlers
            ? method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray() : [];
        var initializer = Body(pool.Initializer);
        var cctor = Body(pool.Owner.FindStaticConstructor());
        var touch = Body(pool.Touch);
        if (initializer.Length != 3 || initializer[0].OpCode.Code != Code.Newobj ||
            initializer[0].Operand is not IMethod target || target.ResolveMethodDef() is not { } ctor || ctor.DeclaringType != pool.Owner ||
            initializer[1].OpCode.Code != Code.Stsfld || (initializer[1].Operand as IField)?.ResolveFieldDef() != pool.Root ||
            initializer[2].OpCode.Code != Code.Ret || cctor.Length != 2 || cctor[0].OpCode.Code != Code.Call ||
            (cctor[0].Operand as IMethod)?.ResolveMethodDef() != pool.Initializer || cctor[1].OpCode.Code != Code.Ret) return false;
        var construction = Body(ctor);
        if (construction.Length != 3 || construction[0].OpCode.Code != Code.Ldarg_0 ||
            construction[1].OpCode.Code != Code.Call || construction[1].Operand is not IMethod baseCtor ||
            baseCtor.FullName != "System.Void System.Object::.ctor()" || construction[2].OpCode.Code != Code.Ret ||
            touch.Length != 5 || touch[0].OpCode.Code != Code.Ldsfld || (touch[0].Operand as IField)?.ResolveFieldDef() != pool.Root ||
            touch[1].OpCode.Code is not (Code.Brtrue or Code.Brtrue_S) || touch[1].Operand != touch[4] ||
            touch[2].OpCode.Code != Code.Ldnull || touch[3].OpCode.Code != Code.Throw || touch[4].OpCode.Code != Code.Ret) return false;
        // The only initializer path allocates a plain private object and publishes it.
        // No callback, shared write, throwing prefix or recursive entry is possible.
        // Preserve every other shape rather than assuming successful initialization.
        var sites = new List<(MethodDef Method, Instruction Call)>();
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
            for (var at = 0; at < method.Body.Instructions.Count; at++)
            {
                var instruction = method.Body.Instructions[at];
                if (instruction.Operand is not IMethod called || called.ResolveMethodDef() != pool.Touch) continue;
                if (instruction.OpCode.Code != Code.Call || at > 0 && method.Body.Instructions[at - 1].OpCode.OpCodeType == OpCodeType.Prefix) return false;
                sites.Add((method, instruction));
            }
        foreach (var method in sites.Select(s => s.Method)) outer.Capture(method);
        using var probe = new BodyMutationBatch(sites.Select(s => s.Method));
        foreach (var (_, call) in sites) { call.OpCode = OpCodes.Nop; call.Operand = null; }
        if (!RuntimeCleanupPass.ComputeUnreferenced(context.Module, [pool.Owner]).Contains(pool.Owner)) return false;
        probe.Commit();
        removedCalls = sites.Count;
        return true;
    }
}
