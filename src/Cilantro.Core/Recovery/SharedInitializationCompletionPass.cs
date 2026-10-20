using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Retires preserved recovery initialization after all other consumers disappear.</summary>
public sealed class SharedInitializationCompletionPass : DeobfuscationPass
{
    internal const string TypesFact = "cleanup.retiredSharedInitializerTypes";
    public override string Name => "shared-initialization-completion";
    public override IReadOnlyCollection<string> Dependencies => ["integer-helper-runtime-cleanup"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Runtime removal is disabled."]);
        context.TryGetFact<IReadOnlySet<TypeDef>>(NumericInitializationCompletionPass.SharedTypesFact, out var numeric);
        context.TryGetFact<IReadOnlySet<TypeDef>>(StringLookupCompletionPass.SharedTypesFact, out var strings);
        context.TryGetFact<IReadOnlySet<TypeDef>>(LiteralStringDecoderPass.InitializersFact, out var literals);
        var retained = new HashSet<TypeDef>(numeric ?? new HashSet<TypeDef>());
        retained.UnionWith(strings ?? new HashSet<TypeDef>());
        retained.UnionWith(literals ?? new HashSet<TypeDef>());
        if (retained.Count == 0)
            return (PassStatus.Success, 0, ["No preserved recovery initializer requires retirement."]);
        var changed = 0;
        var notes = new List<string>();
        var present = context.Module.GetTypes().ToHashSet();
        var roots = RebuiltMethods.CleanupRoots(context).ToHashSet();
        var exposed = ModuleReachability.Compute(context.Module).ReflectivelyExposedTypes;
        var names = present.SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions).Select(i => i.Operand).OfType<string>().ToHashSet(StringComparer.Ordinal);
        foreach (var owner in retained.Where(present.Contains))
        {
            var nest = ProtectorIslands.Nest(owner).ToHashSet();
            if (nest.Any(t => MemberVisibility.IsExternallyVisible(t) || t.HasGenericParameters || t.Methods.Any(roots.Contains) ||
                    exposed.Contains(t) || names.Contains(t.Name.String) || names.Contains(t.FullName) ||
                    t.Fields.Any(f => names.Contains(f.Name.String) || names.Contains(f.FullName)) ||
                    t.Methods.Any(m => names.Contains(m.Name.String) || names.Contains(m.FullName))) ||
                owner.FindStaticConstructor() is not { HasBody: true } initializer) continue;
            var pairs = new List<(MethodDef Method, Instruction Token, Instruction Call)>();
            foreach (var method in present.Where(t => !nest.Contains(t)).SelectMany(t => t.Methods).Where(m => m.HasBody))
            {
                ControlFlowGraph? graph = null;
                var il = method.Body.Instructions;
                for (var index = 0; index + 1 < il.Count; index++)
                    if (il[index].OpCode.Code == Code.Ldtoken && ReferenceEquals(il[index].Operand, owner) &&
                        IsInitializationCall(context.Module, il[index + 1]))
                    {
                        graph ??= ControlFlowGraph.Build(method);
                        if (graph.BlockOf(il[index]) == graph.BlockOf(il[index + 1])) pairs.Add((method, il[index], il[index + 1]));
                    }
            }
            if (pairs.Count == 0) continue;
            // Test actual metadata isolation, including references from otherwise dead
            // declarations. A lone field reader, exposed handle or alternate call entry
            // retains the initializer and its entire graph.
            using (var trial = new BodyMutationBatch(pairs.Select(p => p.Method).Distinct()))
            {
                Clear();
                if (!RuntimeCleanupPass.ComputeUnreferenced(context.Module, [owner]).Contains(owner))
                { notes.Add($"{owner.FullName}: a shared-initializer consumer remains."); continue; }
            }
            // Independent cold interpretation must terminate twice with identical closed
            // effects. Unlike ClosedInitializerValues alone, this also checks prefix calls,
            // exceptional operations and the lifetimes of constructed objects.
            // A previously retired binder can be observed again by later string
            // recovery. Its literal no-op body needs no construction evidence.
            var empty = initializer.Body.ExceptionHandlers.Count == 0 &&
                initializer.Body.Instructions.Count(instruction => instruction.OpCode.Code == Code.Ret) == 1 &&
                initializer.Body.Instructions.All(instruction => instruction.OpCode.Code is Code.Nop or Code.Ret);
            if (!empty)
            {
                if (!NumericInitializationOwnership.TryProve(context, initializer, out var shared, out var reason, out var resources) ||
                    shared is not null || resources.Count != 0)
                { notes.Add($"{owner.FullName}: initialization retained ({reason})."); continue; }
            }
            using var edit = new BodyMutationBatch(pairs.Select(p => p.Method).Distinct());
            Clear();
            if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                    CilantroPipeline.BuildRewriteAllowance(context)).Passed)
            { notes.Add($"{owner.FullName}: initialization retirement failed structural verification."); continue; }
            edit.Commit();
            context.TryGetFact<IReadOnlySet<uint>>(TypesFact, out var previous);
            context.SetFact<IReadOnlySet<uint>>(TypesFact, new HashSet<uint>(previous ?? new HashSet<uint>()) { owner.MDToken.Raw });
            RecoveryOrphans.DeclareOwningTypes(context, nest.SelectMany(t => t.Methods));
            context.AddChange(new(Name, "retire-unobserved-shared-initialization", owner.FullName,
                $"Removed {pairs.Count} preserved initialization trigger(s); independently completed construction writes only unobserved owner data and all other consumers are absent."));
            changed += pairs.Count;

            void Clear()
            {
                foreach (var pair in pairs)
                {
                    pair.Token.OpCode = OpCodes.Nop; pair.Token.Operand = null;
                    pair.Call.OpCode = OpCodes.Nop; pair.Call.Operand = null;
                }
            }
        }
        changed += RetireLiteralRegion(context, literals ?? new HashSet<TypeDef>(), notes);
        return (PassStatus.Success, changed, [$"Retired {changed} unobserved shared-initialization trigger(s).", .. notes.Take(8)]);
    }

    private int RetireLiteralRegion(ArtifactContext context, IReadOnlySet<TypeDef> owners, List<string> notes)
    {
        if (owners.Count is 0 or > 16) return 0;
        var present = context.Module.GetTypes().ToHashSet();
        var roots = RebuiltMethods.CleanupRoots(context).ToHashSet();
        var region = owners.Where(present.Contains).SelectMany(ProtectorIslands.Nest).ToHashSet();
        var exposed = ModuleReachability.Compute(context.Module).ReflectivelyExposedTypes;
        var names = present.SelectMany(t => t.Methods).Where(m => m.HasBody).SelectMany(m => m.Body.Instructions)
            .Select(i => i.Operand).OfType<string>().ToHashSet(StringComparer.Ordinal);
        if (region.Count is 0 or > 64 || region.Any(t => MemberVisibility.IsExternallyVisible(t) || t.HasGenericParameters ||
            exposed.Contains(t) || t.Methods.Any(roots.Contains) || names.Contains(t.Name.String) || names.Contains(t.FullName) ||
            t.Fields.Any(f => names.Contains(f.Name.String) || names.Contains(f.FullName)) ||
            t.Methods.Any(m => names.Contains(m.Name.String) || names.Contains(m.FullName)))) return 0;
        var pairs = new List<(MethodDef Method, Instruction Token, Instruction Call)>();
        foreach (var method in present.Except(region).SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            var graph = ControlFlowGraph.Build(method); var il = method.Body.Instructions;
            for (var at = 0; at + 1 < il.Count; at++)
                if (il[at].OpCode.Code == Code.Ldtoken && il[at].Operand is TypeDef type && owners.Contains(type) &&
                    IsInitializationCall(context.Module, il[at + 1]) && graph.BlockOf(il[at]) == graph.BlockOf(il[at + 1]))
                    pairs.Add((method, il[at], il[at + 1]));
        }
        if (pairs.Count == 0) return 0;
        using var edit = new BodyMutationBatch(pairs.Select(p => p.Method).Distinct());
        foreach (var pair in pairs)
        {
            pair.Token.OpCode = OpCodes.Nop; pair.Token.Operand = null;
            pair.Call.OpCode = OpCodes.Nop; pair.Call.Operand = null;
        }
        if (RuntimeCleanupPass.ComputeUnreferenced(context.Module, region).Count != region.Count)
        { notes.Add("Literal initialization region retains an external metadata/CIL consumer."); return 0; }
        if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed)
        { notes.Add("Literal initialization region retirement failed structural verification."); return 0; }
        var resources = new HashSet<RecoveredResourceOrigin>();
        foreach (var owner in owners.Where(present.Contains))
        {
            if (owner.FindStaticConstructor() is not { HasBody: true } initializer) return 0;
            if (initializer.Body.ExceptionHandlers.Count == 0 && initializer.Body.Instructions.Count(i => i.OpCode.Code == Code.Ret) == 1 &&
                initializer.Body.Instructions.All(i => i.OpCode.Code is Code.Nop or Code.Ret)) continue;
            if (!NumericInitializationOwnership.TryProve(context, initializer, out var shared, out var why, out var reads, region) || shared is not null)
            { notes.Add("Literal initialization region retained: " + why); return 0; }
            resources.UnionWith(reads);
        }
        edit.Commit();
        context.TryGetFact<IReadOnlySet<uint>>(TypesFact, out var previous);
        context.SetFact<IReadOnlySet<uint>>(TypesFact, (previous ?? new HashSet<uint>()).Concat(region.Select(t => t.MDToken.Raw)).ToHashSet());
        RecoveryOrphans.DeclareOwningTypes(context, region.SelectMany(t => t.Methods));
        foreach (var resource in resources) DecodedResourceOwnership.Remember(context, resource, region.SelectMany(t => t.Methods));
        context.AddChange(new(Name, "retire-closed-literal-initialization-region", string.Join(", ", owners.Select(t => t.FullName)),
            $"Removed {pairs.Count} preserved initialization trigger(s); cold construction has only private region effects and {resources.Count} exact resource input(s), with no surviving external consumers."));
        return pairs.Count;
    }

    private static bool IsInitializationCall(ModuleDef module, Instruction instruction) => instruction.OpCode.Code == Code.Call &&
        instruction.Operand is IMethod call && call.MethodSig is { HasThis: false, GenParamCount: 0 } &&
        call.DeclaringType is TypeRef type && type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName &&
        call.FullName == "System.Void System.Runtime.CompilerServices.RuntimeHelpers::RunClassConstructor(System.RuntimeTypeHandle)";
}

public sealed class SharedInitializerRuntimeCleanupPass : RuntimeCleanupPass
{
    public override string Name => "shared-initializer-runtime-cleanup";
    public override IReadOnlyCollection<string> Dependencies => ["shared-initialization-completion"];
}
