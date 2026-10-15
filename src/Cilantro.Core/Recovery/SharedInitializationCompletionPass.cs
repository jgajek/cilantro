using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Retires preserved numeric-recovery initialization after all other consumers disappear.</summary>
public sealed class SharedInitializationCompletionPass : DeobfuscationPass
{
    internal const string TypesFact = "cleanup.retiredSharedInitializerTypes";
    public override string Name => "shared-initialization-completion";
    public override IReadOnlyCollection<string> Dependencies => ["integer-helper-runtime-cleanup"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<IReadOnlySet<TypeDef>>(NumericInitializationCompletionPass.SharedTypesFact, out var retained) || retained is null)
            return (PassStatus.Success, 0, ["No preserved numeric-recovery initializer requires retirement."]);
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
            if (!NumericInitializationOwnership.TryProve(context, initializer, out var shared, out var reason, out var resources) ||
                shared is not null || resources.Count != 0)
            { notes.Add($"{owner.FullName}: initialization retained ({reason})."); continue; }
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
        return (PassStatus.Success, changed, [$"Retired {changed} unobserved shared-initialization trigger(s).", .. notes.Take(8)]);
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
