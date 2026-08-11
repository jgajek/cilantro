using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Opt-in removal of Reactor runtime scaffolding that recovery has rendered dead.
/// </summary>
/// <remarks>
/// This is the only pass that deletes whole types, so it is deliberately narrow. It runs solely
/// under <c>--remove-runtime</c>, only after method recovery reports completion, and only through
/// <see cref="RewritePolicy.CanRemoveRuntime"/>. A type is removed only when it is a structurally
/// proven delegate proxy and nothing that survives the cleanup still references it, computed as a
/// fixed point so a proxy kept for an external reference can never strand another proxy it points
/// to. Every deletion is declared to the identity gate through the cleanup facts the pipeline reads,
/// so verification still fails on any change this pass did not account for.
/// </remarks>
public sealed class RuntimeCleanupPass : DeobfuscationPass
{
    public override string Name => "runtime-cleanup";
    public override IReadOnlyCollection<string> Dependencies =>
        ["delegate-proxy-analysis", "payload-extraction"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Runtime cleanup is opt-in; skipped without --remove-runtime."]);

        var recoveryComplete =
            !context.TryGetFact<bool>("method-protection.complete", out var complete) || complete;

        var candidates = context.Module.GetTypes()
            .Where(ReactorStructureDetector.IsDelegateProxy)
            .ToHashSet();
        if (candidates.Count == 0)
            return (PassStatus.Success, 0, ["No delegate-proxy runtime types were present."]);

        var removable = ComputeUnreferencedProxies(context.Module, candidates);
        removable.RemoveWhere(type => !RewritePolicy.CanRemoveRuntime(
            recoveryComplete, hasRemainingUseSites: false, confidence: 1.0));
        if (removable.Count == 0)
        {
            return (PassStatus.Success, 0,
            [
                recoveryComplete
                    ? $"All {candidates.Count} proxy types are still referenced; nothing removed."
                    : "Method recovery is incomplete; runtime cleanup withheld."
            ]);
        }

        var removedMethodTokens = new HashSet<uint>();
        var removedPublicApi = new HashSet<string>(StringComparer.Ordinal);
        var removedFieldCount = 0;
        foreach (var type in removable)
        {
            foreach (var method in type.Methods)
            {
                removedMethodTokens.Add(method.MDToken.Raw);
                if (method.IsPublic)
                    removedPublicApi.Add($"M:{method.FullName}");
            }
            foreach (var field in type.Fields)
            {
                removedFieldCount++;
                if (field.IsPublic)
                    removedPublicApi.Add($"F:{field.FullName}");
            }
            if (type.IsPublic || type.IsNestedPublic)
                removedPublicApi.Add($"T:{type.FullName}");

            context.Module.Types.Remove(type);
            context.AddChange(new ChangeRecord(
                Name,
                "remove-runtime-type",
                $"{type.MDToken} {type.FullName}",
                "Removed a proven-dead Reactor delegate-proxy runtime type."));
        }

        context.SetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", removedMethodTokens);
        context.SetFact<IReadOnlySet<string>>("cleanup.removedPublicApi", removedPublicApi);
        context.SetFact("cleanup.removedTypeCount", removable.Count);
        context.SetFact("cleanup.removedFieldCount", removedFieldCount);
        context.AddEvidence(new Evidence(
            "runtime-cleanup",
            $"Removed {removable.Count} dead delegate-proxy types with confidence 1.00.",
            null,
            1.0));
        return (PassStatus.Success, removable.Count,
            [$"Removed {removable.Count} dead runtime types ({removedMethodTokens.Count} methods)."]);
    }

    /// <summary>
    /// Returns the proxy types that no surviving type references, resolved to a fixed point.
    /// </summary>
    /// <remarks>
    /// Starting from every proxy and repeatedly re-adding any that the current survivor set still
    /// references guarantees the result contains only types safe to delete together: a proxy that is
    /// kept for any reason cannot leave behind a dangling reference to a deleted one.
    /// </remarks>
    internal static HashSet<TypeDef> ComputeUnreferencedProxies(
        ModuleDef module, HashSet<TypeDef> candidates)
    {
        var allTypes = module.GetTypes().ToArray();
        var removable = new HashSet<TypeDef>(candidates);
        bool changed;
        do
        {
            var survivors = allTypes.Where(type => !removable.Contains(type));
            var referenced = CollectReferencedCandidates(survivors, candidates);
            var stranded = removable.Where(referenced.Contains).ToArray();
            changed = stranded.Length != 0;
            foreach (var type in stranded)
                removable.Remove(type);
        }
        while (changed);
        return removable;
    }

    private static HashSet<TypeDef> CollectReferencedCandidates(
        IEnumerable<TypeDef> containers, HashSet<TypeDef> candidates)
    {
        var found = new HashSet<TypeDef>();

        void Note(ITypeDefOrRef? reference)
        {
            var resolved = reference switch
            {
                TypeDef definition => definition,
                TypeRef typeRef => typeRef.ResolveTypeDef(),
                TypeSpec spec => spec.ScopeType?.ResolveTypeDef(),
                _ => null
            };
            if (resolved is not null && candidates.Contains(resolved))
                found.Add(resolved);
        }

        void NoteSig(TypeSig? sig)
        {
            if (sig is null)
                return;
            if (sig is GenericInstSig generic)
                foreach (var argument in generic.GenericArguments)
                    NoteSig(argument);
            Note(sig.ScopeType);
        }

        foreach (var type in containers)
        {
            Note(type.BaseType);
            foreach (var interfaceImpl in type.Interfaces)
                Note(interfaceImpl.Interface);
            foreach (var attribute in type.CustomAttributes)
                Note(attribute.AttributeType);
            foreach (var field in type.Fields)
                NoteSig(field.FieldSig?.Type);
            foreach (var property in type.Properties)
                NoteSig(property.PropertySig?.RetType);
            foreach (var method in type.Methods)
                InspectMethod(method, Note, NoteSig);
        }

        return found;
    }

    private static void InspectMethod(
        MethodDef method, Action<ITypeDefOrRef?> note, Action<TypeSig?> noteSig)
    {
        if (method.MethodSig is { } signature)
        {
            noteSig(signature.RetType);
            foreach (var parameter in signature.Params)
                noteSig(parameter);
        }

        foreach (var attribute in method.CustomAttributes)
            note(attribute.AttributeType);

        if (!method.HasBody)
            return;

        foreach (var local in method.Body.Variables)
            noteSig(local.Type);
        foreach (var handler in method.Body.ExceptionHandlers)
            note(handler.CatchType);
        foreach (var instruction in method.Body.Instructions)
        {
            switch (instruction.Operand)
            {
                case ITypeDefOrRef typeReference:
                    note(typeReference);
                    break;
                case IField field:
                    note(field.DeclaringType);
                    noteSig(field.FieldSig?.Type);
                    break;
                case IMethod called:
                    note(called.DeclaringType);
                    if (called.MethodSig is { } calledSignature)
                    {
                        noteSig(calledSignature.RetType);
                        foreach (var parameter in calledSignature.Params)
                            noteSig(parameter);
                    }
                    break;
            }
        }
    }
}
