using dnlib.DotNet;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Removes the Reactor scaffolding that recovery has left unreachable.
/// </summary>
/// <remarks>
/// Once the protector's guards are folded away, most of what it injected is no longer reachable from
/// anything the program can do. Leaving it behind is what makes recovered output several times the
/// size of the original, so removing it is the difference between an assembly that merely runs and
/// one that reads like the original.
///
/// This is the only pass that deletes declarations, so a candidate has to clear four independent
/// checks. Nothing in it may be reachable, which rules out anything the runtime can transfer control
/// to. It must not be externally visible, so no caller outside the assembly can name it. No reachable
/// code may take its handle, which is the one reflective use that is statically visible. Finally the
/// surviving declarations must not reference it anywhere, resolved to a fixed point so anything kept
/// for any reason cannot be left pointing at something deleted; that last check is what keeps the
/// metadata consistent regardless of how the first three were decided.
///
/// Types and methods are removed in that order and for the same reasons, because scaffolding hides in
/// both. A protector's helper types disappear whole, but the call proxies it scatters across the
/// program's own types do not, and leaving them behind would keep most of the injected code. Nested
/// types are judged on their own rather than with their declaring type, since a live type routinely
/// carries a dead nest.
///
/// Virtual methods are never removed. Reachability sees a virtual call only where the module makes
/// it, so an internal type reached through a public interface would look dead while an outside caller
/// can still dispatch to it.
///
/// Deletions are declared to the identity gate through the cleanup facts the pipeline reads, so
/// verification still fails on any change this pass did not account for.
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
            return (PassStatus.Success, 0, ["Runtime cleanup was disabled with --keep-runtime."]);

        var recoveryComplete =
            !context.TryGetFact<bool>("method-protection.complete", out var complete) || complete;
        if (!RewritePolicy.CanRemoveRuntime(recoveryComplete, hasRemainingUseSites: false, confidence: 1.0))
            return (PassStatus.Success, 0, ["Method recovery is incomplete; runtime cleanup withheld."]);

        // Cleanup is the one caller that models type initializers running only when their type is
        // used, because an island of code the protector abandoned looks alive under any other
        // reading. Being wrong about that alone deletes nothing: attribution still has to show
        // recovery is what left the code with no use.
        //
        // A method the run built a body into is a root whatever the module says. A virtualized
        // method is typically one nothing calls by name, so the ordinary reading has it dead, and
        // deleting the very body the run was asked to produce — along with the helpers its code
        // calls — is not cleanup.
        var reachability = ModuleReachability.Compute(
            context.Module,
            typeInitializersAlwaysRun: false,
            Rebuilt(context));
        var orphans = RecoveryOrphans.Of(context);
        var considered = context.Module.GetTypes()
            .Where(type => type != context.Module.GlobalType)
            .ToArray();
        var deadTypes = considered
            .Where(type => IsProvenDead(type, reachability) && IsAttributable(type, orphans))
            .ToHashSet();
        var retained = RetentionSummary(considered, deadTypes, reachability);
        var removableTypes = deadTypes.Count == 0
            ? []
            : ComputeUnreferenced(context.Module, deadTypes);

        var removedMethodTokens = new HashSet<uint>();
        var removedPublicApi = new HashSet<string>(StringComparer.Ordinal);
        var removedFieldCount = 0;
        var removedTypeCount = 0;
        // Only the outermost of a doomed nest is detached; the rest go with it.
        foreach (var type in removableTypes
                     .Where(type => type.DeclaringType is null || !removableTypes.Contains(type.DeclaringType)))
        {
            foreach (var member in Nest(type))
            {
                removedTypeCount++;
                foreach (var method in member.Methods)
                    removedMethodTokens.Add(method.MDToken.Raw);
                removedFieldCount += member.Fields.Count;
                removedPublicApi.UnionWith(ArtifactIdentitySnapshot.PublicApiEntries(member));
            }

            if (type.DeclaringType is { } declaring)
                declaring.NestedTypes.Remove(type);
            else
                context.Module.Types.Remove(type);
            context.AddChange(new ChangeRecord(
                Name,
                "remove-runtime-type",
                $"{type.MDToken} {type.FullName}",
                "Removed a type proven unreachable and unreferenced after recovery."));
        }

        var removedMethodCount = RemoveDeadMethods(
            context, reachability, removedMethodTokens, removedPublicApi, out var unattributed);
        var attribution = unattributed == 0
            ? "Every dead method of a surviving type was attributable to the protector."
            : $"Left {unattributed} dead method(s) of surviving types in place, because nothing " +
                "recovery did accounts for them being unused.";
        if (removedTypeCount == 0 && removedMethodCount == 0)
        {
            return (PassStatus.Success, 0,
            [
                deadTypes.Count == 0
                    ? $"No type was proven unreachable; {retained}"
                    : $"All {deadTypes.Count} unreachable type(s) are still referenced.",
                attribution
            ]);
        }

        context.SetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", removedMethodTokens);
        context.SetFact<IReadOnlySet<string>>("cleanup.removedPublicApi", removedPublicApi);
        context.SetFact("cleanup.removedTypeCount", removedTypeCount);
        context.SetFact("cleanup.removedMethodCount", removedMethodCount);
        context.SetFact("cleanup.removedFieldCount", removedFieldCount);
        context.AddEvidence(new Evidence(
            "runtime-cleanup",
            $"Removed {removedTypeCount} unreachable type(s) and {removedMethodCount} dead method(s) " +
            $"from surviving types, none of them referenced by a surviving declaration.",
            null,
            1.0));
        return (PassStatus.Success, removedTypeCount + removedMethodCount,
        [
            $"Removed {removedTypeCount} unreachable type(s) ({removedMethodTokens.Count} methods " +
            $"in total, of which {removedMethodCount} were dead methods of surviving types).",
            $"Retained the rest: {retained}",
            attribution
        ]);
    }

    /// <summary>
    /// The methods a rebuild wrote bodies into, resolved in the module cleanup is about to prune.
    /// </summary>
    private static IReadOnlyList<MethodDef> Rebuilt(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlySet<uint>>(
                VirtualizationRebuildPass.RebuiltFact, out var tokens) ||
            tokens is null)
        {
            return [];
        }
        return
        [
            .. tokens
                .Select(token => context.Module.ResolveToken(token) as MethodDef)
                .Where(method => method is not null)
                .Select(method => method!)
        ];
    }

    /// <summary>
    /// Deletes the unreachable methods of the types that survived, and reports how many went.
    /// </summary>
    /// <remarks>
    /// A method is only detached once nothing that remains can name it. Reachability alone is not
    /// that guarantee: an unreachable method that is kept, because it is virtual, still has a body
    /// whose references have to stay resolvable, so the candidate set is narrowed to a fixed point
    /// against whatever survives.
    ///
    /// Accessors are excluded outright. A property or event names its methods through the metadata
    /// rather than through any instruction, so removing one would strand the declaration that
    /// points at it.
    ///
    /// Being unreachable is necessary but not sufficient: a method also has to be one recovery
    /// orphaned. Programs contain unused internal helpers of their own, and deleting those would be
    /// an edit to the program rather than the removal of an obfuscation, so the count that fails
    /// only the attribution test is reported instead.
    /// </remarks>
    private int RemoveDeadMethods(
        ArtifactContext context,
        ModuleReachability reachability,
        HashSet<uint> removedMethodTokens,
        HashSet<string> removedPublicApi,
        out int unattributed)
    {
        unattributed = 0;
        var surviving = context.Module.GetTypes().ToArray();
        var accessors = surviving
            .SelectMany(type => type.Properties
                .SelectMany(property => property.GetMethods.Concat(property.SetMethods).Concat(property.OtherMethods))
                .Concat(type.Events.SelectMany(item =>
                    new[] { item.AddMethod, item.RemoveMethod, item.InvokeMethod }
                        .Where(method => method is not null)
                        .Select(method => method!)
                        .Concat(item.OtherMethods))))
            .ToHashSet();

        var orphans = RecoveryOrphans.Of(context);
        var dead = surviving
            .SelectMany(type => type.Methods)
            .Where(method =>
                !method.IsVirtual &&
                !MemberVisibility.IsExternallyVisible(method) &&
                !accessors.Contains(method) &&
                (NothingCallsIt(method) || NothingHappensWhenItDoes(method)))
            .ToArray();
        var candidates = dead.Where(method => orphans.Contains(method.MDToken.Raw)).ToHashSet();
        unattributed = dead.Length - candidates.Count;
        if (candidates.Count == 0)
            return 0;

        bool changed;
        do
        {
            var referenced = CollectReferencedMethods(context.Module, surviving, candidates);
            changed = referenced.Count != 0;
            candidates.ExceptWith(referenced);
        }
        while (changed && candidates.Count != 0);

        foreach (var method in candidates)
        {
            removedMethodTokens.Add(method.MDToken.Raw);
            if (method.IsPublic)
                removedPublicApi.Add(ArtifactIdentitySnapshot.PublicApiEntry(method));
            method.DeclaringType.Methods.Remove(method);
            context.AddChange(new ChangeRecord(
                Name,
                "remove-dead-method",
                $"{method.MDToken} {method.FullName}",
                "Removed a method proven unreachable and unreferenced after recovery."));
        }
        return candidates.Count;

        // The ordinary case: nothing in the module reaches it. A type initializer is excluded
        // because reaching it is not how it runs — the runtime starts it when the type is first
        // used, so no call has to exist for it to matter.
        bool NothingCallsIt(MethodDef method) =>
            !method.IsStaticConstructor && !reachability.IsReachable(method);

        // Which leaves the other way to be beside the point: an initializer whose body cannot do
        // anything is one the runtime is welcome to run, and removing it removes nothing that was
        // going to happen. Reachability is not consulted because the answer would not change the
        // conclusion. Attribution is, as ever, still required, so this reaches only the
        // initializers recovery itself hollowed out.
        static bool NothingHappensWhenItDoes(MethodDef method) =>
            EmptyTypeInitializers.DoesNothing(method);
    }

    /// <summary>
    /// Returns the candidates that something outside the candidate set still names.
    /// </summary>
    private static HashSet<MethodDef> CollectReferencedMethods(
        ModuleDef module, IReadOnlyList<TypeDef> types, HashSet<MethodDef> candidates)
    {
        var found = new HashSet<MethodDef>();
        foreach (var method in types.SelectMany(type => type.Methods))
        {
            if (candidates.Contains(method))
                continue;
            foreach (var overridden in method.Overrides)
            {
                Note(overridden.MethodDeclaration);
                Note(overridden.MethodBody);
            }
            if (!method.HasBody)
                continue;
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is IMethod called)
                    Note(called);
            }
        }

        // A custom attribute names its constructor without any instruction referring to it.
        foreach (var attribute in module.CustomAttributes
                     .Concat(module.Assembly?.CustomAttributes ?? []))
        {
            Note(attribute.Constructor);
        }
        foreach (var type in types)
        {
            foreach (var attribute in type.CustomAttributes)
                Note(attribute.Constructor);
            foreach (var member in type.Methods.Cast<IHasCustomAttribute>()
                         .Concat(type.Fields).Concat(type.Properties).Concat(type.Events))
            {
                foreach (var attribute in member.CustomAttributes)
                    Note(attribute.Constructor);
            }
        }
        return found;

        void Note(IMethod? reference)
        {
            if (reference?.ResolveMethodDef() is { } resolved && candidates.Contains(resolved))
                found.Add(resolved);
        }
    }

    /// <summary>
    /// Accounts for the types cleanup kept, grouped by which check retained them.
    /// </summary>
    /// <remarks>
    /// Cleanup is the pass most likely to look like it did nothing, and the difference between
    /// "the protector left nothing dead" and "one conservative check is holding everything alive"
    /// matters to anyone judging the output. Reporting the breakdown makes that visible without
    /// having to re-derive it.
    /// </remarks>
    private static string RetentionSummary(
        IReadOnlyList<TypeDef> considered,
        HashSet<TypeDef> candidates,
        ModuleReachability reachability)
    {
        var reachable = 0;
        var visible = 0;
        var exposed = 0;
        foreach (var type in considered.Where(type => !candidates.Contains(type)))
        {
            var nest = Nest(type).ToArray();
            if (nest.Any(member => member.Methods.Any(reachability.IsReachable)))
                reachable++;
            else if (nest.Any(MemberVisibility.IsExternallyVisible))
                visible++;
            else if (nest.Any(reachability.IsReflectivelyExposed))
                exposed++;
        }
        return $"{reachable} reachable, {visible} externally visible, {exposed} handed to reflection.";
    }

    /// <summary>
    /// Whether a top-level type and everything nested inside it is provably beyond the program's
    /// reach.
    /// </summary>
    /// <remarks>
    /// The whole nest is judged together because a nested type is deleted with its declaring type,
    /// so one reachable member anywhere in the nest keeps all of it.
    /// </remarks>
    /// <summary>
    /// Whether recovery showed part of the nest to be the protector's own.
    /// </summary>
    /// <remarks>
    /// One orphan is enough, because this is only asked of a nest already proven dead in full. The
    /// protector writes its helper types whole rather than adding methods to the program's, so a
    /// type containing something recovery orphaned is its type, and the rest of a dead nest is the
    /// support that came with it.
    ///
    /// A nest with no orphan at all is kept however dead it is. That is the case of a program's own
    /// unused class, where deleting it would be an edit to the program rather than the removal of
    /// an obfuscation.
    /// </remarks>
    private static bool IsAttributable(TypeDef type, IReadOnlySet<uint> orphans) =>
        Nest(type).SelectMany(member => member.Methods)
            .Any(method => orphans.Contains(method.MDToken.Raw));

    private static bool IsProvenDead(TypeDef type, ModuleReachability reachability) =>
        Nest(type).All(member =>
            !MemberVisibility.IsExternallyVisible(member) &&
            !reachability.IsReflectivelyExposed(member) &&
            member.Methods.All(method => !reachability.IsReachable(method)));

    private static IEnumerable<TypeDef> Nest(TypeDef type)
    {
        yield return type;
        foreach (var nested in type.NestedTypes)
        {
            foreach (var member in Nest(nested))
                yield return member;
        }
    }

    /// <summary>
    /// Returns the candidates that no surviving declaration references, resolved to a fixed point.
    /// </summary>
    /// <remarks>
    /// Starting from every candidate and repeatedly re-adding any that the current survivor set
    /// still references guarantees the result is safe to delete as a group: a type kept for any
    /// reason cannot leave behind a dangling reference to a deleted one.
    /// </remarks>
    internal static HashSet<TypeDef> ComputeUnreferenced(ModuleDef module, HashSet<TypeDef> candidates)
    {
        var doomedNests = candidates.ToDictionary(type => type, type => Nest(type).ToHashSet());
        var allTypes = module.GetTypes().ToArray();
        var removable = new HashSet<TypeDef>(candidates);
        bool changed;
        do
        {
            var doomed = removable.SelectMany(type => doomedNests[type]).ToHashSet();
            var survivors = allTypes.Where(type => !doomed.Contains(type));
            var referenced = CollectReferencedCandidates(module, survivors, doomed);
            var stranded = removable
                .Where(type => doomedNests[type].Overlaps(referenced))
                .ToArray();
            changed = stranded.Length != 0;
            foreach (var type in stranded)
                removable.Remove(type);
        }
        while (changed);
        return removable;
    }

    private static HashSet<TypeDef> CollectReferencedCandidates(
        ModuleDef module, IEnumerable<TypeDef> containers, HashSet<TypeDef> candidates)
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

        // Assembly and module attributes are declarations no type contains, so they would otherwise
        // be invisible to a scan that walks types alone.
        foreach (var attribute in module.CustomAttributes
                     .Concat(module.Assembly?.CustomAttributes ?? []))
        {
            Note(attribute.AttributeType);
        }
        foreach (var exported in module.ExportedTypes)
            Note(exported.Resolve());

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
        foreach (var overridden in method.Overrides)
            note(overridden.MethodDeclaration?.DeclaringType);

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
