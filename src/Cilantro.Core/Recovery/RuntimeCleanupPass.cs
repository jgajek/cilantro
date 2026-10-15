using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using System.Security.Cryptography;

namespace Cilantro.Core.Recovery;

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
public class RuntimeCleanupPass : DeobfuscationPass
{
    protected virtual bool PruneUnusedPrivateHelpers => false;
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

        // Retry bounded integrity ownership after recovery simplified initialization chains,
        // while the original checker declarations are still available for interpretation.
        if (complete && context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var reactor) && reactor?.IsReactor == true)
            IntegrityResourceOwnership.Capture(context);

        // Keep reconstructed resolver dependencies as analysis roots until the
        // earlier initialization and dispatcher proofs have finished. Deleting
        // their declarations must not change those proofs' input graph midway.
        RebuiltMethods.EnableResolverCleanup(context);
        ReactorRuntimeForwarders.CaptureReaderAdapters(context);
        // Reactor also emits a token-based delegate builder in some string-only builds,
        // even when there are no proxies to rewrite. Attribute its exact shape here, late
        // enough not to alter recovery proofs. Attribution alone never deletes a live type.
        foreach (var setup in ReactorProxySetup.Find(context))
        {
            RecoveryOrphans.Declare(context, setup);
            RecoveryOrphans.Declare(context, ReactorRuntimeFallbacks.Find(context, setup));
        }

        // Cleanup is the one caller that models type initializers running only when their type is
        // used, because an island of code the protector abandoned looks alive under any other
        // reading. Being wrong about that alone deletes nothing: attribution still has to show
        // recovery is what left the code with no use.
        //
        // A method the run built a body into is a root unless recovery has positively
        // attributed it to a removed protector consumer. A virtualized
        // method is typically one nothing calls by name, so the ordinary reading has it dead, and
        // deleting the very body the run was asked to produce — along with the helpers its code
        // calls — is not cleanup.
        // A virtual method is kept only where an instance of its type can exist. Without that, a
        // protector's interpreter is held alive by its own constructors: nothing reaches them, so
        // nothing makes one of its types, and yet their virtual methods go on matching the shape of
        // calls that surviving code makes. The narrower reading refuses itself on a module that can
        // make an instance without naming its type, so asking for it here costs nothing where it
        // cannot be had.
        var guardCallChanges = ReactorGuardHelpers.CompleteCalls(context);
        var reachability = ModuleReachability.ComputeWithInstances(
            context.Module,
            typeInitializersAlwaysRun: false,
            RebuiltMethods.CleanupRoots(context));
        // This only admits positively identified VM/proxy types whose uses recovery replaced.
        // Application types are never candidates merely because their references form an island.
        // Dynamic reflection over deliberately removed protector metadata is not preserved.
        var islands = ProtectorIslands.Find(context);
        context.TryGetFact<IReadOnlySet<uint>>(ProtectorIslands.VmTypesFact, out var vmTokens);
        var vmTypes = context.Module.GetTypes().Where(type => vmTokens?.Contains(type.MDToken.Raw) == true).ToArray();
        var vmMethods = vmTypes.SelectMany(ProtectorIslands.Nest).SelectMany(type => type.Methods).ToHashSet();
        var resourceNames = context.Module.Resources.Select(resource => resource.Name.String).ToHashSet(StringComparer.Ordinal);
        var vmResourceNames = vmMethods.Where(method => method.HasBody).SelectMany(method => method.Body.Instructions)
            .Select(instruction => instruction.Operand).OfType<string>().Where(resourceNames.Contains).ToHashSet(StringComparer.Ordinal);
        foreach (var method in context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody && !vmMethods.Contains(method)))
            vmResourceNames.ExceptWith(method.Body.Instructions.Select(instruction => instruction.Operand).OfType<string>());
        if (islands.Count != 0) reachability = ProtectorIslands.Without(context, islands);
        // Numeric tokens can come from encrypted tables, rather than ldtoken operands. Until
        // those consumers are eliminated, ordinary reference analysis cannot identify their
        // targets, and deleting rows would also change the meaning of every later token.
        var tokenConsumer = context.Module.GetTypes().SelectMany(type => type.Methods)
            .Where(method => reachability.IsReachable(method) ||
                reachability.IsReflectivelyExposed(method.DeclaringType))
            .FirstOrDefault(method =>
            {
                if (!method.HasBody) return false;
                var uses = method.Body.Instructions.Where(instruction =>
                    instruction.Operand is IMethod called && NumericTokenUses.IsResolution(called)).ToArray();
                if (uses.Length == 0) return false;
                var roundTrips = NumericTokenUses.MemberRoundTrips(method);
                return uses.Any(instruction => !roundTrips.Contains(instruction));
            });
        if (tokenConsumer is not null)
            return (PassStatus.Success, guardCallChanges,
                [$"Metadata declarations retained because {tokenConsumer.FullName} still resolves numeric metadata tokens."]);

        // Complete runtime decoys, on independently recovered string/proxy owners,
        // provide the same ownership anchor as a retired resolver. Publish that
        // anchor before whole-type cleanup; deadness and surviving references still
        // decide whether the complete nest or only an individual helper can go.
        RecoveryOrphans.Declare(context, ReactorDummyArrayHelpers.Find(context));
        var orphans = RecoveryOrphans.Of(context);
        var refused = reachability.InstanceRefusal is { } why
            ? $"Every virtual method whose shape a call here matches was kept, because this " +
                $"module can get behind the question of which types can have instances: {why}."
            : null;
        var considered = context.Module.GetTypes()
            .Where(type => type != context.Module.GlobalType)
            .ToArray();
        var deadTypes = considered
            .Where(type => islands.Contains(type) || IsProvenDead(type, reachability) && IsAttributable(type, orphans))
            .ToHashSet();
        var retained = RetentionSummary(considered, deadTypes, reachability);
        var removableTypes = deadTypes.Count == 0
            ? []
            : ComputeUnreferenced(context.Module, deadTypes);

        var removedMethodTokens = new HashSet<uint>();
        var addedMethods = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.Rid == 0).ToArray();
        var removedPublicApi = new HashSet<string>(StringComparer.Ordinal);
        var removedFieldCount = 0;
        var removedTypeCount = 0;
        RemoveTypes(removableTypes);

        var guardPairs = ReactorGuardHelpers.Find(context);
        var removedMethodCount = RemoveDeadMethods(
            context, reachability, removedMethodTokens, removedPublicApi,
            guardPairs.SelectMany(p => new[] { p.Getter, p.Test }).Concat(ReactorGuardHelpers.FindConstantMethods(context)).ToHashSet(), out var unattributed);
        foreach (var pair in guardPairs)
        {
            var owner = pair.Field.DeclaringType;
            if (owner.Methods.Contains(pair.Getter) || owner.Methods.Contains(pair.Test)) continue;
            // The recognition proof found exactly two field references, both in these
            // accessors. Their physical removal leaves no instruction naming the field.
            var fieldName = pair.Field.FullName;
            owner.Fields.Remove(pair.Field);
            removedFieldCount++;
            context.AddChange(new ChangeRecord(Name, "remove-unused-reactor-guard-field", fieldName,
                "Removed the unwritten singleton-guard field after both attributed guard accessors were physically removed; application methods and initialization remain unchanged."));
        }
        // Removing an orphaned method can release types previously pinned only by its
        // signature or body. Reuse the original deadness proof, but recheck references
        // against the declarations that actually survived method cleanup.
        var remainingDead = context.Module.GetTypes().Where(deadTypes.Contains).ToHashSet();
        if (remainingDead.Count != 0 && removedMethodCount != 0)
            RemoveTypes(ComputeUnreferenced(context.Module, remainingDead));
        var survivingTypes = context.Module.GetTypes().ToHashSet();
        if (vmTypes.Length != 0)
        {
            var retainedEngines = vmTypes.Count(survivingTypes.Contains);
            context.SetFact("cleanup.retainedVmEngines", retainedEngines);
            context.AddEvidence(new Evidence("vm-machinery-removal",
                $"Identified {vmTypes.Length} replaced VM engine(s): {vmTypes.Length - retainedEngines} removed, {retainedEngines} retained. " +
                "Removal is checked against actual declarations, not reconstruction-trial agreement."));
            if (retainedEngines == 0)
            {
                context.TryGetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles", out var roles);
                var applicationResources = (roles ?? []).Where(role => role.Role is ResourceRole.ManagedPayload or ResourceRole.NativePayload or
                    ResourceRole.RestoredApplicationResource or ResourceRole.EncryptedResourceBundle).Select(role => role.Resource).ToHashSet(StringComparer.Ordinal);
                context.TryGetFact<IReadOnlySet<string>>("cleanup.removedResources", out var priorRemoved);
                var removedResources = (priorRemoved ?? new HashSet<string>()).ToHashSet(StringComparer.Ordinal);
                foreach (var resource in context.Module.Resources.Where(resource => vmResourceNames.Contains(resource.Name.String) && !applicationResources.Contains(resource.Name.String)).ToArray())
                {
                    if (resource is not EmbeddedResource embedded) continue;
                    var hash = Convert.ToHexStringLower(SHA256.HashData(embedded.CreateReader().ToArray()));
                    context.Module.Resources.Remove(resource);
                    removedResources.Add(resource.Name.String);
                    context.AddChange(new ChangeRecord(Name, "remove-vm-resource", resource.Name,
                        $"Removed VM data referenced only by removed engine methods; SHA-256 {hash}. The input retains the original bytes."));
                }
                if (removedResources.Count != 0) context.SetFact<IReadOnlySet<string>>("cleanup.removedResources", removedResources);
            }
        }
        var attribution = unattributed == 0
            ? "Every eligible dead method was either protector-attributed or an unused private helper."
            : $"Left {unattributed} dead method(s) of surviving types in place, because neither protector attribution " +
                "nor the private-helper removal policy applies.";
        if (removedTypeCount == 0 && removedMethodCount == 0)
        {
            return (PassStatus.Success, guardCallChanges,
            [
                deadTypes.Count == 0
                    ? $"No type was proven unreachable; {retained}"
                    : $"All {deadTypes.Count} unreachable type(s) are still referenced.",
                attribution,
                .. refused is null ? Array.Empty<string>() : [refused]
            ]);
        }

        context.TryGetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", out var priorMethodTokens);
        context.TryGetFact<IReadOnlySet<string>>("cleanup.removedPublicApi", out var priorPublicApi);
        context.TryGetFact<int>("cleanup.removedAddedMethodCount", out var priorAddedMethodCount);
        context.TryGetFact<int>("cleanup.removedTypeCount", out var priorTypeCount);
        context.TryGetFact<int>("cleanup.removedMethodCount", out var priorMethodCount);
        context.TryGetFact<int>("cleanup.removedFieldCount", out var priorFieldCount);
        context.SetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", removedMethodTokens.Concat(priorMethodTokens ?? new HashSet<uint>()).ToHashSet());
        var survivingMethods = context.Module.GetTypes().SelectMany(type => type.Methods).ToHashSet();
        var removedAddedMethodCount = addedMethods.Count(method => !survivingMethods.Contains(method));
        context.SetFact("cleanup.removedAddedMethodCount", priorAddedMethodCount + removedAddedMethodCount);
        context.SetFact<IReadOnlySet<string>>("cleanup.removedPublicApi", removedPublicApi.Concat(priorPublicApi ?? new HashSet<string>()).ToHashSet(StringComparer.Ordinal));
        context.SetFact("cleanup.removedTypeCount", priorTypeCount + removedTypeCount);
        context.SetFact("cleanup.removedMethodCount", priorMethodCount + removedMethodCount);
        context.SetFact("cleanup.removedFieldCount", priorFieldCount + removedFieldCount);
        context.AddEvidence(new Evidence(
            "runtime-cleanup",
            $"Removed {removedTypeCount} unreachable type(s) and {removedMethodCount} dead method(s) " +
            $"from surviving types, none of them referenced by a surviving declaration.",
            null,
            1.0));
        return (PassStatus.Success, guardCallChanges + removedTypeCount + removedMethodCount,
        [
            $"Removed {removedTypeCount} unreachable type(s) ({removedMethodTokens.Count + removedAddedMethodCount} methods " +
            $"in total, of which {removedMethodCount} were dead methods of surviving types).",
            $"Retained the rest: {retained}",
            attribution,
            .. refused is null ? Array.Empty<string>() : [refused]
        ]);

        void RemoveTypes(HashSet<TypeDef> typesToRemove)
        {
            // Only the outermost of a doomed nest is detached; the rest go with it.
            foreach (var type in typesToRemove
                         .Where(type => type.DeclaringType is null || !typesToRemove.Contains(type.DeclaringType)))
            {
                foreach (var member in Nest(type))
                {
                    removedTypeCount++;
                    foreach (var method in member.Methods)
                    {
                        if (method.Rid != 0) removedMethodTokens.Add(method.MDToken.Raw);
                        RecordRebuiltRemoval(context, method);
                    }
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
        }

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
    /// Unused private static application helpers may also be removed when they have
    /// no reflection/name exposure, attributes or metadata role. Such removal is
    /// reported separately and never establishes protector ownership. Other unused
    /// application declarations retain the attribution requirement.
    /// </remarks>
    private int RemoveDeadMethods(
        ArtifactContext context,
        ModuleReachability reachability,
        HashSet<uint> removedMethodTokens,
        HashSet<string> removedPublicApi,
        HashSet<MethodDef> guardCandidates,
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
        var stringForwarders = Cilantro.Core.Strings.RecoveredStringForwarders.Candidates(context);
        var dead = surviving
            .SelectMany(type => type.Methods)
            .Where(method =>
                // Runtime delegate constructors are required for type loading even
                // when managed IL only reaches the delegate through marshaling.
                !method.IsRuntime &&
                !method.IsVirtual &&
                !MemberVisibility.IsExternallyVisible(method) &&
                // Reflection preserves application declarations, but positively
                // identified protector guards and recovery-emptied initializers
                // may lose their metadata under the cleanup contract. Direct
                // handles, live calls and surviving references still veto removal.
                (!reachability.IsReflectivelyExposed(method.DeclaringType) || guardCandidates.Contains(method) || stringForwarders.Contains(method) ||
                    method.Rid != 0 && orphans.Contains(method.MDToken.Raw) && EmptyTypeInitializers.DoesNothing(method)) &&
                !accessors.Contains(method) &&
                (NothingCallsIt(method) || NothingHappensWhenItDoes(method)))
            .ToArray();
        var rebuiltCandidates = RebuiltMethods.CleanupCandidates(context);
        // Keep this attribution local to methods: it does not establish that every
        // unused sibling or the containing type is protector-owned.
        var integrityCandidates = ReactorIntegrityHelpers.Find(context).ToHashSet();
        var cryptoCandidates = ReactorCryptoHelpers.Find(context).ToHashSet();
        var fileCandidates = ReactorFileHelpers.Find(context).ToHashSet();
        var encodingCandidates = ReactorEncodingHelpers.Find(context).ToHashSet();
        var dummyArrays = ReactorDummyArrayHelpers.Find(context).ToHashSet();
        var cacheWriters = ReactorStringCacheWriters.Find(context).ToHashSet();
        var runtimeForwarders = ReactorRuntimeForwarders.Find(context).ToHashSet();
        var candidates = dead.Where(method => (method.Rid != 0 && orphans.Contains(method.MDToken.Raw)) ||
            rebuiltCandidates.Contains(method) || integrityCandidates.Contains(method) || guardCandidates.Contains(method) ||
            runtimeForwarders.Contains(method) || cryptoCandidates.Contains(method) || fileCandidates.Contains(method) ||
            encodingCandidates.Contains(method) || dummyArrays.Contains(method) || cacheWriters.Contains(method)).ToHashSet();
        // Unused private application helpers may be pruned under the application
        // behavior contract. This is not protector ownership and must never
        // attribute their containing types or dependencies to Reactor.
        var literalNames = surviving.SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions).Select(i => i.Operand).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var unusedPrivate = dead.Where(m => PruneUnusedPrivateHelpers && m.IsPrivate && m.IsStatic && m.HasBody && !m.IsConstructor &&
            !m.HasCustomAttributes && m.Overrides.Count == 0 && !ReadingMarker.Marks(m) &&
            !reachability.IsReflectivelyExposed(m.DeclaringType) &&
            !literalNames.Contains(m.Name.String) && !literalNames.Contains(m.FullName)).ToHashSet();
        unusedPrivate.ExceptWith(candidates);
        candidates.UnionWith(unusedPrivate);
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
            if (dummyArrays.Contains(method))
                context.AddEvidence(new Evidence("runtime-dummy-array-ownership",
                    "Removed a complete recognized array decoy from an independently recovered string/proxy runtime owner after surviving-reference checks.", method.FullName));
            if (encodingCandidates.Contains(method))
                context.AddEvidence(new Evidence("runtime-encoding-helper-ownership",
                    "Removed the complete Base64/UTF-16 utility from an independently recovered string/proxy runtime owner after surviving-reference checks.", method.FullName));
            if (fileCandidates.Contains(method))
                context.AddEvidence(new Evidence("runtime-file-helper-ownership",
                    "Removed a complete recognized file reader or assembly-location utility, including its exception regions, from an independently recovered string/proxy runtime owner after surviving-reference checks.", method.FullName));
            if (cacheWriters.Contains(method))
                context.AddEvidence(new Evidence("string-cache-writer-ownership",
                    "Removed a closed writer whose only escaping value is a newly allocated byte array stored in the exact independently decoded cache of a physically retired string resolver.", method.FullName));
            if (cryptoCandidates.Contains(method))
            {
                context.AddEvidence(new Evidence("crypto-helper-ownership",
                    "Removed a complete recognized crypto utility or its bounded forwarding adapter on an independently recovered string/proxy runtime owner; only actual same-owner dependencies inherit attribution, and later cleanup rechecks their uses.", method.FullName));
                RecoveryOrphans.DeclareLocalDependencies(context, method);
            }
            if (runtimeForwarders.Contains(method))
                context.AddEvidence(new Evidence("runtime-forwarder-ownership",
                    "Removed an erased-argument thunk to a framework method or fully recognized BinaryReader adapter from an owner with independently recovered string and proxy inputs after dead-method and surviving-reference checks.", method.FullName));
            if (integrityCandidates.Contains(method))
            {
                context.AddEvidence(new Evidence("integrity-helper-ownership",
                    "Removed the self-file signature checker from an owner with independently recovered string and proxy inputs after dead-method and surviving-reference checks.", method.FullName));
                // Keep the proof before detaching the checker. Its private helper
                // chain can become dead only after this removal; a later cleanup
                // still applies the ordinary reference and visibility gates.
                RecoveryOrphans.DeclareLocalDependencies(context, method);
            }
            if (method.Rid != 0) removedMethodTokens.Add(method.MDToken.Raw);
            RecordRebuiltRemoval(context, method);
            if (method.IsPublic)
                removedPublicApi.Add(ArtifactIdentitySnapshot.PublicApiEntry(method));
            var removedMethodLocation = $"{method.MDToken} {method.FullName}";
            method.DeclaringType.Methods.Remove(method);
            context.AddChange(new ChangeRecord(
                Name,
                unusedPrivate.Contains(method) ? "remove-unused-private-helper" : "remove-dead-method",
                removedMethodLocation,
                unusedPrivate.Contains(method)
                ? "Removed an unused private static application helper after reachability, reflection/name and surviving-reference checks; no protector ownership is inferred."
                : "Removed a method proven unreachable and unreferenced after recovery."));
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

    private void RecordRebuiltRemoval(ArtifactContext context, MethodDef method)
    {
        if (!ReadingMarker.Marks(method)) return;
        context.TryGetFact<IReadOnlyList<VirtualizationRebuildPass.LiftedRecipe>>(
            VirtualizationRebuildPass.LiftedRecipesFact, out var recipes);
        var recipe = recipes?.FirstOrDefault(item => item.Holder == method);
        if (recipe is null && !RebuiltMethods.CleanupCandidates(context).Contains(method)) return;
        var attribution = recipe is not null
            ? $"the lifted body of orphaned original caller 0x{recipe.Caller:X8}"
            : $"the reconstructed body 0x{method.MDToken.Raw:X8} from {RebuiltMethods.CleanupAttribution(context, method)}";
        context.AddChange(new ChangeRecord(Name, "remove-orphaned-rebuilt-method", method.FullName,
            $"Removed {attribution} after visibility, reachability and surviving-reference checks. " +
            $"Removed body fingerprint: {MethodBodySnapshot.Capture(method).Fingerprint}."));
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
                         .Concat(type.Methods.SelectMany(method => method.ParamDefs))
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

    internal static HashSet<TypeDef> CollectReferencedCandidates(
        ModuleDef module, IEnumerable<TypeDef> containers, HashSet<TypeDef> candidates)
    {
        var found = new HashSet<TypeDef>();
        var signatures = new HashSet<TypeSig>(ReferenceEqualityComparer.Instance);

        void Note(ITypeDefOrRef? reference)
        {
            if (reference is TypeSpec specification)
            {
                NoteSig(specification.TypeSig);
                return;
            }
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
            if (sig is null || !signatures.Add(sig))
                return;
            if (sig is GenericInstSig generic)
                foreach (var argument in generic.GenericArguments)
                    NoteSig(argument);
            if (sig is ModifierSig modifier) Note(modifier.Modifier);
            if (sig is FnPtrSig { Signature: MethodSig function })
            {
                NoteSig(function.RetType);
                foreach (var parameter in function.Params) NoteSig(parameter);
                if (function.ParamsAfterSentinel is { } trailing)
                    foreach (var parameter in trailing) NoteSig(parameter);
            }
            NoteSig(sig.Next);
            Note(sig.ScopeType);
        }

        void NoteArgument(CAArgument argument)
        {
            NoteSig(argument.Type);
            switch (argument.Value)
            {
                case ITypeDefOrRef type: Note(type); break;
                case TypeSig signature: NoteSig(signature); break;
                case CAArgument boxed: NoteArgument(boxed); break;
                case IList<CAArgument> array:
                    foreach (var item in array) NoteArgument(item);
                    break;
            }
        }

        void NoteAttribute(CustomAttribute attribute)
        {
            Note(attribute.AttributeType);
            foreach (var argument in attribute.ConstructorArguments) NoteArgument(argument);
            foreach (var argument in attribute.NamedArguments) NoteArgument(argument.Argument);
        }

        void NoteGenericParameter(GenericParam parameter)
        {
            foreach (var constraint in parameter.GenericParamConstraints)
            {
                Note(constraint.Constraint);
                foreach (var attribute in constraint.CustomAttributes) NoteAttribute(attribute);
            }
            foreach (var attribute in parameter.CustomAttributes) NoteAttribute(attribute);
        }

        Note(module.EntryPoint?.DeclaringType);

        // Assembly and module attributes are declarations no type contains, so they would otherwise
        // be invisible to a scan that walks types alone.
        foreach (var attribute in module.CustomAttributes
                     .Concat(module.Assembly?.CustomAttributes ?? []))
        {
            NoteAttribute(attribute);
        }
        foreach (var exported in module.ExportedTypes)
            Note(exported.Resolve());

        foreach (var type in containers)
        {
            Note(type.BaseType);
            foreach (var interfaceImpl in type.Interfaces)
            {
                Note(interfaceImpl.Interface);
                foreach (var attribute in interfaceImpl.CustomAttributes) NoteAttribute(attribute);
            }
            foreach (var parameter in type.GenericParameters) NoteGenericParameter(parameter);
            foreach (var attribute in type.CustomAttributes)
                NoteAttribute(attribute);
            foreach (var field in type.Fields)
                NoteSig(field.FieldSig?.Type);
            foreach (var property in type.Properties)
            {
                NoteSig(property.PropertySig?.RetType);
                if (property.PropertySig is { } signature)
                    foreach (var parameter in signature.Params) NoteSig(parameter);
            }
            foreach (var item in type.Events) Note(item.EventType);
            foreach (var method in type.Methods)
            {
                InspectMethod(method, Note, NoteSig);
                foreach (var attribute in method.CustomAttributes) NoteAttribute(attribute);
                foreach (var parameter in method.ParamDefs)
                    foreach (var attribute in parameter.CustomAttributes) NoteAttribute(attribute);
                foreach (var parameter in method.GenericParameters) NoteGenericParameter(parameter);
            }

            // An attribute is a use of its type that no signature and no instruction mentions, so a
            // type only ever written as one is reachable in a way this scan has to be told about.
            // Types and methods were; fields, properties and events were not, and neither were
            // parameters. A single attribute worn by one field was enough to have its type judged
            // unreachable and deleted, and the row wearing it left behind naming nothing — which
            // costs the reader not the attribute but every method of the type that carries the
            // field, ILSpy abandoning a whole file rather than one declaration it cannot resolve.
            foreach (var member in type.Fields.Cast<IHasCustomAttribute>()
                         .Concat(type.Properties).Concat(type.Events))
            {
                foreach (var attribute in member.CustomAttributes)
                    NoteAttribute(attribute);
            }
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
        foreach (var parameter in method.ParamDefs)
            foreach (var attribute in parameter.CustomAttributes)
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
                    if (called is MethodSpec { GenericInstMethodSig: { } instantiation })
                        foreach (var argument in instantiation.GenericArguments) noteSig(argument);
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
