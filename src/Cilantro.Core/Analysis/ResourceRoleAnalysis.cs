using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

public enum ResourceRole
{
    Unknown,
    ProxyMap,
    StringTable,
    ManagedPayload,
    MethodPatchStream,
    VirtualMachineData,
    IntegrityData,
    EncryptedResourceBundle,

    /// <summary>An application resource lifted back out of a decrypted bundle.</summary>
    RestoredApplicationResource
}

public sealed record ResourceRoleFact(
    string Resource,
    ResourceRole Role,
    double Confidence,
    IReadOnlyList<string> Consumers,
    IReadOnlyList<string> Evidence);

public static class ResourceRoleAnalyzer
{
    public static IReadOnlyList<ResourceRoleFact> Analyze(
        ModuleDefMD module,
        ReactorStructureFacts structure)
    {
        var methods = module.GetTypes().SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .ToArray();
        // Reactor keeps its resource-resolve machinery on one type: the handler it subscribes to
        // AppDomain, plus the helpers that read and decrypt the bundle. Attributing a resource to
        // that type is what separates an encrypted resource bundle from an embedded assembly,
        // because both are opaque high-entropy blobs on their own.
        //
        // A signature says a method could be the handler; the subscription says it is. Preferring the
        // subscription is what keeps the attribution independent of how a build spells the handler,
        // and it costs nothing to read here because the hook is Reactor's own code and so is never
        // one of the stubs this runs ahead of. The signature stands in only where no subscription can
        // be read at all.
        var subscribed = SubscribedResolveHandlers(module)
            .Select(handler => handler.DeclaringType)
            .ToHashSet();
        var resolverHostTypes = subscribed.Count != 0
            ? subscribed
            : module.GetTypes().Where(type => type.Methods.Any(IsResourceResolveHandler)).ToHashSet();
        var results = new List<ResourceRoleFact>();
        foreach (var resource in module.Resources.OfType<EmbeddedResource>())
        {
            var consumers = methods.Where(method =>
                method.Body.Instructions.Any(instruction =>
                    instruction.Operand is string value &&
                    value == resource.Name)).ToArray();
            var calls = consumers
                .SelectMany(method => method.Body.Instructions)
                .Select(instruction => instruction.Operand as IMethod)
                .Where(method => method is not null)
                .Cast<IMethod>()
                .ToArray();
            var evidence = new List<string>();
            var role = ResourceRole.Unknown;
            var confidence = 0.25;
            if (calls.Any(call => call.Name.String.StartsWith("ResolveMethod", StringComparison.Ordinal)))
            {
                role = ResourceRole.ProxyMap;
                confidence = 0.9;
                evidence.Add("consumer resolves method tokens");
            }
            else if (calls.Any(call =>
                         call.DeclaringType?.FullName == "System.Reflection.Assembly" &&
                         call.Name == "Load"))
            {
                role = ResourceRole.ManagedPayload;
                confidence = 0.9;
                evidence.Add("consumer reaches Assembly.Load");
            }
            else if (consumers.Any(ReactorStructureDetector.IsStringResolver))
            {
                role = ResourceRole.StringTable;
                confidence = 0.9;
                evidence.Add("consumer has string(int32) resolver signature");
            }
            else if (consumers.Any(method => resolverHostTypes.Contains(method.DeclaringType)))
            {
                role = ResourceRole.EncryptedResourceBundle;
                confidence = 0.85;
                evidence.Add("consumer is declared alongside the AppDomain resource-resolve handler");
            }
            else if (structure.MethodStubCount >= 10 &&
                     Entropy.Calculate(resource.CreateReader().ToArray()) >= 7.75)
            {
                role = ResourceRole.MethodPatchStream;
                confidence = resource.CreateReader().Length > 1024 ? 0.65 : 0.4;
                evidence.Add("high-entropy resource in method-stub generation");
            }
            else if (resource.CreateReader().Length == 256 && structure.IsReactor6)
            {
                role = ResourceRole.IntegrityData;
                confidence = 0.65;
                evidence.Add("256-byte runtime integrity blob");
            }

            results.Add(new ResourceRoleFact(
                resource.Name,
                role,
                confidence,
                consumers.Select(method => $"{method.MDToken} {method.FullName}").ToArray(),
                evidence));
        }

        return results;
    }

    /// <summary>Whether a method is shaped like the handler the resource-resolve event is given.
    /// </summary>
    /// <remarks>
    /// The event's delegate takes a <c>ResolveEventArgs</c>, but a handler does not have to say so to
    /// be bound to one. An argument of that type arrives as a reference either way, so a method
    /// declaring the parameter as <see cref="object"/> can be handed over with <c>ldftn</c> and runs,
    /// and Reactor 6 declares its handler exactly that way. Insisting on the event's own spelling
    /// therefore finds no handler on those builds, so no type hosts one, so the encrypted bundle is
    /// attributed to nothing and the reading that would decrypt it declines on a module that plainly
    /// has one. Both spellings are accepted, and what settles a candidate is the subscription rather
    /// than the signature.
    /// </remarks>
    public static bool IsResourceResolveHandler(MethodDef method) =>
        method.MethodSig?.Params.Count == 2 &&
        method.MethodSig.Params[0].ElementType == ElementType.Object &&
        method.MethodSig.Params[1].FullName is "System.ResolveEventArgs" or "System.Object" &&
        method.ReturnType.FullName == "System.Reflection.Assembly";

    /// <summary>The handlers this module hands to <c>AppDomain.ResourceResolve</c>.</summary>
    /// <remarks>
    /// A hook that is never subscribed never runs, so the subscription is present in every build that
    /// serves resources this way, which makes it the one piece of evidence that does not depend on how
    /// the handler is declared. The delegate the event is given is the function loaded just before it,
    /// so the <c>ldftn</c> nearest the subscription names the handler.
    /// </remarks>
    public static IEnumerable<MethodDef> SubscribedResolveHandlers(ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(module);
        const int reach = 4;
        foreach (var method in module.GetTypes()
                     .SelectMany(type => type.Methods)
                     .Where(method => method.HasBody))
        {
            var instructions = method.Body.Instructions;
            for (var index = 0; index < instructions.Count; index++)
            {
                if (instructions[index].Operand is not IMethod subscribed ||
                    subscribed.Name != "add_ResourceResolve")
                    continue;
                for (var back = index - 1; back >= 0 && back >= index - reach; back--)
                {
                    if (instructions[back].OpCode.Code is not (Code.Ldftn or Code.Ldvirtftn) ||
                        instructions[back].Operand is not IMethod bound ||
                        bound.ResolveMethodDef() is not { } handler ||
                        handler.Module != module)
                    {
                        continue;
                    }

                    yield return handler;
                    break;
                }
            }
        }
    }
}

public sealed class ResourceRolePass : DeobfuscationPass
{
    public override string Name => "resource-roles";
    public override IReadOnlyCollection<string> Dependencies => ["resource-analysis"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var structure) ||
            structure is null)
            return (PassStatus.Failed, 0, ["Structural facts are unavailable."]);
        var facts = ResourceRoleAnalyzer.Analyze(context.Module, structure);
        context.SetFact("resource.roles", facts);
        foreach (var fact in facts.Where(fact => fact.Role != ResourceRole.Unknown))
        {
            context.AddEvidence(new Evidence(
                "resource-role",
                $"{fact.Resource}: {fact.Role}",
                string.Join("; ", fact.Consumers),
                fact.Confidence));
        }

        return (PassStatus.Success, 0,
            [$"Classified {facts.Count(fact => fact.Role != ResourceRole.Unknown)} of {facts.Count} resources."]);
    }
}

/// <summary>
/// Reclassifies resources once protected bodies and strings have been restored.
/// </summary>
/// <remarks>
/// Role inference reads consumer IL and looks for the resource name as a literal. On a JIT-hook
/// artifact both are unavailable during analysis: every consumer body is an encrypted stub and
/// the name arrives from the string resolver. The first classification therefore attributes
/// nothing, which would leave later stages unable to distinguish an unextracted payload from a
/// resource that is fully accounted for. Repeating the inference against the recovered module
/// resolves that, and it stays non-mutating.
/// </remarks>
public sealed class ResourceRoleRefinementPass : DeobfuscationPass
{
    public override string Name => "resource-role-refinement";
    public override IReadOnlyCollection<string> Dependencies => ["constant-strings"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var structure) ||
            structure is null)
            return (PassStatus.Success, 0, ["No Reactor structure was detected to refine."]);

        context.TryGetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles", out var previous);
        var refined = ResourceRoleAnalyzer.Analyze(context.Module, structure);
        context.SetFact("resource.roles", refined);
        var classified = refined.Count(fact => fact.Role != ResourceRole.Unknown);
        var before = previous?.ToDictionary(fact => fact.Resource, StringComparer.Ordinal);
        var changed = refined
            .Where(fact => before is null ||
                !before.TryGetValue(fact.Resource, out var original) ||
                original.Role != fact.Role)
            .ToArray();
        foreach (var fact in refined.Where(fact => fact.Role != ResourceRole.Unknown))
        {
            context.AddEvidence(new Evidence(
                "resource-role-refined",
                $"{fact.Resource}: {fact.Role}",
                string.Join("; ", fact.Consumers),
                fact.Confidence));
        }

        return (PassStatus.Success, 0,
        [
            $"Classified {classified} of {refined.Count} resources against recovered consumers.",
            changed.Length == 0
                ? "Recovery did not change any resource attribution."
                : $"Recovery corrected {changed.Length} attribution(s): " + string.Join(
                    ", ",
                    changed.Select(fact => $"{fact.Resource}={fact.Role}"))
        ]);
    }
}
