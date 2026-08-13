using dnlib.DotNet;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Seeds a bounded machine with the module's observable environment and runs Reactor's loader
/// initialization, which is the precondition for interpreting anything the loader set up.
/// </summary>
/// <remarks>
/// Reactor's resolvers, decryptors, and opaque predicates all read state that only exists after the
/// module initializer and the resolver key holders have run. Every pass that interprets one of them
/// therefore needs the identical starting state, and a difference between those setups would show
/// up as one pass proving a value another cannot. Sharing one seeding routine is what keeps those
/// interpretations comparable.
///
/// The environment is deliberately minimal and closed: only this module's resources, identity,
/// pointer size, file bytes, and mapped image are visible. Every other ambient input the loader
/// might consult is absent rather than invented, so an interpretation that depends on one stops
/// instead of producing a value that happens to be wrong.
/// </remarks>
public static class BootstrapMachine
{
    public static StaticMachineLimits Limits(int maximumSteps) => new(
        MaximumSteps: maximumSteps,
        MaximumRecursionDepth: 64,
        MaximumAllocatedBytes: 256 * 1024 * 1024,
        MaximumArrayLength: 256 * 1024 * 1024,
        MaximumProvenanceNodes: 1_000_000,
        MaximumProvenanceDepth: 8_192,
        MaximumRenderedProvenanceNodes: 96);

    /// <summary>
    /// Creates a seeded machine and runs the loader initializers, or explains why it could not.
    /// </summary>
    public static bool TryRunInitializers(
        ArtifactContext context,
        int maximumSteps,
        out StaticMachine? machine,
        out string diagnostic)
    {
        if (!TrySeed(context, maximumSteps, out machine, out diagnostic) || machine is null)
            return false;

        var candidate = machine;
        if (context.Module.GlobalType.FindStaticConstructor() is { HasBody: true } moduleInitializer)
            candidate.Execute(moduleInitializer);
        foreach (var holder in context.Module.GetTypes()
                     .Where(type => type != context.Module.GlobalType &&
                         ReactorStructureDetector.IsResolverKeyHolder(type)))
        {
            if (holder.FindStaticConstructor() is { HasBody: true } holderInitializer)
                candidate.Execute(holderInitializer);
        }

        return true;
    }

    /// <summary>
    /// Creates a machine holding the module's environment, with nothing run in it yet.
    /// </summary>
    /// <remarks>
    /// Reactor's own resolvers need the loader initialization above, but code that only takes a
    /// literal apart needs none of it, and paying for the initialization once per method examined
    /// costs more than the examination. Type initializers still run when something reads what they
    /// set, so a method that turns out to need the loader is not misread — it simply pulls in what
    /// it depends on.
    /// </remarks>
    public static bool TrySeed(
        ArtifactContext context,
        int maximumSteps,
        out StaticMachine? machine,
        out string diagnostic)
    {
        ArgumentNullException.ThrowIfNull(context);
        machine = null;
        diagnostic = string.Empty;
        var candidate = new StaticMachine(Limits(maximumSteps), modelTypeInitialization: true);
        foreach (var resource in context.Module.Resources.OfType<EmbeddedResource>())
            candidate.State.RegisterResource(resource.Name, resource.CreateReader().ToArray());
        candidate.State.RegisterAssemblyIdentity(
            context.Module.Assembly?.Name ?? context.Module.Name,
            context.Module.Assembly?.PublicKeyToken?.Data ?? []);
        candidate.State.RegisterPointerSize(context.OriginalImage.IsPe32Plus ? 8 : 4);
        candidate.State.RegisterModuleMetadata(context.Module);
        candidate.State.RegisterModuleFile(
            Path.GetFullPath(context.InputPath), context.OriginalBytes);
        if (!candidate.State.TryRegisterImage(
                context.OriginalImage.CreateMappedImage(), context.OriginalImage.ImageBase))
        {
            diagnostic = "the mapped image exceeded the interpreter allocation budget";
            return false;
        }

        machine = candidate;
        return true;
    }
}
