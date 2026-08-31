using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;

namespace Cilantro.Core.Recovery;

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
/// pointer size, file bytes, and mapped image are visible, together with whatever the run's host
/// profile states about the computer. Every other ambient input the loader might consult is absent
/// rather than invented, so an interpretation that depends on one stops instead of producing a value
/// that happens to be wrong.
/// </remarks>
public static class BootstrapMachine
{
    /// <summary>
    /// The section protections of a mapped image, so that a module asking what protection covers
    /// its own sections is answered from its own section table rather than from a convention.
    /// </summary>
    public static IReadOnlyList<MappedImageProtection> MappedProtections(PeImageView image) =>
        image.Sections
            .Select(section => new MappedImageProtection(
                section.VirtualAddress,
                section.MappedSize,
                section.PageProtection))
            .ToArray();

    public static StaticMachineLimits Limits(int maximumSteps, DeclaredBudgets? budgets = null) =>
        (budgets ?? DeclaredBudgets.None).Over(new StaticMachineLimits(
            MaximumSteps: maximumSteps,
            MaximumRecursionDepth: 64,
            MaximumAllocatedBytes: 256 * 1024 * 1024,
            MaximumArrayLength: 256 * 1024 * 1024,
            MaximumProvenanceNodes: 1_000_000,
            MaximumProvenanceDepth: 8_192,
            MaximumRenderedProvenanceNodes: 96));

    /// <summary>
    /// The key under which the choice between the two environments below is remembered, so every
    /// pass interprets the module in the same one.
    /// </summary>
    private const string FileRefusedFact = "bootstrap.moduleFileRefused";

    /// <summary>
    /// The key under which what the run was told, and what it could not get past, are kept.
    /// </summary>
    /// <remarks>
    /// One environment for the whole run, shared by every machine any pass builds, so that a stated
    /// fact is answered wherever it is asked and the report can say what the run consulted and what
    /// stopped it, rather than what one pass out of twenty happened to see.
    /// </remarks>
    public const string RunEnvironmentFact = "run.environment";

    /// <summary>
    /// The run's environment, made on first use so that a pass run on its own still has one.
    /// </summary>
    /// <remarks>
    /// Passes are run directly as well as through the pipeline, and one that built its own
    /// environment would quietly stop answering the facts the run was given. Making it here, once,
    /// means every machine in the run shares the profile it was handed and writes into the same
    /// ledger.
    /// </remarks>
    public static RunEnvironment Environment(ArtifactContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.TryGetFact<RunEnvironment>(RunEnvironmentFact, out var existing) &&
            existing is not null)
            return existing;
        var made = new RunEnvironment();
        context.SetFact(RunEnvironmentFact, made);
        return made;
    }

    /// <summary>
    /// Creates a seeded machine and runs the loader initializers, or explains why it could not.
    /// </summary>
    /// <param name="watching">
    /// Called with the machine before anything runs in it, for a caller that wants to watch. It is
    /// called here rather than after this returns because the initializers are part of what runs,
    /// and in a module whose initializer is the protected one they are the interesting part.
    /// </param>
    public static bool TryRunInitializers(
        ArtifactContext context,
        int maximumSteps,
        out StaticMachine? machine,
        out string diagnostic,
        Action<StaticMachine>? watching = null)
    {
        if (!TrySeed(context, maximumSteps, out machine, out diagnostic) || machine is null)
            return false;

        watching?.Invoke(machine);
        RunInitializers(context, machine);
        SeedResolvedProxies(context, machine);
        if (machine.State.ModuleFileIsAbsent || Refusal(machine) is not { } refusal)
            return true;

        // The module hashed the file it was read from and rejected it, so this file is not the one
        // the protector signed. Its own code covers that case by skipping the check when the
        // assembly has no file, which is the environment a payload unpacked by another module runs
        // in. Interpreting it there is what lets the rest of the module be read; interpreting it
        // here would only produce the refusal again, in every pass.
        RecordRefusal(context, refusal);
        if (!TrySeed(context, maximumSteps, out machine, out diagnostic) || machine is null)
            return false;

        watching?.Invoke(machine);
        RunInitializers(context, machine);
        SeedResolvedProxies(context, machine);
        return true;
    }

    /// <summary>
    /// Seeds the proxy delegate fields with delegates over the targets the proxy map named, so that
    /// code reached after the map is recovered can call through a proxy and land on the real method
    /// rather than on a field the loader has left unfilled or filled with a delegate over a dynamic
    /// method this machine cannot follow.
    /// </summary>
    /// <remarks>
    /// It does nothing until the proxy map is recovered, which is a pass that runs after method
    /// bodies are back and before the string readings that need it, so the interpretations that must
    /// not see seeded proxies — method-body recovery among them — never do, and the ones that must
    /// always do. Each delegate is marked open, because Reactor's adapter passes every argument
    /// straight through to the target, receiver included.
    /// </remarks>
    public static void SeedResolvedProxies(ArtifactContext context, StaticMachine machine)
    {
        if (!context.TryGetFact<IReadOnlyList<ProxyBinding>>("proxy.bindings", out var bindings) ||
            bindings is null ||
            bindings.Count == 0)
        {
            return;
        }

        var fields = ProxyLoaderTable.ProxyFields(context.Module);
        foreach (var binding in bindings)
        {
            if (!fields.TryGetValue(binding.FieldToken, out var field) ||
                context.Module.ResolveToken(binding.TargetToken) is not IMethod target ||
                field.FieldSig?.Type.FullName is not { } delegateType ||
                !machine.State.Heap.TryAllocateObject(delegateType, out var proxy))
            {
                continue;
            }

            machine.State.Heap.TrySetModelValue(proxy, StaticMachine.DelegateMethodKey, target);
            machine.State.Heap.TrySetModelValue(proxy, StaticMachine.DelegateTargetKey, StaticValue.Null);
            machine.State.Heap.TrySetModelValue(proxy, StaticMachine.DelegateOpenKey, true);
            machine.State.WriteStaticField(field, proxy);
        }
    }

    /// <summary>
    /// The date-based trial guards to enter and leave rather than run, seen through the proxy map
    /// once it is recovered.
    /// </summary>
    /// <remarks>
    /// The guard reads the wall clock through one of the module's delegate proxies, so it is
    /// invisible until the proxy map is in hand — the same point <see cref="SeedResolvedProxies"/>
    /// begins acting, and for the same reason. Before then a machine simply runs the guard and lets
    /// it throw, which the early passes already tolerate as a bounded stop; after then every machine
    /// this teller seeds knows to pass it the way a registered copy would, so a reading of the
    /// loader's later work is not ended by a clock the interpretation itself chose.
    /// </remarks>
    private static HashSet<uint> NeutralizedGuards(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<ProxyBinding>>("proxy.bindings", out var bindings) ||
            bindings is null ||
            bindings.Count == 0)
        {
            return [];
        }
        return TrialGuardAnalysis.Find(
            context.Module,
            [.. bindings.Select(binding => (binding.FieldToken, binding.TargetToken))]);
    }

    private static void RunInitializers(ArtifactContext context, StaticMachine machine)
    {
        if (context.Module.GlobalType.FindStaticConstructor() is { HasBody: true } moduleInitializer)
            machine.Execute(moduleInitializer);
        foreach (var holder in context.Module.GetTypes()
                     .Where(type => type != context.Module.GlobalType &&
                         ReactorStructureDetector.IsResolverKeyHolder(type)))
        {
            if (holder.FindStaticConstructor() is { HasBody: true } holderInitializer)
                machine.Execute(holderInitializer);
        }
    }

    /// <summary>
    /// The refused verification, if the module read its own file and then rejected what it read.
    /// </summary>
    /// <remarks>
    /// Both halves are required. A verification that failed over something other than the module
    /// file says nothing about where the module lives, and a module that read its file and accepted
    /// it is already being interpreted in the environment it was built for.
    /// </remarks>
    private static LoaderObservation? Refusal(StaticMachine machine)
    {
        var observations = machine.State.LoaderEvidence.Observations;
        return observations.Any(observation =>
                observation.Kind == LoaderObservationKind.ModuleFileRead)
            ? observations.FirstOrDefault(observation =>
                observation.Kind == LoaderObservationKind.SignatureVerification &&
                observation.Verdict == false)
            : null;
    }

    private static void RecordRefusal(ArtifactContext context, LoaderObservation refusal)
    {
        if (context.TryGetFact<bool>(FileRefusedFact, out _))
            return;
        context.SetFact(FileRefusedFact, true);
        context.AddEvidence(new Evidence(
            "interpretation-environment",
            "The module's integrity check rejected the file it was read from, so it was " +
            "interpreted as an assembly loaded from memory, which is the case its own check " +
            "skips. Recovery therefore describes the module as it behaves when another module " +
            "loads it, not as it behaves when run from this file.",
            refusal.Detail,
            0.9));
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
        var environment = Environment(context);
        var candidate = new StaticMachine(
            Limits(maximumSteps, environment.Declarations.Budgets),
            modelTypeInitialization: true);
        if (!TryTell(context, candidate, out diagnostic))
            return false;

        machine = candidate;
        return true;
    }

    /// <summary>
    /// Tells a machine everything known about the module it is about to interpret.
    /// </summary>
    /// <remarks>
    /// There is more than one reason to run the loader — seeding a machine for a single method and
    /// interpreting the whole bootstrap for method-body recovery — and they must be told the same
    /// things. When they were not, the difference did not read as a missing registration; it read as
    /// the loader refusing an operation, which is indistinguishable from an operation the tool has
    /// genuinely not modeled. Keeping the telling in one place is what makes the two agree.
    /// </remarks>
    public static bool TryTell(ArtifactContext context, StaticMachine machine, out string diagnostic)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(machine);
        diagnostic = string.Empty;
        machine.State.RegisterRunEnvironment(Environment(context));
        foreach (var library in context.TrustedModules)
            machine.State.RegisterTrustedModule(library);
        foreach (var resource in context.Module.Resources.OfType<EmbeddedResource>())
            machine.State.RegisterResource(resource.Name, resource.CreateReader().ToArray());
        machine.State.RegisterAssemblyIdentity(
            context.Module.Assembly?.Name ?? context.Module.Name,
            context.Module.Assembly?.PublicKeyToken?.Data ?? []);
        machine.State.RegisterPointerSize(context.OriginalImage.IsPe32Plus ? 8 : 4);
        machine.State.RegisterModuleMetadata(context.Module);
        foreach (var guard in NeutralizedGuards(context))
            machine.State.RegisterNeutralizedMethod(guard);
        if (context.TryGetFact<bool>(FileRefusedFact, out _))
            machine.State.RegisterModuleBytes(context.OriginalBytes);
        else
            machine.State.RegisterModuleFile(
                Path.GetFullPath(context.InputPath), context.OriginalBytes);
        if (machine.State.TryRegisterImage(
                context.OriginalImage.CreateMappedImage(),
                context.OriginalImage.ImageBase,
                MappedProtections(context.OriginalImage)))
        {
            return true;
        }

        diagnostic = "the mapped image exceeded the interpreter allocation budget";
        return false;
    }
}
