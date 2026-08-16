using System.Security.Cryptography;
using dnlib.DotNet;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Payload;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Recovers assemblies a module unpacks for itself, by interpreting the code that unpacks them.
/// </summary>
/// <remarks>
/// A protected sample is often two things stacked. Reactor is the outer layer, and underneath it
/// sits a crypter the author ran first: a generated loader that carries the real assembly as an
/// encrypted resource, decrypts it through a chain of transforms at startup, and hands the result
/// to <c>Assembly.Load</c>. Undoing Reactor perfectly still leaves that loader intact, because none
/// of it is Reactor's, and the payload is what an analyst came for.
///
/// Recognising the chain is not the way in. In the samples this was built against the chain is an
/// abstract <c>byte[] Transform(byte[])</c> with one implementation per stage — a cipher, a
/// decompressor, the load — driven by a loop that feeds each stage's output to the next. That
/// shape belongs to one builder, the stage set differs per build, and every name in it is
/// randomised, so a matcher written against it would describe this crypter rather than the problem.
///
/// What every such loader must do instead is the anchor. It has to end by naming the bytes it wants
/// run, and there is one call that does that. So the module's own startup path is interpreted under
/// the bounded machine and the argument to <c>Assembly.Load</c> is taken as it goes by. Nothing has
/// to be known about the ciphers, the container, the number of stages, or who generated them: the
/// module decrypts its payload exactly as it would at run time, and says which buffer the answer is
/// by trying to load it. A different crypter with a different cipher is recovered by the same code.
///
/// The load is captured, never performed. What comes back is validated as managed metadata before
/// it is believed, and the whole interpretation is repeated and required to agree, so a payload is
/// reported only when the module produced the same bytes twice and those bytes parse as an
/// assembly.
/// </remarks>
public static class PayloadChainRecovery
{
    /// <summary>
    /// Interpreting a startup path costs more than interpreting a decryptor, because everything the
    /// program does before it unpacks is interpreted too.
    /// </summary>
    private const int MaximumSteps = 16_000_000;

    /// <summary>
    /// What a chain is allowed to spend once it has shown it needs more than the usual allowance.
    /// </summary>
    /// <remarks>
    /// A stage that decrypts megabytes inside the protector's own interpreter costs orders of
    /// magnitude more than one written as plain code, and giving every module that allowance up
    /// front would make every analysis pay for the rare one. So the ordinary allowance is tried
    /// first and raised only for a root that ran out of it, which is the one case where more
    /// spending is known to buy something.
    /// </remarks>
    private const int PatientSteps = 64_000_000;

    /// <summary>
    /// How many candidate roots are worth interpreting before the search stops paying for itself.
    /// </summary>
    /// <remarks>
    /// Each root costs two full interpretations, so a module that offers hundreds of candidates
    /// would spend minutes proving that most of them unpack nothing. Candidates are taken in
    /// metadata order, which puts a crypter's own types — emitted before the payload's — first.
    /// </remarks>
    private const int MaximumRoots = 24;

    public sealed record Recovered(MethodDef Root, byte[] Image, string AssemblyName, string Sha256);

    /// <summary>
    /// How a caller wants the interpretation done, for callers who need it done differently.
    /// </summary>
    /// <param name="Repeat">
    /// Whether to interpret each root twice and require the two runs to agree. The payload pass
    /// wants that, because it is deciding whether to believe an answer it has no other check on. A
    /// caller comparing this module's answer against another module's already has its check, and
    /// the second interpretation would only cost it twice as much to learn the same thing.
    /// </param>
    /// <param name="Machine">
    /// Called with each machine before it runs, for a caller that wants to watch. The one use is
    /// finding out whether a particular method was actually entered, which is the difference
    /// between a comparison that tested something and one that tested nothing.
    /// </param>
    public sealed record Watch(bool Repeat = true, Action<StaticMachine>? Machine = null);

    /// <summary>
    /// Recovers every assembly the module unpacks for itself, or explains why none could be.
    /// </summary>
    public static IReadOnlyList<Recovered> Recover(
        ArtifactContext context,
        out IReadOnlyList<string> diagnostics) =>
        Recover(context, new Watch(), out diagnostics);

    /// <inheritdoc cref="Recover(ArtifactContext, out IReadOnlyList{string})"/>
    public static IReadOnlyList<Recovered> Recover(
        ArtifactContext context,
        Watch watch,
        out IReadOnlyList<string> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(watch);
        var notes = new List<string>();
        var roots = UnpackingRoots(context.Module);
        if (roots.Length == 0)
        {
            diagnostics = ["No startup path reaches a load of an assembly from memory."];
            return [];
        }

        var recovered = new List<Recovered>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var root in roots)
        {
            var images = Harvest(context, root, watch, out var why);
            if (images is null)
            {
                notes.Add($"{root.Name}: {why}");
                continue;
            }

            // The same interpretation twice, agreeing, is what rules out an answer that depended on
            // the order the machine happened to do things in.
            if (watch.Repeat)
            {
                var again = Harvest(context, root, watch, out _);
                if (again is null || !SameImages(images, again))
                {
                    notes.Add($"{root.Name}: the interpretation was not reproducible");
                    continue;
                }
            }

            foreach (var image in images)
            {
                var hash = Convert.ToHexStringLower(SHA256.HashData(image));
                if (!seen.Add(hash))
                    continue;
                recovered.Add(new Recovered(root, image, AssemblyNameOf(image), hash));
            }

            // The remaining candidates were only ever guesses about where the chain starts. Once one
            // of them has run the chain and produced assemblies, the others have nothing left to
            // answer, and interpreting them costs as much as the one that worked.
            if (recovered.Count != 0)
                break;
        }

        if (recovered.Count == 0 && notes.Count == 0)
            notes.Add("The startup path loaded nothing that parses as an assembly.");
        diagnostics = notes;
        return recovered;
    }

    /// <summary>
    /// Methods worth interpreting in the hope that they unpack something.
    /// </summary>
    /// <remarks>
    /// A crypter runs before the program does, so the entry point is where its work is reachable
    /// from and is the first candidate. It is not the only one. A library has no entry point and can
    /// still unpack from an initializer, and a startup path can be unreachable for reasons that have
    /// nothing to do with the crypter — anti-tamper the machine will not follow, or, as in the
    /// samples this was extended for, a virtualized module initializer that the crypter's own stages
    /// sit entirely outside of. Entering at the chain instead of ahead of it steps over all of that.
    ///
    /// So any argument-free method reaching a memory load is admitted, whether or not it needs a
    /// receiver, provided one can be supplied: a driver written as a class with a default
    /// constructor is as ordinary as one written as a static method, and excluding it would only
    /// encode a preference about how the crypter's author spelled things. Reaching the load is what
    /// makes a candidate worth the cost, and candidates that load nothing simply say so.
    /// </remarks>
    private static MethodDef[] UnpackingRoots(ModuleDef module)
    {
        var roots = new List<MethodDef>();
        if (module.EntryPoint is { HasBody: true } entry && ReachesAMemoryLoad(entry))
            roots.Add(entry);
        roots.AddRange(module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody &&
                method.MethodSig?.Params.Count == 0 &&
                !method.HasGenericParameters &&
                !method.IsConstructor &&
                method != module.EntryPoint &&
                (method.IsStatic || CanSupplyReceiver(method.DeclaringType)) &&
                ReachesAMemoryLoad(method))
            .OrderBy(method => method.MDToken.Raw)
            .Take(MaximumRoots));
        return [.. roots];
    }

    /// <summary>
    /// Whether the machine can stand up an instance of a type to call an instance root on.
    /// </summary>
    private static bool CanSupplyReceiver(TypeDef? type) =>
        type is { IsAbstract: false, IsInterface: false } &&
        !type.HasGenericParameters &&
        DefaultConstructor(type) is not null;

    private static MethodDef? DefaultConstructor(TypeDef type) =>
        type.FindInstanceConstructors()
            .FirstOrDefault(constructor =>
                constructor.HasBody && constructor.MethodSig?.Params.Count == 0);

    /// <summary>
    /// Whether a method can reach <c>Assembly.Load</c> on a byte array through the calls it makes.
    /// </summary>
    private static bool ReachesAMemoryLoad(MethodDef root)
    {
        const int maximumVisited = 2048;
        var visited = new HashSet<MethodDef>(MethodEqualityComparer.CompareDeclaringTypes);
        var pending = new Queue<MethodDef>();
        pending.Enqueue(root);
        while (pending.Count != 0 && visited.Count < maximumVisited)
        {
            var method = pending.Dequeue();
            if (!visited.Add(method))
                continue;

            // An abstract stage is called through its base declaration, so a body-less method is
            // where the interesting edge starts rather than where the search stops. The overrides
            // are what actually run.
            foreach (var over in Overrides(root.Module, method))
                pending.Enqueue(over);
            if (!method.HasBody)
                continue;
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is not IMethod called)
                    continue;
                if (IsMemoryLoad(called))
                    return true;
                if (called.ResolveMethodDef() is { } resolved && resolved.Module == root.Module)
                    pending.Enqueue(resolved);
            }
        }

        return false;
    }

    private static IEnumerable<MethodDef> Overrides(ModuleDef module, MethodDef method)
    {
        if (method.HasBody || !method.IsVirtual)
            return [];
        return module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(candidate => candidate.HasBody &&
                candidate.IsVirtual &&
                candidate.Name == method.Name &&
                candidate.MethodSig?.Params.Count == method.MethodSig?.Params.Count);
    }

    private static bool IsMemoryLoad(IMethod called) =>
        called.Name == "Load" &&
        called.DeclaringType?.FullName == "System.Reflection.Assembly" &&
        called.MethodSig?.Params.Count == 1 &&
        called.MethodSig.Params[0].FullName == "System.Byte[]";

    /// <summary>
    /// Interprets a root and returns the images it tried to load that parse as assemblies.
    /// </summary>
    private static byte[][]? Harvest(
        ArtifactContext context,
        MethodDef root,
        Watch watch,
        out string diagnostic)
    {
        var harvested = Harvest(context, root, watch, MaximumSteps, out diagnostic, out var exhausted);
        return harvested is null && exhausted
            ? Harvest(context, root, watch, PatientSteps, out diagnostic, out _)
            : harvested;
    }

    private static byte[][]? Harvest(
        ArtifactContext context,
        MethodDef root,
        Watch watch,
        int budget,
        out string diagnostic,
        out bool exhausted)
    {
        exhausted = false;
        diagnostic = string.Empty;
        if (!BootstrapMachine.TryRunInitializers(
                context, budget, out var machine, out var seed, watch.Machine) ||
            machine is null)
        {
            diagnostic = seed;
            return null;
        }

        if (!TryBuildArguments(machine, root, out var arguments))
        {
            diagnostic = "a receiver for the root could not be constructed";
            return null;
        }

        var result = machine.Execute(root, arguments);
        exhausted = machine.State.RanOutOfBudget;
        var loaded = machine.State.CapturedAssemblyLoads
            .Where(image => !image.AsSpan().SequenceEqual(context.OriginalBytes))
            .Where(LooksLikeManagedAssembly)
            .ToArray();
        if (loaded.Length == 0)
        {
            diagnostic = machine.State.CapturedAssemblyLoads.Count == 0
                ? result.Succeeded
                    ? "the startup path ran to completion without loading anything from memory"
                    : $"the startup path stopped before any load: {result.Diagnostic}"
                : $"{machine.State.CapturedAssemblyLoads.Count} loaded buffer(s) are not managed assemblies";
            // Where it first went wrong is more use than where it finally stopped, because a loader
            // that catches its own exceptions reports them far from their cause.
            var throws = machine.State.ThrowSites;
            if (throws.Count != 0)
                diagnostic += $"; first threw at {string.Join(", then ", throws.Take(3))}";
            return null;
        }

        return loaded;
    }

    /// <summary>
    /// Builds the argument list a root is entered with, including a receiver where one is needed.
    /// </summary>
    /// <remarks>
    /// An instance root is constructed rather than merely allocated, because a driver keeps what it
    /// unpacks from — the resource name, the stage list — in fields its constructor fills, and an
    /// allocated-but-unconstructed receiver would enter the chain with all of that missing.
    /// </remarks>
    private static bool TryBuildArguments(
        StaticMachine machine,
        MethodDef root,
        out IReadOnlyList<StaticValue>? arguments)
    {
        arguments = null;
        var supplied = new List<StaticValue>();
        if (root.MethodSig?.HasThis == true)
        {
            if (DefaultConstructor(root.DeclaringType) is not { } constructor ||
                !machine.State.Heap.TryAllocateObject(root.DeclaringType.FullName, out var receiver) ||
                !machine.Execute(constructor, [receiver]).Succeeded)
            {
                return false;
            }

            supplied.Add(receiver);
        }

        // An entry point is the one root that may take arguments, and it is given the empty command
        // line it would see when run without any.
        if (root.MethodSig?.Params.Count == 1)
        {
            if (!machine.State.Heap.TryAllocateArray(null, 0, out var empty))
                return false;
            supplied.Add(empty);
        }

        arguments = supplied.Count == 0 ? null : supplied;
        return true;
    }

    private static bool SameImages(byte[][] first, byte[][] second) =>
        first.Length == second.Length &&
        first.Zip(second).All(pair => pair.First.AsSpan().SequenceEqual(pair.Second));

    /// <summary>
    /// Whether a buffer is a managed assembly, decided by parsing it rather than by its header.
    /// </summary>
    private static bool LooksLikeManagedAssembly(byte[] image)
    {
        if (image.Length < 128 || image[0] != 'M' || image[1] != 'Z')
            return false;
        try
        {
            using var module = ModuleDefMD.Load(image);
            return module.Types.Count != 0;
        }
        catch (Exception exception) when (ManagedImage.Rejects(exception))
        {
            return false;
        }
    }

    private static string AssemblyNameOf(byte[] image)
    {
        try
        {
            using var module = ModuleDefMD.Load(image);
            return module.Assembly?.Name ?? module.Name ?? "payload";
        }
        catch (Exception exception) when (ManagedImage.Rejects(exception))
        {
            return "payload";
        }
    }
}
