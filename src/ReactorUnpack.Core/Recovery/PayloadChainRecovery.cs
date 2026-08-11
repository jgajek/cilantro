using System.Security.Cryptography;
using dnlib.DotNet;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;

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

    public sealed record Recovered(MethodDef Root, byte[] Image, string AssemblyName, string Sha256);

    /// <summary>
    /// Recovers every assembly the module unpacks for itself, or explains why none could be.
    /// </summary>
    public static IReadOnlyList<Recovered> Recover(
        ArtifactContext context,
        out IReadOnlyList<string> diagnostics)
    {
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
            var images = Harvest(context, root, out var why);
            if (images is null)
            {
                notes.Add($"{root.Name}: {why}");
                continue;
            }

            // The same interpretation twice, agreeing, is what rules out an answer that depended on
            // the order the machine happened to do things in.
            var again = Harvest(context, root, out _);
            if (again is null || !SameImages(images, again))
            {
                notes.Add($"{root.Name}: the interpretation was not reproducible");
                continue;
            }

            foreach (var image in images)
            {
                var hash = Convert.ToHexStringLower(SHA256.HashData(image));
                if (!seen.Add(hash))
                    continue;
                recovered.Add(new Recovered(root, image, AssemblyNameOf(image), hash));
            }
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
    /// from and is the first candidate. It is not the only one, because a library has no entry point
    /// and can still unpack from an initializer, so any static argument-free method that reaches a
    /// memory load is admitted too. Reaching the load is what makes a candidate worth the cost;
    /// candidates that turn out not to load anything are simply reported as having loaded nothing.
    /// </remarks>
    private static MethodDef[] UnpackingRoots(ModuleDef module)
    {
        var roots = new List<MethodDef>();
        if (module.EntryPoint is { HasBody: true } entry && ReachesAMemoryLoad(entry))
            roots.Add(entry);
        roots.AddRange(module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody &&
                method.IsStatic &&
                method.MethodSig?.Params.Count == 0 &&
                !method.HasGenericParameters &&
                method != module.EntryPoint &&
                ReachesAMemoryLoad(method))
            .OrderBy(method => method.MDToken.Raw));
        return [.. roots];
    }

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
    private static byte[][]? Harvest(ArtifactContext context, MethodDef root, out string diagnostic)
    {
        diagnostic = string.Empty;
        if (!BootstrapMachine.TryRunInitializers(context, MaximumSteps, out var machine, out var seed) ||
            machine is null)
        {
            diagnostic = seed;
            return null;
        }

        var arguments = root.MethodSig?.Params.Count == 1 &&
            machine.State.Heap.TryAllocateArray(null, 0, out var empty)
                ? new[] { empty }
                : null;
        var result = machine.Execute(root, arguments);
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
            return null;
        }

        return loaded;
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
        catch (Exception exception) when (exception is BadImageFormatException or IOException or
            NotSupportedException or ArgumentException or InvalidOperationException)
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
        catch (Exception exception) when (exception is BadImageFormatException or IOException or
            NotSupportedException or ArgumentException or InvalidOperationException)
        {
            return "payload";
        }
    }
}
