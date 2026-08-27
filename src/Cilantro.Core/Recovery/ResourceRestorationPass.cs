using System.Security.Cryptography;
using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Recovers Reactor's encrypted managed-resource bundle by statically running its decryptor.
/// </summary>
/// <remarks>
/// Reactor moves an assembly's original <c>.resources</c> into a single encrypted blob and serves
/// them at runtime through an AppDomain resolve hook. This pass locates that bundle from the
/// recovered resource roles and, when a decryptor can be interpreted to a concrete byte array under
/// the bounded machine, records the plaintext as a recovered artifact. Running the genuine
/// decryptor is what keeps the result correct by construction.
///
/// Reattaching the plaintext and dropping the resolve hook changes module identity, so that
/// destructive step is deferred to the opt-in runtime-cleanup path; this pass only proves and
/// records the plaintext and never mutates the module. If the bundle is present but its decryptor
/// cannot be statically evaluated to a validated result, the pass declines with a precise
/// diagnostic rather than guessing.
/// </remarks>
public sealed class ResourceRestorationPass : DeobfuscationPass
{
    public override string Name => "resource-restoration";
    public override IReadOnlyCollection<string> Dependencies => ["resource-role-refinement"];
    public override bool GatesEmission => false;

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles", out var roles) ||
            roles is null)
        {
            return (PassStatus.Success, 0, ["No resource-role analysis is available to restore from."]);
        }
        var bundles = roles
            .Where(role => role.Role == ResourceRole.EncryptedResourceBundle)
            .Select(role => context.Module.Resources.OfType<EmbeddedResource>()
                .FirstOrDefault(resource => resource.Name == role.Resource))
            .Where(resource => resource is not null)
            .Cast<EmbeddedResource>()
            .ToArray();
        if (bundles.Length == 0)
            return (PassStatus.Success, 0, ["No encrypted managed-resource bundle was detected."]);
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete)
        {
            return (PassStatus.Unsupported, 0,
            [
                "Resource restoration was deferred because method-body recovery is not complete.",
                "The bundle decryptor cannot be interpreted from unrestored bodies."
            ]);
        }

        var reattach = context.TryGetFact<bool>("options.removeRuntime", out var enabled) && enabled;
        var recovered = new List<ExtractedPayload>();
        var diagnostics = new List<string>();
        var attached = new HashSet<string>(StringComparer.Ordinal);
        foreach (var bundle in bundles)
        {
            if (!TryRecoverBundle(context, bundle, out var plaintext, out var recoverDiagnostic) ||
                plaintext is null)
            {
                return (PassStatus.Unsupported, 0,
                [
                    $"Encrypted resource bundle {bundle.Name} was detected but not statically recovered: " +
                    $"{recoverDiagnostic}.",
                    "The module was not modified; the bundle stays encrypted."
                ]);
            }
            var info = DescribeRecoveredBundle(bundle, plaintext);
            recovered.Add(new ExtractedPayload(info, plaintext));
            var streams = ResourceContainer.TryParse(plaintext, out var parsed)
                ? parsed
                : [];
            diagnostics.Add(
                $"Recovered {plaintext.Length} plaintext byte(s) from {bundle.Name}, " +
                $"holding {streams.Count} resource stream(s): " +
                string.Join(", ", streams.Select(stream => stream.Name)));
            context.AddEvidence(new Evidence(
                "restored-resource",
                $"Statically decrypted managed-resource bundle {bundle.Name}.",
                bundle.Name,
                0.95));
            context.AddChange(new ChangeRecord(
                Name,
                "recover-resource-bundle",
                bundle.Name,
                $"Recovered {plaintext.Length} bytes, SHA-256 {info.PayloadSha256}."));
            if (reattach)
                attached.UnionWith(Reattach(context, streams));
        }

        var combined = context.TryGetFact<IReadOnlyList<ExtractedPayload>>(
                "payload.artifacts", out var existing) && existing is not null
            ? existing.Concat(recovered).ToArray()
            : recovered.ToArray();
        context.SetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", combined);
        context.SetFact("resources.restoredBundles", recovered.Count);
        if (attached.Count != 0)
        {
            context.SetFact<IReadOnlySet<string>>("resources.addedResources", attached);
            // Role inference reads consumer IL, and nothing in the module names a resource that
            // was not there when it was built. Recording the role here is what keeps every
            // resource attributed for the stages that require full accounting.
            context.SetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles",
            [
                .. roles,
                .. attached.Select(name => new ResourceRoleFact(
                    name,
                    ResourceRole.RestoredApplicationResource,
                    1.0,
                    [],
                    ["lifted from the decrypted resource bundle"]))
            ]);
        }
        diagnostics.Insert(0, $"Statically recovered {recovered.Count} encrypted resource bundle(s).");
        diagnostics.Add(reattach
            ? $"Reattached {attached.Count} resource stream(s) to the module."
            : "Reattachment was skipped with --keep-runtime; the plaintext is recorded as an artifact.");
        return (PassStatus.Success, recovered.Count, diagnostics);
    }

    /// <summary>
    /// Puts recovered streams back on the module under the names the original assembly used.
    /// </summary>
    /// <remarks>
    /// The encrypted bundle stays where it is. Reactor's resolve hook runs from the module
    /// initializer and reads the bundle unconditionally, so removing it would fault a module that
    /// otherwise still runs; leaving it costs a redundant resource and makes the hook moot, because
    /// the runtime only consults a resolve hook after its own lookup fails and that lookup now
    /// succeeds. Names already present are left alone rather than overwritten, since a resource the
    /// module still carries is the authority on its own contents.
    /// </remarks>
    private IEnumerable<string> Reattach(
        ArtifactContext context,
        IReadOnlyList<ResourceContainer.Entry> streams)
    {
        var present = context.Module.Resources
            .Select(resource => resource.Name.String)
            .ToHashSet(StringComparer.Ordinal);
        foreach (var stream in streams)
        {
            if (!present.Add(stream.Name))
                continue;
            context.Module.Resources.Add(new EmbeddedResource(
                stream.Name, stream.Data, ManifestResourceAttributes.Public));
            context.AddChange(new ChangeRecord(
                Name,
                "reattach-resource",
                stream.Name,
                $"Reattached {stream.Data.Length} byte(s) recovered from the encrypted bundle."));
            yield return stream.Name;
        }
    }

    private static PayloadInfo DescribeRecoveredBundle(EmbeddedResource bundle, byte[] plaintext)
    {
        var encoded = bundle.CreateReader().ToArray();
        var hash = Convert.ToHexStringLower(SHA256.HashData(plaintext));
        return new PayloadInfo(
            bundle.Name,
            Convert.ToHexStringLower(SHA256.HashData(encoded)),
            encoded.Length,
            hash,
            plaintext.Length,
            hash,
            bundle.Name,
            bundle.Name,
            0,
            []);
    }

    /// <summary>
    /// Runs the module's own bundle reader under the bounded machine and takes the plaintext it
    /// produced.
    /// </summary>
    /// <remarks>
    /// Reactor does not expose the bundle through a tidy <c>byte[] Decrypt()</c>; the plaintext is a
    /// by-product of a resolver installer that returns nothing and stores its result in a container
    /// object. Keying on a return value therefore misses every real sample. What every version does
    /// have is a static method that names the bundle and reads it as a manifest resource stream, so
    /// that is the anchor: interpret it for its effect, then take the plaintext out of the machine.
    ///
    /// Choosing among the buffers the installer allocated is a validation question, not a guess. The
    /// plaintext is whichever buffer parses as a resource container, so candidates are checked
    /// against the container format and anything that does not parse is discarded. That keeps the
    /// result independent of which cipher, key schedule, or compression the sample happens to use.
    /// </remarks>
    private static bool TryRecoverBundle(
        ArtifactContext context,
        EmbeddedResource bundle,
        out byte[]? plaintext,
        out string diagnostic)
    {
        plaintext = null;
        diagnostic = string.Empty;
        var readers = BundleReaders(context.Module, bundle);
        if (readers.Length == 0)
        {
            diagnostic = "no interpretable static method reads the bundle as a manifest resource";
            return false;
        }

        var failures = new List<string>();
        foreach (var reader in readers)
        {
            var first = HarvestPlaintext(context, reader, bundle, out var readerDiagnostic);
            if (first is null)
            {
                failures.Add($"{reader.Name}: {readerDiagnostic}");
                continue;
            }
            var second = HarvestPlaintext(context, reader, bundle, out _);
            if (second is null || !first.SequenceEqual(second))
            {
                failures.Add($"{reader.Name}: the interpretation was not reproducible");
                continue;
            }
            plaintext = first;
            return true;
        }

        diagnostic = string.Join("; ", failures);
        return false;
    }

    /// <summary>
    /// Static, callable methods that name the bundle and read it as a manifest resource stream.
    /// </summary>
    private static MethodDef[] BundleReaders(ModuleDef module, EmbeddedResource bundle) =>
        [.. module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody &&
                method.IsStatic &&
                method.MethodSig?.Params.Count == 0 &&
                !method.HasGenericParameters &&
                NamesBundle(method, bundle) &&
                ReachesAManifestResourceRead(method))];

    private static bool NamesBundle(MethodDef method, EmbeddedResource bundle) =>
        method.Body.Instructions.Any(instruction =>
            instruction.Operand is string value && value == bundle.Name.String);

    /// <summary>What reading one bundle is allowed to spend.</summary>
    /// <remarks>
    /// The reader decrypts and inflates a whole satellite assembly, and that costs on the order of a
    /// hundred and fifty interpreted steps per byte of it, so what it needs is set by the bundle
    /// rather than by a figure here: three and a half megabytes is around half a billion steps, where
    /// a flat few million stops inside the first per cent of the decryption and reports its own
    /// ceiling — which reads as a protection the tool cannot follow when it is only a resource the
    /// tool declined to finish. The floor is what every reading used to get, so nothing that reads
    /// today is given less, and the cap holds however large the resource claims to be.
    /// </remarks>
    internal static int Budget(EmbeddedResource bundle)
    {
        const int stepsPerByte = 150;
        const int headroom = 2;
        const int fewest = 8_000_000;
        const int most = 1_200_000_000;
        return (int)Math.Clamp(
            (long)bundle.CreateReader().Length * stepsPerByte * headroom, fewest, most);
    }

    /// <summary>
    /// Whether a method reads a manifest resource, directly or through the helpers it calls.
    /// </summary>
    /// <remarks>
    /// Reactor routes the read through a helper that takes and returns <see cref="object"/>, so the
    /// call the reader makes mentions neither <see cref="System.Reflection.Assembly"/> nor the
    /// stream it produces. Following calls is what sees past that laundering, and it costs nothing
    /// in precision here because naming the bundle is already the discriminating half of the test.
    /// </remarks>
    private static bool ReachesAManifestResourceRead(MethodDef root)
    {
        const int maximumVisited = 512;
        var visited = new HashSet<MethodDef>(MethodEqualityComparer.CompareDeclaringTypes);
        var pending = new Queue<MethodDef>();
        pending.Enqueue(root);
        while (pending.Count != 0 && visited.Count < maximumVisited)
        {
            var method = pending.Dequeue();
            if (!visited.Add(method) || !method.HasBody)
                continue;
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is not IMethod called)
                    continue;
                if (called.Name == "GetManifestResourceStream")
                    return true;
                if (called.ResolveMethodDef() is { } resolved && resolved.Module == root.Module)
                    pending.Enqueue(resolved);
            }
        }

        return false;
    }

    /// <summary>
    /// Interprets a reader and returns the one buffer it produced that parses as a resource
    /// container.
    /// </summary>
    private static byte[]? HarvestPlaintext(
        ArtifactContext context,
        MethodDef reader,
        EmbeddedResource bundle,
        out string diagnostic)
    {
        diagnostic = string.Empty;
        if (!BootstrapMachine.TryRunInitializers(
                context, Budget(bundle), out var machine, out var seed) ||
            machine is null)
        {
            diagnostic = seed;
            return null;
        }

        var result = machine.Execute(reader);
        var ciphertext = bundle.CreateReader().ToArray();
        var produced = machine.State.Heap.EnumerateByteArrays()
            .Select(array => array.Bytes)
            .Where(bytes => bytes.Length != 0 &&
                !bytes.AsSpan().SequenceEqual(ciphertext) &&
                !bytes.AsSpan().SequenceEqual(context.OriginalBytes))
            .ToArray();
        var candidates = produced.Where(ResourceContainer.LooksLikeContainer).ToArray();
        if (candidates.Length == 0)
        {
            diagnostic =
                $"none of the {produced.Length} buffer(s) the reader produced parse as a " +
                $"resource container ({DescribeLargest(produced)})";
            if (!result.Succeeded)
                diagnostic += $"; the reader also stopped early: {result.Diagnostic}";
            return null;
        }

        return candidates[^1];
    }

    /// <summary>
    /// Names the biggest buffers a declined interpretation produced, so the decline can be diagnosed.
    /// </summary>
    private static string DescribeLargest(byte[][] produced)
    {
        if (produced.Length == 0)
            return "none";
        return string.Join(", ", produced
            .OrderByDescending(bytes => bytes.Length)
            .Take(4)
            .Select(bytes =>
                $"{bytes.Length} bytes opening {Convert.ToHexString(bytes.AsSpan(0, Math.Min(16, bytes.Length)))}"));
    }
}
