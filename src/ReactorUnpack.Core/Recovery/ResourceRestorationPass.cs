using System.Security.Cryptography;
using dnlib.DotNet;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Passes;

namespace ReactorUnpack.Core.Recovery;

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
            return (PassStatus.Partial, 0,
            [
                "Resource restoration was deferred because method-body recovery is not complete.",
                "The bundle decryptor cannot be interpreted from unrestored bodies."
            ]);
        }

        var recovered = new List<ExtractedPayload>();
        var diagnostics = new List<string>();
        foreach (var bundle in bundles)
        {
            if (!TryRecoverBundle(context, bundle, out var plaintext, out var recoverDiagnostic) ||
                plaintext is null)
            {
                return (PassStatus.Partial, 0,
                [
                    $"Encrypted resource bundle {bundle.Name} was detected but not statically recovered: " +
                    $"{recoverDiagnostic}.",
                    "The module was not modified; reattachment is left to the opt-in runtime-cleanup path."
                ]);
            }
            var info = DescribeRecoveredBundle(bundle, plaintext);
            recovered.Add(new ExtractedPayload(info, plaintext));
            diagnostics.Add($"Recovered {plaintext.Length} plaintext byte(s) from {bundle.Name}.");
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
        }

        var combined = context.TryGetFact<IReadOnlyList<ExtractedPayload>>(
                "payload.artifacts", out var existing) && existing is not null
            ? existing.Concat(recovered).ToArray()
            : recovered.ToArray();
        context.SetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", combined);
        context.SetFact("resources.restoredBundles", recovered.Count);
        diagnostics.Insert(0, $"Statically recovered {recovered.Count} encrypted resource bundle(s).");
        return (PassStatus.Success, recovered.Count, diagnostics);
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
    /// Interprets a zero-argument decryptor that reads the bundle and returns its plaintext bytes.
    /// </summary>
    /// <remarks>
    /// The decryptor is identified structurally: a static method that returns a byte array and names
    /// the bundle resource. When exactly one such method exists it is evaluated under the bounded
    /// machine, seeded exactly as method-body recovery seeds it, and its concrete byte-array result
    /// is the plaintext. Ambiguity or an inconclusive interpretation yields no recovery.
    /// </remarks>
    private static bool TryRecoverBundle(
        ArtifactContext context,
        EmbeddedResource bundle,
        out byte[]? plaintext,
        out string diagnostic)
    {
        plaintext = null;
        diagnostic = string.Empty;
        var decryptors = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody &&
                method.IsStatic &&
                method.MethodSig?.Params.Count == 0 &&
                IsByteArray(method.ReturnType) &&
                method.Body.Instructions.Any(instruction =>
                    instruction.Operand is string value && value == bundle.Name.String))
            .ToArray();
        if (decryptors.Length != 1)
        {
            diagnostic = decryptors.Length == 0
                ? "no zero-argument byte-array decryptor names the bundle"
                : $"{decryptors.Length} candidate decryptors are ambiguous";
            return false;
        }

        var first = EvaluateDecryptor(context, decryptors[0]);
        var second = EvaluateDecryptor(context, decryptors[0]);
        if (first is null || second is null)
        {
            diagnostic = "the decryptor did not evaluate to a concrete byte array";
            return false;
        }
        if (!first.SequenceEqual(second))
        {
            diagnostic = "the decryptor produced non-deterministic output";
            return false;
        }
        plaintext = first;
        return true;
    }

    private static byte[]? EvaluateDecryptor(ArtifactContext context, MethodDef decryptor)
    {
        var limits = new StaticMachineLimits(
            MaximumSteps: 4_000_000,
            MaximumRecursionDepth: 64,
            MaximumAllocatedBytes: 256 * 1024 * 1024,
            MaximumArrayLength: 256 * 1024 * 1024,
            MaximumProvenanceNodes: 1_000_000,
            MaximumProvenanceDepth: 8_192,
            MaximumRenderedProvenanceNodes: 96);
        var machine = new StaticMachine(limits, modelTypeInitialization: true);
        foreach (var resource in context.Module.Resources.OfType<EmbeddedResource>())
            machine.State.RegisterResource(resource.Name, resource.CreateReader().ToArray());
        machine.State.RegisterAssemblyIdentity(
            context.Module.Assembly?.Name ?? context.Module.Name,
            context.Module.Assembly?.PublicKeyToken?.Data ?? []);
        machine.State.RegisterPointerSize(context.OriginalImage.IsPe32Plus ? 8 : 4);
        machine.State.RegisterModuleFile(Path.GetFullPath(context.InputPath), context.OriginalBytes);
        if (!machine.State.TryRegisterImage(
                context.OriginalImage.CreateMappedImage(), context.OriginalImage.ImageBase))
        {
            return null;
        }
        if (context.Module.GlobalType.FindStaticConstructor() is { HasBody: true } initializer)
            machine.Execute(initializer);
        foreach (var holder in context.Module.GetTypes()
                     .Where(type => type != context.Module.GlobalType &&
                         ReactorStructureDetector.IsResolverKeyHolder(type)))
        {
            if (holder.FindStaticConstructor() is { HasBody: true } holderInitializer)
                machine.Execute(holderInitializer);
        }

        var result = machine.Execute(decryptor);
        if (!result.Succeeded || !machine.State.Heap.TryGetLength(result.Value, out var length) ||
            length < 0 || length > limits.MaximumArrayLength)
        {
            return null;
        }
        if (!machine.State.Heap.TryGetArrayElementType(result.Value, out var elementType) ||
            elementType != "System.Byte")
        {
            return null;
        }
        var bytes = new byte[length];
        return machine.State.Heap.TryReadBytes(result.Value, 0, bytes) ? bytes : null;
    }

    private static bool IsByteArray(TypeSig type) =>
        type.ElementType == ElementType.SZArray &&
        type.Next?.ElementType == ElementType.U1;
}
