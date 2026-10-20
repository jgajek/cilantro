using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Agreed method-image inputs, including tables restored from resource-only satellites later.</summary>
internal static class BabelMethodImageResourceOwnership
{
    internal const string Fact = "babel.methodImages.resourceInputs";
    internal sealed record Read(RecoveredResourceOrigin Source, int Length, uint Reader);
    internal sealed class Pending(RecoveredResourceOrigin source, int length, MethodDef[] readers)
    {
        internal RecoveredResourceOrigin Source { get; } = source;
        internal int Length { get; } = length;
        internal MethodDef[] Readers { get; } = readers;
        internal bool Published { get; set; }
    }

    internal static IReadOnlyList<Read> Observe(ModuleDef module, MethodDef stub, LoaderInterpretationEvidence evidence,
        IReadOnlySet<uint>? foreignTokens = null)
    {
        if (!evidence.HasCompleteObservations(LoaderObservationKind.ManagedResourceRead)) return [];
        var direct = new List<(ManagedResourceRead Resource, uint Reader, bool Owned)>();
        foreach (var observation in evidence.Observations.Where(item => item.Kind == LoaderObservationKind.ManagedResourceRead))
        {
            ManagedResourceRead? resource;
            try { resource = JsonSerializer.Deserialize<ManagedResourceRead>(observation.Detail); }
            catch (JsonException) { return []; }
            if (resource is null || resource.Length < 1 || resource.Length > 16 * 1024 * 1024) return [];
            var token = observation.CallStack.Count == 0 ? 0 : observation.CallStack[^1];
            var reader = module.ResolveToken(token) as MethodDef;
            // The image reader produces a local descriptor from a stream. A satellite
            // resolver returns Assembly, and scalar/string constructors return void;
            // neither can establish ownership of a method-image table here.
            var owned = foreignTokens?.Contains(token) != true && observation.CallStack.Contains(stub.MDToken.Raw) && reader is
                { HasBody: true, IsStatic: true, MethodSig.Params.Count: 0 } && reader.DeclaringType != stub.DeclaringType &&
                reader.ReturnType.ToTypeDefOrRef()?.ResolveTypeDef()?.Module == module &&
                reader.Body.Instructions.Any(instruction => instruction.Operand is IMethod called &&
                    called.FullName == "System.IO.Stream System.Reflection.Assembly::GetManifestResourceStream(System.String)");
            direct.Add((resource, token, owned));
        }
        // One unowned read of the same name prevents a successful image read from
        // hiding another consumer. Different bytes under one name are ambiguous too.
        return direct.GroupBy(item => item.Resource.Name).Where(group => group.All(item => item.Owned) &&
                group.Select(item => item.Resource).Distinct().Count() == 1)
            .SelectMany(group => group.Select(item => new Read(new(item.Resource.Name, item.Resource.Sha256), item.Resource.Length, item.Reader)))
            .Distinct().ToArray();
    }

    // Called only after both complete body constructions and the rewrite have committed.
    internal static void Remember(ArtifactContext context, IEnumerable<Read> reads)
    {
        context.TryGetFact<IReadOnlyList<Pending>>(Fact, out var earlier);
        var pending = new List<Pending>(earlier ?? []);
        foreach (var group in reads.Distinct().GroupBy(item => (item.Source, item.Length)))
        {
            var readers = group.Select(item => context.Module.ResolveToken(item.Reader)).OfType<MethodDef>().Distinct().ToArray();
            if (readers.Length != group.Select(item => item.Reader).Distinct().Count() || readers.Any(reader => reader.Module != context.Module)) continue;
            pending.Add(new(group.Key.Source, group.Key.Length, readers));
        }
        context.SetFact<IReadOnlyList<Pending>>(Fact, pending);
        Publish(context);
    }

    internal static void Publish(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<Pending>>(Fact, out var pending) || pending is null) return;
        foreach (var proof in pending.Where(proof => !proof.Published))
        {
            if (context.Module.Resources.Count(resource => resource.Name == proof.Source.Name) != 1 ||
                !context.Module.Resources.OfType<EmbeddedResource>().Any(resource => resource.Length == proof.Length && proof.Source.Matches(resource)) ||
                proof.Readers.Any(reader => reader.Module != context.Module)) continue;
            DecodedResourceOwnership.Remember(context, proof.Source, proof.Readers, methodImageConstruction: true);
            RecoveryOrphans.Declare(context, proof.Readers);
            proof.Published = true;
            context.AddEvidence(new("babel-method-image-resource-ownership",
                $"Both body-construction trials read {proof.Source.Name} (SHA-256 {proof.Source.Sha256}); removal requires every direct image reader to be physically retired.",
                string.Join(", ", proof.Readers.Select(reader => reader.FullName))));
        }
    }
}
