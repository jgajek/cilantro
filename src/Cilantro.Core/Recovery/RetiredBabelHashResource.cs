using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>An exact encrypted table superseded by an intact verified eager cache.</summary>
internal sealed class RetiredBabelHashResource
{
    internal const string Fact = "babel.hashStrings.retiredResources";
    internal RecoveredResourceOrigin Source { get; }
    private readonly (MethodDef Method, string Signature, MethodBodySnapshot Body)[] methods;
    private readonly (FieldDef Field, string Signature, FieldAttributes Attributes)[] fields;
    private readonly FieldDef? nameDelegate;
    private readonly string? nameDelegateSignature;

    private RetiredBabelHashResource(RecoveredResourceOrigin source, BabelHashStringShape.Cache cache)
    {
        Source = source;
        methods = new[] { cache.Constructor, cache.Initializer, cache.Getter, cache.Wrapper }
            .Select(method => (method, method.FullName, MethodBodySnapshot.Capture(method))).ToArray();
        fields = new[] { cache.Singleton, cache.Dictionary }
            .Select(field => (field, field.FullName, field.Attributes)).ToArray();
        nameDelegate = cache.Constructor.DeclaringType.Fields.SingleOrDefault(field => field != cache.Singleton && field != cache.Dictionary);
        nameDelegateSignature = nameDelegate?.FullName;
    }

    // Called only after complete original construction trials, replacement and verification.
    internal static void Remember(ArtifactContext context, RecoveredResourceOrigin source, BabelHashStringShape.Cache cache)
    {
        if (context.Module.Resources.Count(resource => resource.Name == source.Name) != 1 ||
            !context.Module.Resources.OfType<EmbeddedResource>().Any(source.Matches)) return;
        context.TryGetFact<IReadOnlyList<RetiredBabelHashResource>>(Fact, out var earlier);
        context.SetFact<IReadOnlyList<RetiredBabelHashResource>>(Fact, [.. earlier ?? [], new(source, cache)]);
        context.AddEvidence(new("babel-hash-resource-retirement",
            $"Two complete construction trials attributed {source.Name} (SHA-256 {source.Sha256}); cleanup requires the exact materialized cache and remaining-reader checks.", cache.Wrapper.FullName));
    }

    internal bool IsPreserved(ModuleDef module)
    {
        if (module.Resources.Count(resource => resource.Name == Source.Name) != 1 ||
            !module.Resources.OfType<EmbeddedResource>().Any(Source.Matches)) return false;
        var types = module.GetTypes().ToHashSet();
        return methods.All(item => types.Contains(item.Method.DeclaringType) && item.Method.DeclaringType.Methods.Contains(item.Method) &&
                item.Method.FullName == item.Signature && item.Body.StructurallyEquals(item.Method)) &&
            fields.All(item => types.Contains(item.Field.DeclaringType) && item.Field.DeclaringType.Fields.Contains(item.Field) &&
                item.Field.FullName == item.Signature && item.Field.Attributes == item.Attributes);
    }

    internal static IEnumerable<FieldDef> UnusedNameDelegates(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<RetiredBabelHashResource>>(Fact, out var proofs) || proofs is null) yield break;
        var referenced = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions).Select(instruction => instruction.Operand).OfType<IField>()
            .Select(field => field.ResolveFieldDef()).OfType<FieldDef>().ToHashSet();
        foreach (var proof in proofs.Where(proof => proof.IsPreserved(context.Module)))
            if (proof.nameDelegate is { IsPrivate: true, IsStatic: true, IsInitOnly: true, HasCustomAttributes: false } field &&
                field.FullName == proof.nameDelegateSignature && field.DeclaringType is { IsAutoLayout: true } owner &&
                owner.Fields.Contains(field) && !referenced.Contains(field)) yield return field;
    }
}
