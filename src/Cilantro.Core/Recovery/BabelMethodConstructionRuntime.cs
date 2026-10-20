using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cilantro.Core.Analysis;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Complete reviewed delegate factories supplied with successfully recovered method images.</summary>
internal static class BabelMethodConstructionRuntime
{
    private const string Fact = "babel.methodImages.constructionRuntime";
    private sealed record Proof(uint Type, string Graph, string Metadata, string Parameters);

    internal static void Remember(ArtifactContext context, ModuleDef original)
    {
        var found = original.GetTypes().Where(type => type.Fields.Count == 2 && type.Methods.Count == 2 &&
            type.Fields.Any(field => field.FieldType.FullName == "System.Reflection.Emit.DynamicMethod") &&
            type.Fields.Any(field => field.FieldType.FullName == "System.Type"))
            .Select(Read).OfType<Proof>().ToArray();
        if (found.Length == 0) return;
        context.TryGetFact<IReadOnlyList<Proof>>(Fact, out var prior);
        context.SetFact<IReadOnlyList<Proof>>(Fact, (prior ?? []).Concat(found).Distinct().ToArray());
    }

    internal static IEnumerable<TypeDef> ReviewedFactories(ModuleDef module) => module.GetTypes()
        .Where(type => type.Fields.Count == 2 && type.Methods.Count == 2 &&
            type.Fields.Any(field => field.FieldType.FullName == "System.Reflection.Emit.DynamicMethod") &&
            type.Fields.Any(field => field.FieldType.FullName == "System.Type") && Read(type) is not null);

    internal static void Publish(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<Proof>>(Fact, out var proofs) || proofs is null) return;
        foreach (var proof in proofs)
        {
            if (context.Module.ResolveToken(proof.Type) is not TypeDef type || !context.Module.GetTypes().Contains(type) || Read(type) != proof) continue;
            if (context.Module.GetTypes().Where(candidate => candidate != type).SelectMany(candidate => candidate.Methods)
                .Where(method => method.HasBody).SelectMany(method => method.Body.Instructions)
                .Any(instruction => instruction.Operand is string text && (text == type.FullName || text == type.ReflectionFullName ||
                    text.StartsWith(type.ReflectionFullName + ",", StringComparison.Ordinal)))) continue;
            RecoveryOrphans.Declare(context, type.Methods);
            RecoveryOrphans.DeclareTypes(context, [type]);
        }
    }

    private static Proof? Read(TypeDef type)
    {
        if (type.Fields.Count != 2 || type.Methods.Count != 2 || type.Properties.Count != 0 || type.Events.Count != 0 ||
            type.DeclSecurities.Count != 0 || type.ClassLayout is not null) return null;
        var graph = GeneratedRuntimeShape.ReadCanonical(type.Methods[0]);
        if (graph.Types.Count != 1 || graph.Types[0] != type) return null;
        var metadata = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(GeneratedRuntimeMetadata.Describe(type))));
        return (graph.Fingerprint, metadata) is
            ("30d28c010882bb3346aa3f538062d27145f7ba2c309e217ffb7d96ac4405f90a", "60c6bbb8f5a2683a69dc09e53257e54a2fa325439ecad94637db071a2c392526") or
            ("1a02ace6444ff9532b7ed34a66dfbd0aaa7e1f6a8235b9150143a42e878ab1ae", "eee8fcebdda9a103560af3ee3050d290f0b70263099d1ea341751f6c1d55e6d7") or
            ("cfb76f0f484d2eee94d9addaca10bcfa7429284a8c726ae9a5504824045ac51f", "0b041b4ca3f108cb4fe6ab79192db31801681e061562259c12fc7d7847c40f99")
            ? new(type.MDToken.Raw, graph.Fingerprint, metadata, JsonSerializer.Serialize(type.Methods.Select(method =>
                method.ParamDefs.Select(parameter => new { parameter.Sequence, Name = parameter.Name.String })))) : null;
    }
}
