using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cilantro.Core.Analysis;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Reviewed leaf declarations of an independently recovered method runtime.</summary>
internal static class BabelMethodLeafRuntime
{
    private const string Fact = "babel.methodImages.leafRuntime";
    private sealed record Proof(uint[] Types, string Metadata, string BufferGraph);

    internal static void Remember(ArtifactContext context, ModuleDef original, IEnumerable<MethodDef> dispatchers,
        IReadOnlyList<BabelMethodImageResourceOwnership.Read> inputs)
    {
        if (!context.TryGetFact<int>("babel.methodImages.detected", out var detected) || detected < 1 ||
            !context.TryGetFact<int>("babel.methodImages.restored", out var restored) || restored != detected ||
            inputs.Count == 0 || inputs.Select(input => input.Source).Distinct().Count() != 1) return;
        var roots = dispatchers.ToArray();
        if (roots.Length != 1) return;
        TypeDef[] family;
        int graphTypes;
        try
        {
            family = BabelDormantMethodRuntime.Family(roots[0]);
            graphTypes = GeneratedRuntimeShape.ReadCanonicalFamily(roots[0]).Types.Count;
        }
        catch (InvalidOperationException) { return; }
        // Signature-writer bodies vary with the protected input. The original
        // declaration schema and agreed image reads anchor only this fixed leaf
        // set; the buffer's complete body graph is checked independently below.
        if (family.Length != 54 || graphTypes != 52 ||
            !KnownFamily(Hash(BabelDormantMethodRuntime.Describe(family)))) return;
        var leaves = family.Where(type => !type.IsNested && (type.IsEnum || type.IsValueType && type.Methods.Count == 0 ||
            type.Methods.Count == 5 && type.Fields.Count == 2 &&
            type.Fields.Any(field => field.FieldType.FullName == "System.Int32[]") &&
            type.Fields.Any(field => field.FieldType.ElementType == ElementType.I4))).ToArray();
        if (leaves.Length != 9 || leaves.Count(type => type.IsEnum) != 6) return;
        var proof = Read(leaves);
        if (proof is null || !Known(proof.Metadata, proof.BufferGraph, false)) return;
        context.SetFact(Fact, proof);
    }

    internal static void Publish(ArtifactContext context)
    {
        if (!context.TryGetFact<Proof>(Fact, out var proof) || proof is null) return;
        var present = context.Module.GetTypes().ToHashSet();
        var types = proof.Types.Select(token => context.Module.ResolveToken(token)).OfType<TypeDef>().ToArray();
        if (types.Length != 9 || types.Any(type => !present.Contains(type))) return;
        var current = Read(types);
        if (current is null || current.Metadata != proof.Metadata || !Known(current.Metadata, current.BufferGraph, true)) return;
        var names = types.SelectMany(type => new[] { type.FullName, type.ReflectionFullName }).ToArray();
        if (present.Except(types).SelectMany(type => type.Methods).Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions).Any(instruction => instruction.Operand is string text &&
                names.Any(name => text == name || text.StartsWith(name + ",", StringComparison.Ordinal)))) return;
        RecoveryOrphans.Declare(context, types.SelectMany(type => type.Methods));
        // A combined-protection runtime can still use the buffer or a layout.
        // Attribution grants no exemption from ordinary deadness/reference gates.
        RecoveryOrphans.DeclareTypes(context, types);
    }

    private static Proof? Read(TypeDef[] types)
    {
        if (types.Length != 9 || types.Any(type => type.IsGlobalModuleType || MemberVisibility.IsExternallyVisible(type) ||
            type.HasGenericParameters || type.IsNested || type.NestedTypes.Count != 0 || type.Interfaces.Count != 0 ||
            type.ClassLayout is not null || type.DeclSecurities.Count != 0 || type.Events.Count != 0 ||
            type.Methods.Any(method => method.HasGenericParameters || method.DeclSecurities.Count != 0) ||
            type.Properties.Any(property => property.HasCustomAttributes))) return null;
        var buffers = types.Where(type => type.Methods.Count != 0).ToArray();
        if (buffers.Length != 1 || buffers[0].Methods.Count != 5) return null;
        var buffer = buffers[0];
        GeneratedRuntimeShape.Graph graph;
        try { graph = GeneratedRuntimeShape.ReadCanonical(buffer.Methods[0]); }
        catch (InvalidOperationException) { return null; }
        if (graph.Types.Count != 1 || graph.Types[0] != buffer) return null;
        var metadata = Hash(JsonSerializer.Serialize(new
        {
            Declarations = BabelDormantMethodRuntime.Describe(types),
            BaseScopes = types.Select(type => type.BaseType?.DefinitionAssembly?.FullName)
        }));
        return new(types.Select(type => type.MDToken.Raw).ToArray(), metadata, graph.Fingerprint);
    }

    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private static bool KnownFamily(string metadata) => metadata is
        "c229e7dab7613baeff10ba631e933b97b0bdb849e2d035c1f2a87a0b703ca015" or
        "440a7f36a368d1f8225b6b1213fef3ef4fb055fb85b77940d6f5d1628c9bdbac" or
        "8b7705ae0e1b678a96fc18ef24e51888b5330032faa2d819b078610cf5dbfe63" or
        "c0314b67bf3f04cf43b9f0602b4f2de452636fa7a7504e0e492c77ce5193507b" or
        "eda5c8ea9fa7c9a9a6973a40d8b7a951422fc5163018c243ef3e2196d3999133" or
        "61a81e6874eedc0ae7ab80ad045a6d8ce275888179aca00753ebbe08a5d92627" or
        "d53b005752a801bbbc6b38cc39b551e68f6c4d952f69648dbbc7bf89797d9e4e" or
        "d6d60b69c772390b9f23432253bd72ccfd03e88a06289c4e20aa5d21c8114f81" or
        "faf0d1fba3cfc82e51c90e7850345955f87d991cd6f539b9265439de9ced104f";

    private static bool Known(string metadata, string graph, bool allowSimplified) => (metadata, graph) is
        ("dd67f6011f9682bcc4efa8bea0228a371fef6f83c009caec8fcf1afa4f6d3ccb", "c6b09069e30332f2ec09f9d4d1a54e25102359b3d9f3c0420bc01f74810a1fca") or
        ("f60d59e08eb0e67918a5942609562334b9c00fcd22e8ad6b8a1267b48b5f4fbd", "56721f6daf25c44fd497dd2a640dc70ed54209483602493e5c1724600ff24451") or
        ("6f29c5e27710805f4c6ea03ae8114f4529e29345a73e1ab84d130d6184e02406", "2e9a816d3e029f93a199c6ba04a741b7f601d327fff4f8d70b7c0c8ede24c6d5") ||
        allowSimplified && (metadata, graph) is
        ("dd67f6011f9682bcc4efa8bea0228a371fef6f83c009caec8fcf1afa4f6d3ccb", "6195df4ce2eab4ff977558d66670dc173cdfd37d31d30ef0633cb2be3de047f1") or
        ("f60d59e08eb0e67918a5942609562334b9c00fcd22e8ad6b8a1267b48b5f4fbd", "37d4a0b421ccf95cf5cd4c5435d0eeac728bffb7cf316f46ee9c81fb2bf5a2d5") or
        ("6f29c5e27710805f4c6ea03ae8114f4529e29345a73e1ab84d130d6184e02406", "df8cd42dab51704b7e512786f798bce402979913048934f583844675bb8799f7");
}
