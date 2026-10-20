using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cilantro.Core.Analysis;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Complete reviewed empty-image runtimes, never inferred from a watermark alone.</summary>
internal static class BabelDormantMethodRuntime
{
    private const string Fact = "babel.methodImages.dormantRuntime";
    private sealed record Proof(uint Root, string Graph, string Metadata);

    internal static bool Remember(ArtifactContext context, ModuleDef original, IEnumerable<MethodDef> dispatchers)
    {
        if (original.Resources.Count != 0) return false;
        var proofs = dispatchers.Select(root => Read(root, false)).OfType<Proof>().Distinct().ToArray();
        if (proofs.Length == 0) return false;
        context.SetFact<IReadOnlyList<Proof>>(Fact, proofs);
        return true;
    }

    internal static void Publish(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<Proof>>(Fact, out var proofs) || proofs is null) return;
        foreach (var proof in proofs)
        {
            if (context.Module.ResolveToken(proof.Root) is not MethodDef root || !context.Module.GetTypes().Contains(root.DeclaringType) ||
                !root.DeclaringType.Methods.Contains(root)) continue;
            if (Read(root, true) != proof)
            {
                context.AddEvidence(new("babel-dormant-runtime-retained", "The reviewed empty-image runtime changed before cleanup; ownership was withheld."));
                continue;
            }
            var types = Family(root);
            var names = types.SelectMany(type => new[] { type.FullName, type.ReflectionFullName }).ToArray();
            if (context.Module.GetTypes().Except(types).SelectMany(type => type.Methods).Where(method => method.HasBody)
                .SelectMany(method => method.Body.Instructions).Any(instruction => instruction.Operand is string text &&
                    names.Any(name => text == name || text.StartsWith(name + ",", StringComparison.Ordinal)))) continue;
            var reachability = ModuleReachability.ComputeWithInstances(context.Module, typeInitializersAlwaysRun: false, RebuiltMethods.CleanupRoots(context));
            if (types.Any(type => reachability.IsReflectivelyExposed(type) || type.Methods.Any(reachability.IsReachable)) ||
                RuntimeCleanupPass.ComputeUnreferenced(context.Module, types.ToHashSet()).Count != types.Length) continue;
            RecoveryOrphans.Declare(context, types.SelectMany(type => type.Methods));
            RecoveryOrphans.DeclareTypes(context, types);
        }
    }

    private static Proof? Read(MethodDef root, bool allowSimplified)
    {
        var graph = GeneratedRuntimeShape.ReadCanonicalFamily(root);
        var factories = BabelMethodConstructionRuntime.ReviewedFactories(root.Module).ToArray();
        if (root.Module.Resources.Count != 0 || factories.Length != 1) return null;
        var types = Family(root);
        if (graph.Types.Count != 52 || types.Length != 54 || types.Any(type => type.IsGlobalModuleType || MemberVisibility.IsExternallyVisible(type) ||
            type.DeclSecurities.Count != 0 || type.Events.Count != 0 || type.Interfaces.Any(item => item.HasCustomAttributes) ||
            type.Methods.Any(method => method.HasGenericParameters || method.DeclSecurities.Count != 0) ||
            type.Properties.Any(property => property.HasCustomAttributes))) return null;
        var metadata = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Describe(types))));
        var original = OriginalGraph(graph.Fingerprint, metadata, allowSimplified);
        return original is null ? null : new(root.MDToken.Raw, original, metadata);
    }

    // Babel also emits an otherwise disconnected value/enum storage pair. Only
    // this bounded storage shape participates; arbitrary inbound application
    // references remain consumers for the ordinary cleanup reference gate.
    internal static TypeDef[] Family(MethodDef root)
    {
        var graph = GeneratedRuntimeShape.ReadCanonicalFamily(root);
        var storage = root.Module.GetTypes().Where(type => type.IsValueType && !type.IsEnum &&
            !type.HasGenericParameters && !type.IsNested && type.NestedTypes.Count == 0 && type.Interfaces.Count == 0 &&
            new SigComparer().Equals(type.BaseType, root.Module.CorLibTypes.GetTypeRef("System", "ValueType")) &&
            type.Methods.Count == 0 && type.Fields.Count == 2 &&
            type.Fields[0].FieldType.ToTypeDefOrRef()?.ResolveTypeDef() is { IsEnum: true } enumeration && graph.Types.Contains(enumeration) &&
            type.Fields[1].FieldType.ElementType == ElementType.Object);
        return graph.Types.Concat(BabelMethodConstructionRuntime.ReviewedFactories(root.Module)).Concat(storage).Distinct().ToArray();
    }

    // The second graph is the reviewed result of the pipeline's constant-branch and
    // dispatcher simplification. It is accepted only after the original graph was
    // independently authenticated; metadata must remain identical in both states.
    private static string? OriginalGraph(string graph, string metadata, bool allowSimplified)
    {
        var pair = metadata switch
        {
            "7ae73955883164b974cc12bd7902786bf509e7cf75fb66d0efeabe3c7ecb7ce3" => ("5bcdcbe6571e1284afc6b69844ad4ef73045616b775e1ef37d6b384876e2050e", "7ab93ed2e2c6e6ea852993603cd91ffa3ef92b5bca972cdf7345a06bca734867"),
            "4fcab6781515a407c8f08abcad3b00d936c11a8bfbb2616a745b20f0694e8e0d" => ("26f546f96d634052365c7527a1d06441844afa4c5090aa6463f5c6970da48906", "565e1c7efbfda4a2f5594902cdee477553985c1d1ff23a1fce1ac7e00029d151"),
            "5501891212716fda979076fee73daa12509bd62c52570c4462a900799832c06c" => ("f1b7457964d432b65436f3984e753f3b2f41fadb813430168a966d12e632fbb5", "0b17bdc3a992dbe396977fc760170ec03047bec1cd70a1ae9af906ffc4664266"),
            _ => ("", "")
        };
        return pair.Item1.Length != 0 && (graph == pair.Item1 || allowSimplified && graph == pair.Item2) ? pair.Item1 : null;
    }

    internal static string Describe(IReadOnlyList<TypeDef> types, bool scopedTypeNames = false)
    {
        var methods = types.SelectMany(type => type.Methods).Select((method, index) => (method, index)).ToDictionary(item => item.method, item => item.index);
        string Role(string text)
        {
            if (types[0].Module.Assembly is { } assembly) text = text.Replace(assembly.FullName, "$assembly", StringComparison.Ordinal);
            if (scopedTypeNames) return RuntimeTypeRoles.Replace(text, types.Select((type, index) => (type.FullName, "$type" + index)).ToArray());
            foreach (var pair in types.Select((type, index) => (type, index)).OrderByDescending(pair => pair.type.FullName.Length))
                text = text.Replace(pair.type.FullName, "$type" + pair.index, StringComparison.Ordinal);
            return text;
        }
        object? Normalize(JsonElement item) => item.ValueKind switch
        {
            JsonValueKind.Object => item.EnumerateObject().ToDictionary(property => property.Name, property => Normalize(property.Value), StringComparer.Ordinal),
            JsonValueKind.Array => item.EnumerateArray().Select(Normalize).ToArray(),
            JsonValueKind.String => Role(item.GetString()!),
            JsonValueKind.Number => item.GetInt64(),
            JsonValueKind.True => true, JsonValueKind.False => false, _ => null
        };
        int Method(MethodDef? method) => method is not null && methods.TryGetValue(method, out var index) ? index : -1;
        return JsonSerializer.Serialize(types.Select(type =>
        {
            using var extra = JsonDocument.Parse(GeneratedRuntimeMetadata.Describe(type));
            return new
            {
                type.Attributes, Base = Role(type.BaseType?.FullName ?? ""), type.PackingSize, type.ClassSize,
                Fields = type.Fields.Select(field => new { field.Attributes, field.FieldOffset, Marshal = field.MarshalType?.ToString(), Initial = Convert.ToHexString(field.InitialValue ?? []) }),
                Metadata = Normalize(extra.RootElement),
                Parameters = type.Methods.Select(method => method.ParamDefs.Select(parameter => new
                { parameter.Sequence, parameter.Attributes, Name = parameter.Name.String, Marshal = parameter.MarshalType?.ToString(), ConstantType = parameter.Constant?.Type, Constant = Convert.ToString(parameter.Constant?.Value, System.Globalization.CultureInfo.InvariantCulture) })),
                Properties = type.Properties.Select(property => new
                {
                    Name = Role(property.Name.String), property.Attributes, Signature = Role(property.PropertySig.ToString()),
                    Scopes = property.PropertySig.Params.Prepend(property.PropertySig.RetType).Select(signature => Role(signature.ToTypeDefOrRef()?.DefinitionAssembly?.FullName ?? "")),
                    Getters = property.GetMethods.Select(Method), Setters = property.SetMethods.Select(Method), Other = property.OtherMethods.Select(Method),
                    ConstantType = property.Constant?.Type,
                    Constant = Convert.ToString(property.Constant?.Value, System.Globalization.CultureInfo.InvariantCulture)
                })
            };
        }));
    }
}
