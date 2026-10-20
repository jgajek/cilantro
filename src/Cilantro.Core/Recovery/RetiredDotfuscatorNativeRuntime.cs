using System.Text.Json;
using Cilantro.Core.Analysis;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Whole-type proof for the public native bridge superseded by v2 recovery.</summary>
internal sealed record RetiredDotfuscatorNativeRuntime(TypeDef Type, string Environment, string Fingerprint, string Metadata)
{
    private const string Fact = "dotfuscator.v2.retiredNative";

    internal static void Remember(ArtifactContext context, DotfuscatorV2Shape.Runtime runtime)
    {
        if (context.Module.ResolveToken(runtime.NativeType.MDToken) is not TypeDef type) return;
        using var proof = ModuleDefMD.Load(context.OriginalBytes);
        if (proof.ResolveToken(runtime.NativeType.MDToken) is not TypeDef source || !Describe(source, runtime.EnvironmentFile, out var hash) || !Reviewed(hash)) return;
        context.TryGetFact<IReadOnlyList<RetiredDotfuscatorNativeRuntime>>(Fact, out var previous);
        context.SetFact<IReadOnlyList<RetiredDotfuscatorNativeRuntime>>(Fact,
            [.. previous ?? [], new(type, runtime.EnvironmentFile, hash, ExtraMetadata(source))]);
    }

    internal static IEnumerable<TypeDef> Unused(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<RetiredDotfuscatorNativeRuntime>>(Fact, out var proofs) || proofs is null) yield break;
        var current = context.Module.GetTypes().ToHashSet();
        foreach (var proof in proofs)
        {
            if (!current.Contains(proof.Type) || context.Module.EntryPoint?.DeclaringType == proof.Type) continue;
            var metadata = ExtraMetadata(proof.Type);
            if (metadata != proof.Metadata)
            { context.AddEvidence(new("dotfuscator-native-retained", "Native bridge metadata changed after recovery; whole-type retirement withheld: " + Difference(proof.Metadata, metadata))); continue; }
            // Type-name reflection from surviving application code is a consumer too.
            if (current.Where(type => type != proof.Type).SelectMany(type => type.Methods).Where(method => method.HasBody)
                .SelectMany(method => method.Body.Instructions).Any(instruction => instruction.Operand is string text &&
                    (text == proof.Type.FullName || text == proof.Type.ReflectionFullName || text.StartsWith(proof.Type.ReflectionFullName + ",", StringComparison.Ordinal)))) continue;
            if (MatchesCurrent(context, proof, out var reason)) yield return proof.Type;
            else context.AddEvidence(new("dotfuscator-native-retained", reason));
        }
    }

    private static bool MatchesCurrent(ArtifactContext context, RetiredDotfuscatorNativeRuntime proof, out string reason)
    {
        reason = "Current native bridge could not be matched to its reviewed complete type.";
        try
        {
            using var bytes = new MemoryStream(); context.Module.Write(bytes);
            using var copy = ModuleDefMD.Load(bytes.ToArray());
            var types = copy.GetTypes().Where(type => type.FullName == proof.Type.FullName).ToArray();
            if (types.Length != 1 || !Describe(types[0], proof.Environment, out var hash)) return false;
            reason = "Native bridge normalized graph changed: " + hash + "; expected " + proof.Fingerprint + ".";
            return hash == proof.Fingerprint || ReviewedInlining(proof.Fingerprint, hash);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or ArgumentException or dnlib.DotNet.Writer.ModuleWriterException)
        { return false; }
    }

    // Called only on independent metadata copies; normalization never changes the output.
    private static bool Describe(TypeDef type, string environment, out string fingerprint)
    {
        fingerprint = "";
        if (type.HasGenericParameters || type.HasInterfaces || type.HasNestedTypes || type.HasProperties || type.HasEvents || type.HasDeclSecurities) return false;
        var roots = type.Methods.Where(method => method.Name == "ComputeKey").ToArray();
        if (roots.Length != 1) return false;
        var root = roots[0];
        // Match the decoder graph's Windows system-library rule. Export names
        // and every non-system library name remain exact.
        foreach (var method in type.Methods.Where(method => method.ImplMap is not null))
            if (string.Equals(method.ImplMap.Module.Name, "kernel32.dll", StringComparison.OrdinalIgnoreCase)) method.ImplMap.Module.Name = "kernel32.dll";
        foreach (var method in type.Methods.Where(method => method.HasBody))
        {
            foreach (var instruction in method.Body.Instructions.Where(instruction => instruction.Operand is string text && text == environment)) instruction.Operand = "$environment";
            if (!GeneratedRuntimeBodyNormalization.TryNormalize(method, false, out _)) return false;
        }
        var graph = GeneratedRuntimeShape.ReadCanonical(root);
        if (graph.Types.Count != 1 || graph.Types[0] != type) return false;
        fingerprint = graph.Fingerprint;
        return true;
    }

    private static bool Reviewed(string fingerprint) => fingerprint is
        "45b06fb056a2db0c04844eef672b162e45ba59dbd47f4789b1c9ed2475dbb50a" or
        "ef9423095f9e2661c98acf2d46db67c24f799abbbd833ecc2da6f97109c79b7d" or
        "12f751d2c2b76986197caaf7708635a75c9e08f7320a582dc80c365a96c1a4a3";

    // Complete CoreCLR type graphs after ordinary forwarder inlining. The only
    // differences are nine calls to the exact no-argument OperatingSystem Boolean
    // APIs in place of their same-owner call/ret wrappers; every other member,
    // instruction, operand, handler, import and field stays in the fingerprint.
    private static bool ReviewedInlining(string source, string current) => (source, current) is
        ("ef9423095f9e2661c98acf2d46db67c24f799abbbd833ecc2da6f97109c79b7d", "7f33ea489cbe6c3f5e41fc4f4060fbd3251e96a2bee9ec7a6b02a756c090cd92") or
        ("12f751d2c2b76986197caaf7708635a75c9e08f7320a582dc80c365a96c1a4a3", "75b68b8e6117109530b8370be09de880346da81acd347c8aa294cc086b785dfa");

    private static string Difference(string expected, string current)
    {
        using var first = JsonDocument.Parse(expected); using var second = JsonDocument.Parse(current);
        foreach (var property in first.RootElement.EnumerateObject())
        {
            var actual = second.RootElement.GetProperty(property.Name);
            if (property.Value.GetRawText() == actual.GetRawText()) continue;
            if (property.Value.ValueKind != JsonValueKind.Array) return property.Name;
            if (property.Value.GetArrayLength() != actual.GetArrayLength()) return property.Name + " count " + property.Value.GetArrayLength() + " -> " + actual.GetArrayLength();
            for (var index = 0; index < property.Value.GetArrayLength(); index++)
                if (property.Value[index].GetRawText() != actual[index].GetRawText())
                    return property.Name + "[" + index + "] expected=" + property.Value[index].GetRawText() + "; current=" + actual[index].GetRawText();
        }
        return "unmatched metadata";
    }

    private static string ExtraMetadata(TypeDef type) => GeneratedRuntimeMetadata.Describe(type);
}
