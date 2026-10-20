using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

/// <summary>Complete bounded Android Root Check graph, including generic helper declarations.</summary>
internal static class DotfuscatorRootCheckShape
{
    // Filled only from an independently reviewed licensed producer capture.
    internal static bool Supported(string fingerprint) => fingerprint is
        "c9b07469e63c9fb4281e8b1d5f0c1ce585600a6ebcb963410817f1e27045113a" or
        "ec63229d6f95e08a6edb025f495752558a402f7f7cc5ce4e31a446103d22cb1b" or
        "ac6330502c701035f1227fd64a454d53fb928acef7d3b175c572854bb23c4b45";

    internal static GeneratedRuntimeShape.Graph Read(MethodDef root, bool canonical = false)
    {
        var graph = canonical ? GeneratedRuntimeShape.ReadCanonicalGenericFamily(root) : GeneratedRuntimeShape.ReadGenericFamily(root);
        return WithMetadata(graph);
    }

    internal static GeneratedRuntimeShape.Graph ReadType(MethodDef root) => WithMetadata(GeneratedRuntimeShape.ReadCanonicalType(root));

    private static GeneratedRuntimeShape.Graph WithMetadata(GeneratedRuntimeShape.Graph graph)
    {
        var types = graph.Types;
        if (graph.Fingerprint.Length != 64 || types.Sum(type => type.Methods.Count) > 192 ||
            types.Sum(type => type.Methods.Where(method => method.HasBody).Sum(method => method.Body.Instructions.Count)) > 65_536 ||
            types.Any(type => type.DeclSecurities.Count != 0 || type.Events.Count != 0 ||
                type.Interfaces.Any(item => item.HasCustomAttributes) || type.Properties.Any(property => property.HasCustomAttributes) ||
                type.Methods.Any(method => method.DeclSecurities.Count != 0) ||
                type.GenericParameters.Concat(type.Methods.SelectMany(method => method.GenericParameters)).Any(parameter =>
                    parameter.Kind is not null || parameter.HasCustomAttributes || parameter.GenericParamConstraints.Any(constraint => constraint.HasCustomAttributes))))
            return new(types, "unreviewed Android checker metadata or bounds");
        string Type(ITypeDefOrRef type) => type.FullName + "@" + type.DefinitionAssembly?.FullName;
        object Parameter(GenericParam parameter) => new
        {
            parameter.Number, parameter.Flags, Name = parameter.Name.String,
            Constraints = parameter.GenericParamConstraints.Select(constraint => Type(constraint.Constraint)).ToArray()
        };
        var metadata = JsonSerializer.Serialize(new
        {
            Declarations = BabelDormantMethodRuntime.Describe(types),
            Generics = types.Select(type => new
            {
                Type = type.GenericParameters.Select(Parameter).ToArray(),
                Methods = type.Methods.Select(method => method.GenericParameters.Select(Parameter).ToArray()).ToArray()
            }).ToArray()
        });
        return new(types, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(graph.Fingerprint + "\n" + metadata))));
    }

    internal static bool TryNormalize(DotfuscatorCheckShape.Runtime runtime, out string fingerprint)
    {
        fingerprint = "Android checker normalization did not complete";
        if (runtime.Types.Count > 32 || runtime.Types.Sum(type => type.Methods.Count) > 192) return false;
        try
        {
            foreach (var type in runtime.Types)
            {
                Sort(type.CustomAttributes);
                foreach (var field in type.Fields) Sort(field.CustomAttributes);
                foreach (var method in type.Methods)
                {
                    Sort(method.CustomAttributes);
                    foreach (var parameter in method.ParamDefs) Sort(parameter.CustomAttributes);
                }
            }
            foreach (var method in runtime.Types.SelectMany(type => type.Methods).Where(method => method.HasBody))
            {
                // The injected string codec carries values across loop edges. If
                // general normalization refuses a body, retain its entire original
                // CIL in this private proof copy; the final whole-family hash must
                // still match the reviewed body, including every instruction.
                using var trial = new BodyMutationBatch([method]);
                if (GeneratedRuntimeBodyNormalization.TryNormalizeStackSafe(method, true, out _)) trial.Commit();
            }
            DotfuscatorCheckNormalization.RemoveUnusedMarkerFields(runtime);
            fingerprint = Read(runtime.Method, true).Fingerprint;
            return fingerprint.Length == 64;
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or KeyNotFoundException or IndexOutOfRangeException)
        { fingerprint = "invalid Android checker graph: " + exception.Message; return false; }

        static void Sort(IList<CustomAttribute> attributes)
        {
            var sorted = attributes.OrderBy(attribute => attribute.Constructor.FullName + "@" +
                attribute.Constructor.DeclaringType.DefinitionAssembly?.FullName, StringComparer.Ordinal).ToArray();
            attributes.Clear();
            foreach (var attribute in sorted) attributes.Add(attribute);
        }
    }
}
