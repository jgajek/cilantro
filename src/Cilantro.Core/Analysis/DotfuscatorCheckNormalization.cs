using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Normalizes a private checker copy before comparing its complete graph with reviewed baselines.</summary>
internal static class DotfuscatorCheckNormalization
{
    // Independently reviewed, unflattened check corpus. Mixed protection must
    // reach these same full metadata and instruction-edge graphs.
    internal static bool Reviewed(string fingerprint) => DotfuscatorRootCheckShape.Supported(fingerprint) || fingerprint is
        "fb31b9d945d5ad0cb53dd0cb2c2ca32ffe9f315822a94c456fb9c3dc75772828" or
        "a62b02a7143fc19f497fc7a2be762b1f010562e741da36936695a225ce68ab73" or
        "feb02b4421469885aaf41a0de0e5d0c0128a0e909d46df372bf9ba3b845d35da" or
        "98cdc0fe2117b9706348643c1953cee6872da05dceec3dc434b3f8e2ad30aa1e" or
        "8706f55e81042049c50727f727bc455148478766999c82f35d1a3f40d510ded0" or
        "8849831d077cdf19b1273de06bf1537af2d2b45cbb63ff208928e93e316a591e" or
        "a863e2d6ee27fdf9c22fa547d7e3bfef37975b457cedaf29e857b017ce87e043" or
        "90819447ad989653aa7e3f53d5589b46edf6f4694d60f911dec9fcf2cb6aeb67" or
        "4f2da2705d1b3ac81808314932d905cb6923d79862806c5814709e794b96e3aa";

    internal static bool TryNormalize(DotfuscatorCheckShape.Runtime runtime, bool requireShortLocalMarker, out string fingerprint)
    {
        if (runtime.Kind == "root") return DotfuscatorRootCheckShape.TryNormalize(runtime, out fingerprint);
        fingerprint = "normalization did not complete";
        var methods = runtime.Types.SelectMany(type => type.Methods).Where(method => method.HasBody).ToArray();
        if (runtime.Types.Count > 32 || methods.Length > 192 || methods.Sum(method => method.Body.Instructions.Count) > 65_536 ||
            methods.Any(method => method.Body.Instructions.Count > 4096)) return false;
        var marker = false;
        try
        {
            foreach (var method in methods)
            {
                if (!GeneratedRuntimeBodyNormalization.TryNormalize(method, shortLocals: true, out var shortReads)) return false;
                marker |= shortReads != 0;
            }
            if (requireShortLocalMarker && !marker) { fingerprint = "no generated short-local marker"; return false; }
            RemoveUnusedMarkerFields(runtime);
            fingerprint = GeneratedRuntimeShape.ReadCanonical(runtime.Method).Fingerprint;
            return true;
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or KeyNotFoundException or IndexOutOfRangeException)
        {
            fingerprint = "invalid normalized checker graph: " + exception.GetType().Name;
            return false;
        }
    }

    internal static void RemoveUnusedMarkerFields(DotfuscatorCheckShape.Runtime runtime)
    {
        var referenced = runtime.Method.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions).Select(instruction => instruction.Operand).OfType<IField>()
            .Where(field => field.FieldSig is not null).Select(field => field.ResolveFieldDef()).OfType<FieldDef>().ToHashSet();
        foreach (var type in runtime.Types.Where(type => !type.IsValueType && type.IsAutoLayout))
            foreach (var field in type.Fields.Where(field => !referenced.Contains(field) &&
                         field.Attributes == (FieldAttributes.Private | FieldAttributes.NotSerialized | FieldAttributes.HasDefault) &&
                         field.FieldType.ElementType == ElementType.String && (field.Constant?.Value is sbyte and 32 or "") &&
                         field.FieldOffset is null && field.MarshalType is null && !field.HasCustomAttributes && field.InitialValue is not { Length: > 0 }).ToArray())
                type.Fields.Remove(field);
    }

}
