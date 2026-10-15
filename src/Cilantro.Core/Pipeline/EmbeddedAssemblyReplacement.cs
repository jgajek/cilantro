using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Core;

/// <summary>Prepares an exact-resource child replacement after separate recovery and loader validation.</summary>
/// <remarks>
/// This checks the packaging contract only. The caller must establish that the resource is loaded
/// as an assembly, that child recovery is verified, and that no consumer depends on its original bytes.
/// It deliberately neither mutates the wrapper nor promotes its recovery status.
/// </remarks>
internal static class EmbeddedAssemblyReplacement
{
    internal const int MaximumAssemblyBytes = 256 * 1024 * 1024;

    internal static EmbeddedResource PrepareForLoader(MethodDef loader, Local buffer, string expectedInputSha256, byte[] recovered)
    {
        if (!ManagedBootstrapShape.Matches(loader.Module))
            throw new InvalidDataException("Wrapper does not match a fully supported managed bootstrap body.");
        var name = RawAssemblyBufferUse.ResourceName(loader, buffer)
            ?? throw new InvalidDataException("Loader does not have a proven direct resource-to-assembly buffer.");
        var flow = EvaluationStackOrigins.Analyze(loader);
        if (!flow.Valid) throw new InvalidDataException("Loader stack provenance is incomplete.");
        foreach (var pair in flow.Inputs.Where(pair => pair.Key.Operand is IMethod call &&
            call.FullName == "System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[],System.Byte[])" &&
            pair.Value.Length == 2 && pair.Value[0].Any(i => i is not null && i.IsLdloc() && i.GetLocal(loader.Body.Variables) == buffer)))
            if (pair.Value[1].Count == 0 || pair.Value[1].Any(i => i is null ||
                i.OpCode.Code != Code.Ldnull && (!i.IsLdloc() || i.GetLocal(loader.Body.Variables) is not { } symbols || !OptionalResourceSymbols.IsNull(loader,symbols))))
                throw new InvalidDataException("Original debug symbols cannot be reused with rewritten child methods.");
        var original = loader.Module.Resources.OfType<EmbeddedResource>().Single(r => r.Name == name);
        using var before = ModuleDefMD.Load(original.CreateReader().ToArray());
        using var after = ModuleDefMD.Load(recovered);
        if (before.GetAssemblyRefs().Concat(after.GetAssemblyRefs()).Any(r => r.Name == "PresentationFramework"))
            throw new InvalidDataException("WPF bootstrap metadata adaptation requires a separate preservation proof.");
        return Prepare(original, expectedInputSha256, recovered);
    }
    internal static EmbeddedResource Prepare(EmbeddedResource original, string expectedInputSha256, byte[] recovered)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(recovered);
        var reader = original.CreateReader();
        if (reader.Length > MaximumAssemblyBytes || recovered.Length > MaximumAssemblyBytes)
            throw new InvalidDataException("Embedded assembly replacement exceeds the byte limit.");
        var input = reader.ToArray();
        if (!string.Equals(Convert.ToHexStringLower(SHA256.HashData(input)), expectedInputSha256,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Resource bytes do not match the recovered child input.");
        using var before = ModuleDefMD.Load(input);
        using var after = ModuleDefMD.Load(recovered);
        if (before.Assembly is null || after.Assembly is null ||
            !string.Equals(before.Assembly.FullName, after.Assembly.FullName, StringComparison.Ordinal) ||
            !before.Assembly.PublicKey.Data.SequenceEqual(after.Assembly.PublicKey.Data) ||
            before.Kind != after.Kind || before.Machine != after.Machine ||
            !before.IsILOnly || !after.IsILOnly || before.NativeEntryPoint != 0 || after.NativeEntryPoint != 0)
            throw new InvalidDataException("Recovered child changes assembly identity or managed loading requirements.");
        if (before.EntryPoint is not { IsStatic: true } entry || after.EntryPoint is not { IsStatic: true } replacement ||
            !string.Equals(entry.MethodSig.ToString(), replacement.MethodSig.ToString(), StringComparison.Ordinal))
            throw new InvalidDataException("Recovered child changes or lacks the managed entry-point contract.");
        // Own the buffer: subsequent caller mutation must not silently change the prepared resource.
        return new EmbeddedResource(original.Name, recovered.ToArray(), original.Attributes);
    }
}
