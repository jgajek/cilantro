using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Fingerprints the complete generated checker family, including native imports and layouts.</summary>
internal static class DotfuscatorCheckShape
{
    internal sealed record Runtime(MethodDef Method, string Kind, uint CleanVerdict, IReadOnlyList<TypeDef> Types, string Fingerprint);

    internal static bool Supported(Runtime runtime) => runtime.Kind == "root"
        ? DotfuscatorRootCheckShape.Supported(runtime.Fingerprint) : runtime.Fingerprint is
        "fa42e2263fb4f769888af8a54355c25ee3f11a97920d277b0403501eb3cb5ec9" or
        "8db26e052a58a9d26b82a35cc9d2088ca2149a1bca3b4b4ca2c18e1d4f7d2e18" or
        "b768d6a69bf93259feab5c7db24a20e70f715671932da8c2b1350a86da94057a" or
        "800c5fc30da9f62710541df095960efcde1525ad50d23ee50c3d7fe08b6bdd24" or
        "c5da3079fc8bf0cd61369139ac9d78d609cc416931af24ccb19b3f244b13b4f1" or
        "e3e61ee46a3c22c3d223e754e15c83fe87cc30a05d8475e08ccabd4edcb5f41a" or
        "28678398ea8dfc2b1c62e3d44d9180b3c23b9fd254724133dc6abd103256712a" or
        "7f01e37df728d36e440b73a24a745bccc0951a1cafc566cefea70a466017f922" or
        "6088cb1ed8b9c4738c9fd46412391fbef1a51ce4edaea7dc674475e26ce08490";

    internal static IEnumerable<Runtime> Find(ModuleDef module)
    {
        foreach (var root in module.GetTypes().SelectMany(type => type.Methods).Where(method => method.IsStatic && method.HasBody &&
                     method.ReturnType.ElementType == ElementType.U4))
        {
            var parameters = root.MethodSig.Params;
            var calls = root.Body.Instructions.Select(instruction => instruction.Operand).OfType<IMethod>().ToArray();
            var generatedOwner = root.DeclaringType.Namespace == "PreEmptive.SoS.Runtime";
            var debugging = parameters.Count == 0 && (generatedOwner && root.Name == "WithAttachment" || calls.Any(called =>
                called.DeclaringType?.FullName == "System.Diagnostics.Debugger" && called.Name == "get_IsAttached"));
            var tamper = parameters.Count == 4 && parameters.Skip(1).All(type => type.ElementType == ElementType.String) &&
                parameters[0].FullName is "System.IntPtr" or "System.Reflection.Assembly" &&
                (generatedOwner && root.Name.String is "Verify" or "VerifyFromFile" || calls.Any(called =>
                    called.DeclaringType?.FullName == "System.Security.Cryptography.HashAlgorithm" && called.Name == "ComputeHash"));
            var file = tamper && parameters[0].FullName == "System.Reflection.Assembly";
            var android = parameters.Count == 0 && (generatedOwner && root.Name == "XRFind" ||
                calls.Any(called => called.DeclaringType?.FullName == "Android.OS.Build" && called.Name == "get_Tags") &&
                calls.Any(called => called.DeclaringType?.FullName == "Android.App.Application" && called.Name == "get_Context"));
            if (!debugging && !tamper && !android) continue;
            var graph = android ? DotfuscatorRootCheckShape.Read(root) : GeneratedRuntimeShape.Read(root);
            yield return new(root, android ? "root" : debugging ? "debugging" : file ? "tamper-file" : "tamper-memory",
                android ? 2105837932U : debugging ? 1483055301U : file ? 1172693094U : 3341219236U, graph.Types, graph.Fingerprint);
        }
    }
}
