using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Retires public leaves owned by an independently reviewed complete Root Check family.</summary>
internal sealed record RetiredDotfuscatorRootRuntime(IReadOnlyList<TypeDef> Types, IReadOnlyList<string> Fingerprints)
{
    private const string Fact = "dotfuscator.root.retiredPublicLeaves";
    private const string HelpersFact = "dotfuscator.root.retiredDetachedHelpers";

    // Called only after every original checker family has passed complete review.
    internal static void Remember(ArtifactContext context, DotfuscatorCheckShape.Runtime runtime)
    {
        var leaves = runtime.Types.Where(type => type.IsPublic).ToArray();
        if (leaves.Length == 0) return;
        using var source = ModuleDefMD.Load(context.OriginalBytes);
        var originals = leaves.Select(type => source.ResolveToken(type.MDToken)).OfType<TypeDef>().ToArray();
        if (originals.Length != leaves.Length || !Describe(originals, out var fingerprints)) return;
        var current = leaves.Select(type => context.Module.ResolveToken(type.MDToken)).OfType<TypeDef>().ToArray();
        if (current.Length != leaves.Length) return;
        context.TryGetFact<IReadOnlyList<RetiredDotfuscatorRootRuntime>>(Fact, out var previous);
        context.SetFact<IReadOnlyList<RetiredDotfuscatorRootRuntime>>(Fact, [.. previous ?? [], new(current, fingerprints)]);
        var helpers = new List<RetiredDotfuscatorRootRuntime>();
        foreach (var type in source.GetTypes().Where(HelperCandidate))
        {
            if (!Describe([type], out var hashes) || hashes.Length != 1 || !ReviewedHelper(type, hashes[0]) ||
                context.Module.ResolveToken(type.MDToken) is not TypeDef helper) continue;
            helpers.Add(new([helper], hashes));
        }
        context.SetFact<IReadOnlyList<RetiredDotfuscatorRootRuntime>>(HelpersFact, helpers);
    }

    internal static IEnumerable<TypeDef> Unused(ArtifactContext context) => Unused(context, Fact);

    internal static IEnumerable<TypeDef> UnusedHelpers(ArtifactContext context) => Unused(context, HelpersFact);

    private static List<TypeDef> Unused(ArtifactContext context, string fact)
    {
        if (!context.TryGetFact<IReadOnlyList<RetiredDotfuscatorRootRuntime>>(fact, out var proofs) || proofs is null || proofs.Count == 0) return [];
        var result = new List<TypeDef>();
        // Earlier passes can expand unrelated application bodies. Reach long
        // branches for serialization, then restore their exact original forms.
        var forms = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions).Where(instruction => instruction.OpCode.OperandType == OperandType.ShortInlineBrTarget)
            .Select(instruction => (Instruction: instruction, instruction.OpCode)).ToArray();
        try
        {
            BranchForms.Reach(context.Module);
            using var bytes = new MemoryStream(); context.Module.Write(bytes);
            using var copy = ModuleDefMD.Load(bytes.ToArray());
            foreach (var proof in proofs)
            {
                if (proof.Types.Any(type => !context.Module.GetTypes().Contains(type))) continue;
                var types = proof.Types.Select(type => copy.GetTypes().SingleOrDefault(candidate => candidate.FullName == type.FullName)).ToArray();
                if (types.Any(type => type is null) || !Describe(types.OfType<TypeDef>().ToArray(), out var fingerprints) ||
                    !fingerprints.SequenceEqual(proof.Fingerprints))
                {
                    context.AddEvidence(new("dotfuscator-root-runtime-retained", "Root Check helper declarations or normalized bodies changed; retirement withheld."));
                    continue;
                }
                var family = proof.Types.ToHashSet();
                if (context.Module.GetTypes().Where(type => !family.Contains(type)).SelectMany(type => type.Methods)
                    .Where(method => method.HasBody).SelectMany(method => method.Body.Instructions)
                    .Any(instruction => instruction.Operand is string text && family.Any(type => text == type.FullName ||
                        text == type.ReflectionFullName || text.StartsWith(type.ReflectionFullName + ",", StringComparison.Ordinal)))) continue;
                result.AddRange(proof.Types);
            }
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or InvalidOperationException or dnlib.DotNet.Writer.ModuleWriterException)
        { return []; }
        finally { foreach (var form in forms) form.Instruction.OpCode = form.OpCode; }
        return result;
    }

    private static bool HelperCandidate(TypeDef type) => type.FullName == "PreEmptive.Protection.Checks.Android.Runtime.Root.PlatformClass1" ||
        type.CustomAttributes.Any(attribute => attribute.TypeFullName == "System.CodeDom.Compiler.GeneratedCodeAttribute") &&
        type.Methods.Any(method => method.MethodSig.Params.FirstOrDefault()?.FullName == "Microsoft.Maui.Controls.BindingMode");

    // The installed 7.9 Root Check template contains these otherwise disconnected
    // declarations. Complete capture graphs include the target framework scopes
    // and every GeneratedCode argument. The binding helper also has a reviewed
    // renamed form. An ordinary empty class has no distinctive body, so its exact
    // vendor type name is required; renamed empty classes remain unattributed.
    private static bool ReviewedHelper(TypeDef type, string fingerprint) =>
        type.FullName == "PreEmptive.Protection.Checks.Android.Runtime.Root.PlatformClass1" &&
            fingerprint == "0a29a5ee91c1315e0ab4e51035f4fe94b9aa6d355f7a601561672b08b3c1d5a9" ||
        fingerprint is "042f94e5279d9ee24f22aa2cf8c0c8c74de9416167368f51e90ac6ea8aa32b3f" or
            "0fb2b48181c457277441e67fbd79e259aa6323cd5ecf8cf62a67b5c0329e707a";

    // All normalization takes place in private metadata copies. A public leaf
    // may reference another proved public leaf, but no other local declaration.
    private static bool Describe(TypeDef[] types, out string[] fingerprints)
    {
        fingerprints = [];
        if (types.Length > 8 || types.Any(type => type.Methods.Count == 0 || type.HasGenericParameters)) return false;
        var runtime = new DotfuscatorCheckShape.Runtime(types[0].Methods[0], "root", 0, types, "");
        if (!DotfuscatorRootCheckShape.TryNormalize(runtime, out _)) return false;
        var hashes = new List<string>();
        foreach (var type in types)
        {
            var graph = DotfuscatorRootCheckShape.Read(type.Methods[0], true);
            if (graph.Fingerprint.Length != 64 || graph.Types.Any(candidate => !types.Contains(candidate))) return false;
            hashes.Add(graph.Fingerprint);
        }
        fingerprints = hashes.ToArray();
        return true;
    }
}
