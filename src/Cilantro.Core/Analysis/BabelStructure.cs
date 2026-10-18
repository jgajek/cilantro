using dnlib.DotNet;
using Cilantro.Core.Codec;

namespace Cilantro.Core.Analysis;

public sealed record BabelStructureFacts(bool HasMarker, bool HasMetadataStream,
    int EncryptedResources, bool HasStreamDecoder, double Confidence,
    int EmittedStringRuntimes = 0, bool HasNumericTableRuntime = false)
{
    public bool IsBabel => Confidence >= 0.75;
    public IReadOnlyList<string> CapabilityNames => !IsBabel ? [] :
        ["interpreted-string-decoders", .. EmittedStringRuntimes > 0 ? new[] { "emitted-string-runtime" } : Array.Empty<string>(),
            .. HasNumericTableRuntime ? new[] { "numeric-table-runtime" } : Array.Empty<string>(), .. EncryptedResources > 0
            ? new[] { "encrypted-resource-envelopes", "embedded-assembly-bundles" } : Array.Empty<string>()];
}

public static class BabelStructureDetector
{
    private static readonly string[] NumericResults = ["System.Int32", "System.Int64", "System.Single", "System.Double"];

    public static BabelStructureFacts Analyze(ModuleDefMD module)
    {
        ArgumentNullException.ThrowIfNull(module);
        var types = module.GetTypes().ToArray();
        // An unused class whose name happens to mention Babel is insufficient.
        var marker = types.Any(type => type.FullName is "BabelAttribute" or "BabelObfuscatorAttribute" &&
            type.BaseType?.FullName == "System.Attribute") &&
            (module.CustomAttributes.Concat(module.Assembly?.CustomAttributes ?? [])
                .Any(attribute => attribute.TypeFullName is "BabelAttribute" or "BabelObfuscatorAttribute"));
        var stream = module.Metadata.AllStreams.Any(item => item.Name == "Babel");
        var candidates = module.Resources.OfType<EmbeddedResource>().Where(resource =>
            resource.Length <= BabelResourceCodec.MaximumLength && BabelResourceCodec.IsCandidate(resource.CreateReader().ToArray())).ToArray();
        var decoders = StreamDecoders(module);
        var decoder = decoders.Length != 0;
        var emitted = types.Count(type =>
            type.Methods.Any(method => Getter(method, "System.String") &&
                Calls(method, "System.AppDomain", "GetData") && Calls(method, "System.Collections.Hashtable", "get_Item")) &&
            type.NestedTypes.Any(nested => nested.Methods.Any(method => method.HasBody &&
                method.MethodSig?.RetType.FullName == "System.Reflection.Emit.MethodBuilder" &&
                method.MethodSig.Params.Count == 1 && method.MethodSig.Params[0].FullName == "System.Reflection.Emit.TypeBuilder" &&
                Calls(method, "System.Reflection.Emit.TypeBuilder", "DefineMethod") &&
                Calls(method, "System.Reflection.Emit.ILGenerator", "Emit"))) &&
            type.FindStaticConstructor() is { } initializer &&
            Calls(initializer, "System.Reflection.Assembly", "GetManifestResourceStream") &&
            Called(initializer).Any(called => called.ResolveMethodDef() is { } resolved && decoders.Contains(resolved)));
        var numeric = types.Any(type => NumericResults
            .All(result => type.Methods.Any(method => Getter(method, result))));
        // A plausible length prefix is not an envelope signature. Without a marker,
        // require a successful decode as well as the runtime arrangement.
        var publicKey = module.Assembly?.PublicKey?.Data ?? [];
        var runtimeEnvelope = !marker && !stream && decoder && candidates.Any(resource =>
            BabelResourceCodec.TryDecode(resource.CreateReader().ToArray(), publicKey, out _, out _));
        var confidence = marker || stream ? 0.99 : emitted > 0 && numeric ? 0.97 : runtimeEnvelope ? 0.8 : 0;
        return new(marker, stream, candidates.Length, decoder, confidence, emitted, numeric);
    }

    private static bool Getter(MethodDef method, string result) => method.IsStatic && method.HasBody &&
        method.MethodSig?.RetType.FullName == result && method.MethodSig.Params.Count == 1 &&
        method.MethodSig.Params[0].FullName == "System.Int32";

    internal static MethodDef[] StreamDecoders(ModuleDef module) => module.GetTypes().SelectMany(type => type.Methods)
        .Where(method => method.IsStatic && method.HasBody && method.MethodSig?.Params.Count == 1 &&
            (method.MethodSig.RetType.FullName is "System.IO.Stream" or "System.IO.MemoryStream" && method.MethodSig.Params[0].FullName == "System.IO.Stream" ||
             (method.MethodSig.RetType.ElementType == ElementType.Object || method.MethodSig.RetType.FullName is "System.IO.Stream" or "System.IO.MemoryStream") &&
             method.MethodSig.Params[0].ElementType == ElementType.Object &&
             Calls(method, "System.IO.BinaryReader", "ReadUInt16") && Calls(method, "System.Security.Cryptography.SymmetricAlgorithm", "CreateDecryptor")))
        .ToArray();

    private static bool Calls(MethodDef method, string owner, string name) => Called(method)
        .Any(called => called.DeclaringType?.FullName == owner && called.Name == name);

    // Follow only small local adapters introduced by the outer protector.
    private static IEnumerable<IMethod> Called(MethodDef root)
    {
        var pending = new Stack<MethodDef>();
        var visited = new HashSet<MethodDef>();
        pending.Push(root);
        while (pending.TryPop(out var method) && visited.Count < 32)
        {
            if (!visited.Add(method) || !method.HasBody) continue;
            foreach (var instruction in method.Body.Instructions)
                if (instruction.OpCode.Code is dnlib.DotNet.Emit.Code.Call or dnlib.DotNet.Emit.Code.Callvirt && instruction.Operand is IMethod called)
                {
                    yield return called;
                    if (called.ResolveMethodDef() is { HasBody: true } wrapper && wrapper.Module == root.Module &&
                        wrapper.Body.Instructions.Count <= 16) pending.Push(wrapper);
                }
        }
    }
}

public sealed class BabelDetectionPass : DeobfuscationPass
{
    public override string Name => "babel-detection";
    public override IReadOnlyCollection<string> Dependencies => ["metadata-preflight"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var facts = BabelStructureDetector.Analyze(context.Module);
        context.SetFact("babel.structure", facts);
        if (facts.IsBabel)
        {
            context.AddEvidence(new("protector", "Babel .NET marker, generated string/constant runtime or legacy resource structure.", Confidence: facts.Confidence));
            foreach (var capability in facts.CapabilityNames)
                context.AddEvidence(new("capability", capability, Confidence: facts.Confidence));
        }
        return (PassStatus.Success, 0, [facts.IsBabel
            ? $"Babel .NET detected; {facts.EncryptedResources} candidate resource envelope(s)."
            : "No Babel .NET structure detected."]);
    }
}
