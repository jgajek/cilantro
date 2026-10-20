using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

/// <summary>Attribution from an applied Dotfuscator watermark, not a type name alone.</summary>
public sealed record DotfuscatorStructureFacts(bool HasMarker, string Version, bool HasNativeStringRuntime = false)
{
    public bool IsDotfuscator => HasMarker;
    public double Confidence => HasMarker ? 0.95 : 0;
    // A watermark identifies the producer. It does not prove which transforms were enabled.
    public IReadOnlyList<string> CapabilityNames { get; } = [];
}

public static class DotfuscatorStructureDetector
{
    public static DotfuscatorStructureFacts Analyze(ModuleDefMD module)
    {
        ArgumentNullException.ThrowIfNull(module);
        foreach (var attribute in module.CustomAttributes.Concat(module.Assembly?.CustomAttributes ?? []))
        {
            if (attribute.TypeFullName != "DotfuscatorAttribute" ||
                attribute.Constructor?.DeclaringType.ResolveTypeDef() is not { } type ||
                type.Module != module || type.BaseType?.FullName != "System.Attribute" ||
                attribute.ConstructorArguments.Count is not (1 or 3) ||
                attribute.ConstructorArguments[0].Type.ElementType != ElementType.String)
                continue;
            if (attribute.ConstructorArguments.Count == 3 &&
                (attribute.ConstructorArguments[1].Type.ElementType != ElementType.I4 ||
                 attribute.ConstructorArguments[2].Type.ElementType != ElementType.Boolean)) continue;
            var version = attribute.ConstructorArguments[0].Value?.ToString();
            var nativeStrings = module.GetTypes().SelectMany(t => t.Methods).Any(method =>
                method.IsPinvokeImpl && method.ImplMap?.Name == "__eck" &&
                method.ImplMap.Module.Name.String is "Runtime.Extensions.dll" or "Runtime.Extensions");
            return new(true, string.IsNullOrWhiteSpace(version) ? "unknown" : version, nativeStrings);
        }
        return new(false, "unknown");
    }
}

public sealed class DotfuscatorDetectionPass : DeobfuscationPass
{
    public override string Name => "dotfuscator-detection";
    public override IReadOnlyCollection<string> Dependencies => ["metadata-preflight"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var facts = DotfuscatorStructureDetector.Analyze(context.Module);
        context.SetFact("dotfuscator.structure", facts);
        if (facts.IsDotfuscator)
            context.AddEvidence(new("protector", "Applied DotfuscatorAttribute watermark.", Confidence: facts.Confidence));
        return (PassStatus.Success, 0, [facts.IsDotfuscator
            ? $"Dotfuscator watermark detected ({facts.Version}); enabled protections require separate analysis."
            : "No applied Dotfuscator watermark detected."]);
    }
}
