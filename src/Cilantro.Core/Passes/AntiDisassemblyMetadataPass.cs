using dnlib.DotNet;

namespace Cilantro.Core.Passes;

/// <summary>Removes the framework's disassembly-suppression marker from analyst output.</summary>
public sealed class AntiDisassemblyMetadataPass : DeobfuscationPass
{
    public override string Name => "anti-disassembly-metadata";
    public override IReadOnlyCollection<string> Dependencies => ["symbol-renaming"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Protector metadata cleanup is disabled."]);
        var removed = 0;
        foreach (var owner in new IHasCustomAttribute?[] { context.Module.Assembly, context.Module }.OfType<IHasCustomAttribute>())
        {
            foreach (var attribute in owner.CustomAttributes.Where(a =>
                a.AttributeType is TypeRef type &&
                type.FullName == "System.Runtime.CompilerServices.SuppressIldasmAttribute" &&
                type.DefinitionAssembly?.FullName == context.Module.CorLibTypes.AssemblyRef.FullName &&
                a.Constructor?.Name == ".ctor" && a.Constructor.MethodSig is { HasThis: true, Params.Count: 0 } signature &&
                signature.RetType.ElementType == ElementType.Void).ToArray())
            {
                owner.CustomAttributes.Remove(attribute);
                removed++;
                context.AddChange(new(Name, "remove-disassembly-suppression", owner.MDToken.ToString(),
                    "Removed the framework SuppressIldasmAttribute under the protector-metadata cleanup contract; application CIL and unrelated attributes are unchanged."));
            }
        }
        return (PassStatus.Success, removed, [$"Removed {removed} framework disassembly-suppression attribute(s)."]);
    }
}
