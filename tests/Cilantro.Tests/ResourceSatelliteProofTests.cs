using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace Cilantro.Tests;
public sealed class ResourceSatelliteProofTests
{
    [Theory]
    [InlineData("resources", true)]
    [InlineData("code", false)]
    [InlineData("type", false)]
    [InlineData("changed", false)]
    [InlineData("extra", false)]
    [InlineData("duplicate", false)]
    [InlineData("empty", false)]
    public void RequiresOnlyExactPreservedResourceStreams(string scenario, bool expected)
    {
        using var module = new ModuleDefUser("Satellite.dll") { Kind = ModuleKind.Dll };
        var data = new EmbeddedResource("application", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Public);
        var entries = new[] { RecoveredResourceOrigin.Capture(data) };
        if(scenario != "empty") module.Resources.Add(data);
        if(scenario == "changed") module.Resources[0] = new EmbeddedResource("application", new byte[] { 7 }, ManifestResourceAttributes.Public);
        if(scenario is "extra" or "duplicate") module.Resources.Add(new EmbeddedResource(scenario == "extra" ? "other" : "application", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Public));
        if(scenario == "type") module.Types.Add(new TypeDefUser("Extra", module.CorLibTypes.Object.TypeDefOrRef));
        if(scenario == "code")
        {
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes=MethodAttributes.Static, Body=new CilBody() };
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); module.GlobalType.Methods.Add(method);
        }
        using var bytes = new MemoryStream(); module.Write(bytes);
        var bundle = new RestoredResourceBundle(new("source", "hash"), scenario == "empty" ? [] : entries);
        Assert.Equal(expected, ResourceEnumerationCompletionPass.IsPreservedResourceSatellite(bytes.ToArray(), bundle));
    }
}
