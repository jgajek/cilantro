using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

public sealed class CosturaExtractionPassTests
{
    [Fact]
    public void ExtractsUncompressedCosturaAssembly()
    {
        var embedded = BuildManagedAssemblyBytes("Embedded");
        using var context = SyntheticContext.Build(module =>
        {
            SyntheticContext.AddType(module, "Host");
            module.Resources.Add(new EmbeddedResource(
                "costura.embedded.dll", embedded, ManifestResourceAttributes.Private));
        });

        var result = new CosturaExtractionPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.True(context.TryGetFact<IReadOnlyList<ExtractedPayload>>(
            "payload.artifacts", out var payloads));
        Assert.NotNull(payloads);
        Assert.Contains(payloads!, payload => payload.Info.AssemblyName == "Embedded");
    }

    [Fact]
    public void ReportsNoCosturaWhenAbsent()
    {
        using var context = SyntheticContext.Build(module =>
            SyntheticContext.AddType(module, "Host"));

        var result = new CosturaExtractionPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
    }

    private static byte[] BuildManagedAssemblyBytes(string name)
    {
        var module = new ModuleDefUser($"{name}.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser(name, new Version(1, 0));
        assembly.Modules.Add(module);
        using var stream = new MemoryStream();
        module.Write(stream);
        return stream.ToArray();
    }
}
