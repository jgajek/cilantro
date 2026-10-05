using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Recovery;
using Cilantro.Core.Analysis;
using System.Buffers.Binary;
using System.IO.Compression;

namespace Cilantro.Tests;

public sealed class CosturaExtractionPassTests
{
    [Theory]
    [InlineData("costura32.native.dll", false)]
    [InlineData("costura64.native.dll.compressed", true)]
    public void ExtractsNativeBytesAndPreservesValidSiblingsAfterABadResource(string name, bool compressed)
    {
        var native = BuildManagedAssemblyBytes("NativeFixture");
        // A synthetic PE with no CLR directory, sufficient to test native classification.
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(native.AsSpan(0x3c));
        native.AsSpan(peOffset + 24 + 96 + 14 * 8, 8).Clear();
        byte[] encoded = native;
        if (compressed)
        {
            using var stream = new MemoryStream();
            using (var deflate = new DeflateStream(stream, CompressionMode.Compress, leaveOpen: true))
                deflate.Write(native);
            encoded = stream.ToArray();
        }
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("costura.bad.dll", [1, 2, 3], ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource(name, encoded, ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("costura.valid.dll", BuildManagedAssemblyBytes("Valid"), ManifestResourceAttributes.Private));
        });
        var result = new CosturaExtractionPass().Run(context);
        Assert.Equal(PassStatus.Partial, result.Status);
        Assert.Equal(2, result.Changes);
        Assert.True(context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var payloads));
        var payload = Assert.Single(payloads!, item => item.Info.Origin == PayloadOrigin.NativeDependency);
        Assert.Equal(native, payload.Bytes);
        Assert.Contains(payloads!, item => item.Info.AssemblyName == "Valid");
        var roles = ResourceRoleAnalyzer.Analyze(context.Module, ReactorStructureDetector.Analyze(context.Module));
        Assert.Equal(ResourceRole.NativePayload, Assert.Single(roles, role => role.Resource == name).Role);
        Assert.Equal(ResourceRole.ManagedPayload, Assert.Single(roles, role => role.Resource == "costura.valid.dll").Role);
    }

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
