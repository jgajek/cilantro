using System.Buffers.Binary;
using System.Resources;
using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class ResourceEntryExtractionTests
{
    [Fact]
    public void ExtractsByteArraysAndStreamsButNeverDeserializesCustomObjects()
    {
        using var module = new ModuleDefUser("payload.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser("Payload", new Version(1, 0)).Modules.Add(module);
        using var imageStream = new MemoryStream();
        module.Write(imageStream);
        var managed = imageStream.ToArray();
        var native = (byte[])managed.Clone();
        var pe = BinaryPrimitives.ReadInt32LittleEndian(native.AsSpan(0x3c));
        native.AsSpan(pe + 24 + 96 + 14 * 8, 8).Clear();
        using var resourceStream = new MemoryStream();
        using (var writer = new ResourceWriter(resourceStream))
        {
            writer.AddResource("managed", managed);
            writer.AddResource("native", new MemoryStream(native));
            writer.AddResource("text", "MZ is not a payload");
            writer.AddResource("invalid", new byte[] { 77, 90, 1, 2 });
            // Any attempt to deserialize this entry would try to resolve a missing type.
            writer.AddResourceData("object", "Missing.Type, Missing.Assembly", managed);
            writer.Generate();
        }
        var resources = resourceStream.ToArray();
        using var context = SyntheticContext.Build(host => host.Resources.Add(
            new EmbeddedResource("Host.resources", resources, ManifestResourceAttributes.Private)));
        var existing = new ExtractedPayload(new("old", "", 0, "", 0, "", "old", "old", 0, []), []);
        context.SetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", [existing]);
        var result = new ResourceEntryExtractionPass().Run(context);
        Assert.Equal(PassStatus.Partial, result.Status); // Invalid PE remains explicit.
        Assert.Equal(2, result.Changes);
        Assert.True(context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var payloads));
        Assert.Equal(3, payloads!.Count);
        Assert.Same(existing, payloads[0]);
        Assert.Equal(managed, Assert.Single(payloads, p => p.Info.SourceResource == "Host.resources/managed").Bytes);
        var nativePayload = Assert.Single(payloads, p => p.Info.SourceResource == "Host.resources/native");
        Assert.Equal(native, nativePayload.Bytes);
        Assert.Equal(PayloadOrigin.NativeDependency, nativePayload.Info.Origin);
        Assert.Equal(resources, context.Module.Resources.OfType<EmbeddedResource>().Single().CreateReader().ToArray());
    }

    [Fact]
    public void MalformedContainerIsReportedWithoutThrowing()
    {
        using var context = SyntheticContext.Build(host => host.Resources.Add(
            new EmbeddedResource("Bad.resources", [1, 2, 3], ManifestResourceAttributes.Private)));
        var result = new ResourceEntryExtractionPass().Run(context);
        Assert.Equal(PassStatus.Partial, result.Status);
        Assert.Equal(0, result.Changes);
    }
    [Fact]
    public void ExtractsGzipImagesWithoutChangingResourcesAndContinuesPastBadEntries()
    {
        using var module = new ModuleDefUser("compressed.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser("Compressed", new Version(1, 0)).Modules.Add(module);
        using var imageStream = new MemoryStream(); module.Write(imageStream); var image = imageStream.ToArray();
        using var resourceStream = new MemoryStream();
        using (var writer = new ResourceWriter(resourceStream))
        {
            writer.AddResource("bad-gzip", new byte[] { 0x1f, 0x8b, 8, 0 });
            writer.AddResource("compressed-assembly", Gzip(image));
            writer.AddResource("ordinary-compressed-data", Gzip([1, 2, 3, 4]));
            writer.AddResourceData("custom-object", "Missing.Type, Missing.Assembly", Gzip(image));
            writer.Generate();
        }
        var resource = resourceStream.ToArray();
        using var context = SyntheticContext.Build(host => host.Resources.Add(new EmbeddedResource("Compressed.resources", resource, ManifestResourceAttributes.Private)));
        var result = new ResourceEntryExtractionPass().Run(context);
        Assert.Equal(PassStatus.Partial, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.True(context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var payloads));
        Assert.Equal(image, Assert.Single(payloads!).Bytes);
        Assert.Equal("Compressed.resources/compressed-assembly", payloads![0].Info.SourceResource);
        Assert.Equal(resource, context.Module.Resources.OfType<EmbeddedResource>().Single().CreateReader().ToArray());
    }

    [Fact]
    public void CompressedEntriesShareTheInflatedByteBudget()
    {
        var compressed = Gzip(new byte[48]); var decoded = 0;
        Assert.Equal(48, ResourceEntryExtractionPass.InflateGzip(compressed, ref decoded, 64).Length);
        Assert.Throws<InvalidDataException>(() => ResourceEntryExtractionPass.InflateGzip(compressed, ref decoded, 64));
        Assert.Equal(64, decoded);
    }

    private static byte[] Gzip(byte[] bytes)
    {
        using var output = new MemoryStream();
        using (var gzip = new System.IO.Compression.GZipStream(output, System.IO.Compression.CompressionLevel.SmallestSize, leaveOpen: true)) gzip.Write(bytes);
        return output.ToArray();
    }
}
