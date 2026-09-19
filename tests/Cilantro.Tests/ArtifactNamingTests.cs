using System.Security.Cryptography;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ArtifactNamingTests
{
    [Theory]
    [InlineData("SameName", "SameName")]
    [InlineData("A?B", "A*B")]
    [InlineData("Name", "name")]
    public void PayloadPathsRetainBothContentsWhenReadableNamesCollide(string first, string second)
    {
        using var context = SyntheticContext.Build(_ => { });
        var directory = Directory.CreateTempSubdirectory("cilantro-artifacts");
        try
        {
            var payloads = new[] { Payload(first, [1, 2, 3]), Payload(second, [4, 5, 6]) };
            context.SetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", payloads);

            var paths = CilantroPipeline.WritePayloads(context, directory.FullName, "sample");

            Assert.Equal(2, paths.Distinct(StringComparer.OrdinalIgnoreCase).Count());
            for (var i = 0; i < payloads.Length; i++)
            {
                Assert.Equal(payloads[i].Bytes, File.ReadAllBytes(paths[i]));
                Assert.Contains(payloads[i].Info.PayloadSha256, Path.GetFileName(paths[i]), StringComparison.Ordinal);
            }
            Assert.Equal(paths, CilantroPipeline.WritePayloads(context, directory.FullName, "sample"));
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    public void ListingsKeepOverloadsAndRepeatedProgramNamesSeparate()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Host");
            foreach (var sig in new[] { MethodSig.CreateStatic(module.CorLibTypes.Void), MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32) })
            {
                var method = new MethodDefUser("Duplicate", sig, MethodAttributes.Public | MethodAttributes.Static)
                { Body = new CilBody() };
                method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                type.Methods.Add(method);
            }
        });
        var directory = Directory.CreateTempSubdirectory("cilantro-listings");
        try
        {
            var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
            var programs = methods.Select((m, index) => new VirtualProgram(new VirtualizedMethod(m, m, index, 0), "test", [])).ToArray();
            context.SetFact<IReadOnlyList<VirtualProgram>>("virtualization.programs", [programs[0], programs[1], programs[0]]);

            var paths = CilantroPipeline.WriteVirtualPrograms(context, directory.FullName, "sample");

            Assert.Equal(6, paths.Count);
            Assert.Equal(6, paths.Distinct(StringComparer.OrdinalIgnoreCase).Count());
            Assert.Contains(methods[0].FullName, File.ReadAllText(paths[0]), StringComparison.Ordinal);
            Assert.Contains(methods[1].FullName, File.ReadAllText(paths[2]), StringComparison.Ordinal);
            Assert.Equal(paths, CilantroPipeline.WriteVirtualPrograms(context, directory.FullName, "sample"));
        }
        finally { directory.Delete(recursive: true); }
    }

    private static ExtractedPayload Payload(string name, byte[] bytes) => new(
        new PayloadInfo("test", "", bytes.Length, "", bytes.Length,
            Convert.ToHexStringLower(SHA256.HashData(bytes)), name, name, 0, []), bytes);
}
