using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelResourceRecoveryTests
{
    [Fact]
    public void PipelineWritesDecodedDataWithSafeNamesAndMatchingHashes()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelResources.").FullName;
        try
        {
            using var context = Fixture(false);
            var input = Path.Combine(directory, "input.dll");
            context.Module.Write(input);
            var result = new CilantroPipeline().Run(input, new PipelineOptions(
                ReportDirectory: Path.Combine(directory, "report"), OutputPath: Path.Combine(directory, "cleaned.dll")));
            Assert.True(result.Report.VerificationPassed);
            var decoded = Assert.Single(result.Report.DecodedResources!);
            Assert.Equal("../source", decoded.SourceResource);
            Assert.NotNull(decoded.WrittenTo);
            Assert.StartsWith(Path.Combine(directory, "report", "input.babel-resources"), decoded.WrittenTo, StringComparison.Ordinal);
            var bytes = File.ReadAllBytes(decoded.WrittenTo);
            Assert.Equal(new byte[] { 23, 24, 25 }, bytes);
            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), decoded.DecodedSha256);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InterpretedDecoderReturnsOnlyTheLogicalStreamRange(bool memoryReturn)
    {
        using var context = Fixture(memoryReturn);
        Protect(context);
        var result = new BabelResourceRecoveryPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.True(context.TryGetFact<IReadOnlyList<BabelDecodedResource>>(BabelResourceRecoveryPass.ResourcesFact, out var decoded));
        Assert.Equal(new byte[] { 23, 24, 25 }, Assert.Single(decoded!).Bytes);
        Assert.Equal(3, decoded![0].Info.DecodedLength);
        Assert.Equal(0, new BabelResourceCompletionPass().Run(context).Changes);
        Assert.Single(context.Module.Resources);
    }

    [Fact]
    public void UnchangedInputIsNotReportedAsDecoded()
    {
        using var context = Fixture(false, unchanged: true);
        Protect(context);
        var result = new BabelResourceRecoveryPass().Run(context);
        Assert.Equal(PassStatus.Partial, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.True(context.TryGetFact<IReadOnlyList<BabelDecodedResource>>(BabelResourceRecoveryPass.ResourcesFact, out var decoded));
        Assert.Empty(decoded!);
    }

    [Fact]
    public void AnUnreadInputSuffixPreventsAcceptingTheDecode()
    {
        using var context = Fixture(false, consume: false);
        Protect(context);
        Assert.Equal(PassStatus.Partial, new BabelResourceRecoveryPass().Run(context).Status);
    }

    private static void Protect(ArtifactContext context) =>
        context.SetFact("babel.structure", new BabelStructureFacts(true, false, 0, true, 0.99));

    private static ArtifactContext Fixture(bool memoryReturn, bool unchanged = false, bool consume = true) => SyntheticContext.Build(module =>
    {
        BabelTests.Marker(module);
        var host = SyntheticContext.AddType(module, "Codec");
        var stream = new TypeRefUser(module, "System.IO", "Stream", module.CorLibTypes.AssemblyRef);
        var memory = new TypeRefUser(module, "System.IO", "MemoryStream", module.CorLibTypes.AssemblyRef);
        var method = new MethodDefUser("Decode", MethodSig.CreateStatic(new ClassSig(memoryReturn ? memory : stream), new ClassSig(stream)), MethodAttributes.Static)
            { Body = new CilBody() };
        host.Methods.Add(method);
        void Add(params Instruction[] instructions) { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }
        if (consume)
            Add(OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_0.ToInstruction(),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Length", MethodSig.CreateInstance(module.CorLibTypes.Int64), stream)),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "set_Position", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int64), stream)));
        if (unchanged) { Add(OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ret.ToInstruction()); }
        else
        {
            Add(OpCodes.Ldc_I4_8.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));
            for (var index = 0; index < 8; index++)
                Add(OpCodes.Dup.ToInstruction(), Instruction.CreateLdcI4(index), Instruction.CreateLdcI4(20 + index), OpCodes.Stelem_I1.ToInstruction());
            Add(OpCodes.Ldc_I4_3.ToInstruction(), OpCodes.Ldc_I4_3.ToInstruction(),
                OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void,
                    new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.Int32, module.CorLibTypes.Int32), memory)), OpCodes.Ret.ToInstruction());
        }
        module.Resources.Add(new EmbeddedResource("../source", [3, 0, 17, 18, 19, 1, 7, 99, 99, 99], ManifestResourceAttributes.Private));
    });
}
