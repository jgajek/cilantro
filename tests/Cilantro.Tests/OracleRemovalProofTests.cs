using System.Security.Cryptography;
using Cilantro.Core;
using Cilantro.Core.Corpus;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class OracleRemovalProofTests
{
    [Fact]
    public void ResourceRemovalRequiresTheSameBytesInInputAndOracle()
    {
        using var fixture = new Fixture();
        var proof = fixture.Proof(Fixture.ResourceChange());
        Assert.Equal(["opaque"], proof.Resources);
    }

    [Theory]
    [InlineData("wrong-hash")]
    [InlineData("changed-oracle")]
    [InlineData("still-present")]
    [InlineData("wrong-pass")]
    [InlineData("no-record")]
    public void UnprovenResourceLossCannotBeQualified(string variant)
    {
        using var fixture = new Fixture();
        var change = Fixture.ResourceChange();
        switch (variant)
        {
            case "wrong-hash": change = change with { Description = "SHA-256 " + new string('0', 64) + "." }; break;
            case "changed-oracle":
                fixture.Oracle.Resources.Clear();
                fixture.Oracle.Resources.Add(new EmbeddedResource("opaque", [9], ManifestResourceAttributes.Private));
                break;
            case "still-present": fixture.Output.Resources.Add(new EmbeddedResource("opaque", [1, 2, 3], ManifestResourceAttributes.Private)); break;
            case "wrong-pass": change = change with { Pass = "unrelated" }; break;
        }
        Assert.Empty(fixture.Proof(variant == "no-record" ? [] : [change]).Resources);
    }

    [Fact]
    public void AnExplicitPrivateHelperRemovalHasAUniqueOracleCounterpart()
    {
        using var fixture = new Fixture();
        var proof = fixture.Proof(fixture.MethodChange());
        Assert.Equal([fixture.Reference.FullName], proof.PrivateMethods);
    }

    [Theory]
    [InlineData("public")]
    [InlineData("preserved-name")]
    [InlineData("constructor")]
    [InlineData("ambiguous")]
    [InlineData("still-present")]
    [InlineData("wrong-token")]
    [InlineData("wrong-pass")]
    [InlineData("missing-owner")]
    public void OtherMethodLossCannotBeQualifiedAsUnusedPrivateCleanup(string variant)
    {
        using var fixture = new Fixture();
        switch (variant)
        {
            case "public": fixture.Source.Attributes = MethodAttributes.Public | MethodAttributes.Static; break;
            case "preserved-name": fixture.Source.Name = "EncodePayload"; break;
            case "constructor": fixture.Source.Name = ".cctor"; break;
            case "ambiguous": fixture.Reference.DeclaringType.Methods.Add(Fixture.Method(fixture.Oracle, "smethod_1")); break;
            case "still-present": fixture.Output.Types.Single(type => type.Name == "Crypto").Methods.Add(Fixture.Method(fixture.Output, "smethod_0")); break;
            case "missing-owner": fixture.Output.Types.Remove(fixture.Output.Types.Single(type => type.Name == "Crypto")); break;
        }
        var change = fixture.MethodChange();
        if (variant == "wrong-token") change = change with { Location = "06000002 " + fixture.Source.FullName };
        if (variant == "wrong-pass") change = change with { Pass = "unrelated" };
        Assert.Empty(fixture.Proof(change).PrivateMethods);
    }

    private sealed class Fixture : IDisposable
    {
        public ModuleDefUser Input { get; } = new("input");
        public ModuleDefUser Oracle { get; } = new("oracle");
        public ModuleDefUser Output { get; } = new("output");
        public MethodDef Source { get; }
        public MethodDef Reference { get; }

        public Fixture()
        {
            foreach (var module in new[] { Input, Oracle, Output })
                module.Types.Add(new TypeDefUser("Application", "Crypto", module.CorLibTypes.Object.TypeDefOrRef));
            Source = Method(Input, "Q8Q4KhSaS");
            Reference = Method(Oracle, "smethod_0");
            Input.Types.Single(type => type.Name == "Crypto").Methods.Add(Source);
            Oracle.Types.Single(type => type.Name == "Crypto").Methods.Add(Reference);
            Input.UpdateRowId(Source);
            Input.Resources.Add(new EmbeddedResource("opaque", [1, 2, 3], ManifestResourceAttributes.Private));
            Oracle.Resources.Add(new EmbeddedResource("opaque", [1, 2, 3], ManifestResourceAttributes.Private));
        }

        public static MethodDefUser Method(ModuleDef module, string name) => new MethodDefUser(name,
            MethodSig.CreateStatic(module.CorLibTypes.String, new SZArraySig(module.CorLibTypes.Byte)),
            MethodAttributes.Private | MethodAttributes.Static);

        public static ChangeRecord ResourceChange() => new("protector-resource-cleanup", "remove-decoded-protector-resource",
            "opaque", "Removed attributed protector data; SHA-256 " + Convert.ToHexStringLower(SHA256.HashData([1, 2, 3])) + ".");

        public ChangeRecord MethodChange() => new("unused-private-helper-cleanup", "remove-unused-private-helper",
            Source.MDToken + " " + Source.FullName, "Removed an unused private static application helper.");

        public CorpusRunner.OracleRemovalProof Proof(params ChangeRecord[] changes) =>
            CorpusRunner.ReadOracleRemovalProof(Input, Oracle, Output, changes);

        public void Dispose()
        {
            Input.Dispose();
            Oracle.Dispose();
            Output.Dispose();
        }
    }
}
