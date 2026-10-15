using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DecodedResourceOwnershipTests
{
    [Theory]
    [InlineData("preserved", 1)]
    [InlineData("changed", 0)]
    [InlineData("missing", 0)]
    [InlineData("duplicate", 0)]
    [InlineData("empty", 0)]
    [InlineData("source-mismatch", 0)]
    [InlineData("retained-reader", 0)]
    public void BundleRetirementRequiresEveryRestoredStreamToRemainIntact(string scenario, int expected)
    {
        using var context = Fixture();
        var owner = context.Module.Types.Single(t => t.Name == "Resolver");
        var source = RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0]);
        var restored = new EmbeddedResource("App.resources", new byte[] { 3, 4 }, ManifestResourceAttributes.Public);
        context.Module.Resources.Add(restored);
        var bundle = new RestoredResourceBundle(scenario == "source-mismatch" ? source with { Name = "other" } : source,
            scenario == "empty" ? [] : [RecoveredResourceOrigin.Capture(restored)]);
        DecodedResourceOwnership.Remember(context, source, owner.Methods, bundle: bundle);
        if (scenario != "retained-reader") context.Module.Types.Remove(owner);
        if (scenario == "changed") context.Module.Resources[1] = new EmbeddedResource("App.resources", new byte[] { 9 }, ManifestResourceAttributes.Public);
        if (scenario == "missing") context.Module.Resources.Remove(restored);
        if (scenario == "duplicate") context.Module.Resources.Add(new EmbeddedResource("App.resources", new byte[] { 3, 4 }, ManifestResourceAttributes.Public));
        Assert.Equal(expected, DecodedResourceOwnership.RemovedOrigins(context).Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EveryObservedReaderAndProxyTypeMustBePhysicallyGone(bool proxy)
    {
        using var context = Fixture();
        var owner = context.Module.Types.Single(t => t.Name == "Resolver");
        var reader = owner.Methods[0]; var alias = owner.Methods[1];
        var origin = RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0]);
        DecodedResourceOwnership.Remember(context, origin, [reader], proxy ? new[] { owner } : null);
        DecodedResourceOwnership.Remember(context, origin, [alias]);
        Assert.Empty(DecodedResourceOwnership.RemovedOrigins(context));
        owner.Methods.Remove(reader);
        Assert.Empty(DecodedResourceOwnership.RemovedOrigins(context));
        owner.Methods.Remove(alias);
        Assert.Equal(proxy ? 0 : 1, DecodedResourceOwnership.RemovedOrigins(context).Count);
        context.Module.Types.Remove(owner);
        Assert.Single(DecodedResourceOwnership.RemovedOrigins(context));
        // Reattaching a reader/type invalidates retirement; names alone are not proof.
        context.Module.Types.Add(owner); owner.Methods.Add(alias);
        Assert.Empty(DecodedResourceOwnership.RemovedOrigins(context));
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("foreign")]
    [InlineData("changed")]
    [InlineData("duplicate")]
    public void InvalidAttributionCannotAuthorizeRetirement(string scenario)
    {
        using var context = Fixture(); using var foreign = Fixture();
        var owner = context.Module.Types.Single(t => t.Name == "Resolver");
        var origin = RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0]);
        if (scenario == "changed") origin = origin with { Sha256 = "wrong" };
        if (scenario == "duplicate") context.Module.Resources.Add(new EmbeddedResource("table", new byte[] { 1, 2 }, ManifestResourceAttributes.Private));
        IEnumerable<MethodDef> readers = scenario switch
        { "empty" => [], "foreign" => foreign.Module.Types.Single(t => t.Name == "Resolver").Methods, _ => owner.Methods };
        DecodedResourceOwnership.Remember(context, origin, readers);
        context.Module.Types.Remove(owner);
        Assert.Empty(DecodedResourceOwnership.RemovedOrigins(context));
    }

    [Theory]
    [InlineData("retired", 1)]
    [InlineData("reader-remains", 0)]
    [InlineData("changed", 0)]
    [InlineData("application", 0)]
    [InlineData("duplicate", 0)]
    public void RetiredTablesCanDisappearDespiteUnrelatedNativeCode(string scenario, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("table", new byte[] { 1, 2 }, ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("unrelated", new byte[] { 3, 4 }, ManifestResourceAttributes.Private));
            var owner = SyntheticContext.AddType(module, "Owner");
            var reader = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(reader); reader.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            owner.Methods.Add(new MethodDefUser("Native", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Attributes = MethodAttributes.Static | MethodAttributes.PinvokeImpl,
                ImplMap = new ImplMapUser(new ModuleRefUser(module, "unknown.dll"), "Run", 0)
            });
        });
        var owner = context.Module.Types.Single(t => t.Name == "Owner");
        var reader = owner.Methods.Single(m => m.Name == "Read");
        var source = RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0]);
        DecodedResourceOwnership.Remember(context, source, [reader]);
        context.SetFact("options.removeRuntime", true);
        if (scenario != "reader-remains")
        {
            context.SetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", new HashSet<uint> { reader.MDToken.Raw });
            owner.Methods.Remove(reader);
        }
        if (scenario == "changed") context.Module.Resources[0] = new EmbeddedResource("table", new byte[] { 9 }, ManifestResourceAttributes.Private);
        if (scenario == "duplicate") context.Module.Resources.Add(new EmbeddedResource("table", new byte[] { 1, 2 }, ManifestResourceAttributes.Private));
        if (scenario == "application") context.SetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles",
            [new("table", ResourceRole.ManagedPayload, 1, [], [])]);
        // Decoding alone cannot give an unrelated table the retired-owner exception.
        context.SetFact("proxy.validatedResource", RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[1]));
        Assert.Equal(expected, new ProtectorResourceCleanupPass().Run(context).Changes);
        Assert.Contains(context.Module.Resources, r => r.Name == "unrelated");
        Assert.Contains(owner.Methods, m => m.Name == "Native" && m.IsPinvokeImpl);
        Assert.Equal(0, new ProtectorResourceCleanupPass().Run(context).Changes);
    }
    [Theory]
    [InlineData("owned", 1)]
    [InlineData("unowned", 0)]
    [InlineData("outer-only", 0)]
    [InlineData("shared", 0)]
    [InlineData("truncated", 0)]
    [InlineData("changed", 0)]
    [InlineData("length", 0)]
    [InlineData("malformed", 0)]
    public void ResourceReadsRequireExactBytesAndOwnedInnermostReaders(string scenario, int expected)
    {
        using var context = Fixture();
        var owner = context.Module.Types.Single(t => t.Name == "Resolver");
        var origin = RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0]);
        var token = owner.Methods[0].MDToken.Raw;
        uint[] stack = scenario switch { "unowned" => [0x0600ffff], "outer-only" => [token, 0x0600ffff], _ => [token] };
        var detail = scenario == "malformed" ? "{" : System.Text.Json.JsonSerializer.Serialize(
            new Cilantro.Core.Interpretation.ManagedResourceRead(origin.Name, scenario == "changed" ? "wrong" : origin.Sha256,
                scenario == "length" ? 3 : 2));
        var observations = new List<Cilantro.Core.Interpretation.LoaderObservation>
        { new(Cilantro.Core.Interpretation.LoaderObservationKind.ManagedResourceRead, detail, null, stack) };
        if (scenario == "shared") observations.Add(new(Cilantro.Core.Interpretation.LoaderObservationKind.ManagedResourceRead, detail, null, [0x0600ffff]));
        var evidence = new Cilantro.Core.Interpretation.LoaderInterpretationEvidence(observations,
            new Dictionary<uint, Cilantro.Core.Interpretation.LoaderMethodEffects>()) { ObservationsTruncated = scenario == "truncated" };
        Assert.Equal(expected, DecodedResourceOwnership.ObservedOwnedReads(context, evidence, new HashSet<TypeDef> { owner }).Count);
    }
    private static Cilantro.Core.ArtifactContext Fixture() => SyntheticContext.Build(module =>
    {
        module.Resources.Add(new EmbeddedResource("table", new byte[] { 1, 2 }, ManifestResourceAttributes.Private));
        var owner = SyntheticContext.AddType(module, "Resolver");
        for (var i = 0; i < 2; i++)
        {
            var method = new MethodDefUser(i == 0 ? "Read" : "Alias", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(method); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        }
    });
}
