using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelMethodImageResourceTests
{
    [Theory]
    [InlineData("closed", 1)]
    [InlineData("unowned-alias", 0)]
    [InlineData("different-bytes", 0)]
    [InlineData("empty-stack", 0)]
    [InlineData("startup-only", 0)]
    [InlineData("truncated", 0)]
    [InlineData("malformed", 0)]
    [InlineData("foreign-token", 0)]
    [InlineData("satellite-reader", 0)]
    public void OnlyUnambiguousDirectImageReadsEstablishOwnership(string scenario, int count)
    {
        using var context = SyntheticContext.Build(Build);
        var module = context.Module;
        var stub = module.GlobalType.Methods.Single(method => method.Name == "Stub");
        var reader = module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Read");
        var resource = RecoveredResourceOrigin.Capture((EmbeddedResource)module.Resources[0]);
        var detail = JsonSerializer.Serialize(new ManagedResourceRead(resource.Name, resource.Sha256, 3));
        uint[] stack = [stub.MDToken.Raw, reader.MDToken.Raw];
        if (scenario == "empty-stack") stack = [];
        if (scenario == "startup-only") stack = [reader.MDToken.Raw];
        var reads = new List<LoaderObservation> { new(LoaderObservationKind.ManagedResourceRead, scenario == "malformed" ? "{" : detail, null, stack) };
        if (scenario == "unowned-alias") reads.Add(new(LoaderObservationKind.ManagedResourceRead, detail, null, [stub.MDToken.Raw]));
        if (scenario == "different-bytes") reads.Add(new(LoaderObservationKind.ManagedResourceRead,
            JsonSerializer.Serialize(new ManagedResourceRead(resource.Name, new string('0', 64), 3)), null, stack));
        var evidence = new LoaderInterpretationEvidence(reads, new Dictionary<uint, LoaderMethodEffects>()) { ObservationsTruncated = scenario == "truncated" };
        if (scenario == "satellite-reader") reader.MethodSig.RetType = new ClassSig(module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly"));
        Assert.Equal(count, BabelMethodImageResourceOwnership.Observe(module, stub, evidence,
            scenario == "foreign-token" ? new HashSet<uint> { reader.MDToken.Raw } : null).Count);
    }

    [Theory]
    [InlineData("restored", true)]
    [InlineData("changed", false)]
    [InlineData("duplicate", false)]
    [InlineData("reader-retained", false)]
    public void DeferredTablesRequireExactRestorationAndPhysicalReaderRetirement(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(Build);
        context.SetFact("options.removeRuntime", true);
        var module = context.Module;
        var reader = module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Read");
        var source = RecoveredResourceOrigin.Capture((EmbeddedResource)module.Resources[0]);
        module.Resources.Clear();
        BabelMethodImageResourceOwnership.Remember(context, [new(source, 3, reader.MDToken.Raw)]);
        Assert.True(context.TryGetFact<IReadOnlyList<BabelMethodImageResourceOwnership.Pending>>(BabelMethodImageResourceOwnership.Fact, out var inputs));
        var input = Assert.Single(inputs!); Assert.False(input.Published);
        Assert.False(context.TryGetFact<IReadOnlyList<DecodedResourceOwnership>>(DecodedResourceOwnership.Fact, out _));
        module.Resources.Add(new EmbeddedResource(source.Name, scenario == "changed" ? [3, 2, 1] : [1, 2, 3], ManifestResourceAttributes.Private));
        if (scenario == "duplicate") module.Resources.Add(new EmbeddedResource(source.Name, [1, 2, 3], ManifestResourceAttributes.Private));
        BabelMethodImageResourceOwnership.Publish(context);
        Assert.Equal(scenario is "restored" or "reader-retained", input.Published);
        if (input.Published)
        {
            Assert.True(context.TryGetFact<IReadOnlyList<DecodedResourceOwnership>>(DecodedResourceOwnership.Fact, out var owners));
            Assert.True(Assert.Single(owners!).IsMethodImageConstruction);
        }
        if (scenario != "reader-retained")
        {
            reader.DeclaringType.Methods.Remove(reader);
            context.SetFact("cleanup.removedMethodCount", 1);
            context.SetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", new HashSet<uint> { reader.MDToken.Raw });
        }
        var result = new ProtectorResourceCleanupPass().Run(context);
        Assert.True(result.Changes == (removed ? 1 : 0), string.Join("; ", result.Diagnostics));
        Assert.Equal(!removed, module.Resources.Any(resource => resource.Name == source.Name));
    }

    private static void Build(ModuleDefUser module)
    {
        module.Resources.Add(new EmbeddedResource("image", [1, 2, 3], ManifestResourceAttributes.Private));
        var descriptor = SyntheticContext.AddType(module, "ImageDescriptor");
        var runtime = SyntheticContext.AddType(module, "ImageReader");
        var reader = new MethodDefUser("Read", MethodSig.CreateStatic(new ClassSig(descriptor)), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
        runtime.Methods.Add(reader);
        var stream = new MemberRefUser(module, "GetManifestResourceStream", MethodSig.CreateInstance(
            new ClassSig(module.CorLibTypes.GetTypeRef("System.IO", "Stream")), module.CorLibTypes.String), module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly"));
        reader.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); reader.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("image"));
        reader.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(stream)); reader.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
        reader.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); reader.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var stub = new MethodDefUser("Stub", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
        stub.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); module.GlobalType.Methods.Add(stub);
    }
}
