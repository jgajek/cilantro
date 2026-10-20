using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelMethodCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "babel-12-methods.manifest.json");
    private static string Sample(string id) => Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_METHOD_SAMPLES")!,
        CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id).LocalName);

    [Fact]
    public void ManifestPinsSupportedReceiversProducerControlsAndUnresolvedAdaptations()
    {
        var manifest = CorpusRunner.LoadManifest(Manifest);
        Assert.Equal(21, manifest.Samples.Count);
        Assert.Equal(3, manifest.Samples.Count(sample => sample.Tier == "oracle"));
        foreach (var framework in new[] { "net48", "net8.0", "net10.0" })
        {
            var cases = manifest.Samples.Where(sample => sample.Id.StartsWith(framework + "-", StringComparison.Ordinal) && sample.Tier != "oracle").ToArray();
            Assert.Equal(6, cases.Length);
            Assert.Equal(1, cases.Single(sample => sample.Id.EndsWith("-instance", StringComparison.Ordinal)).ExpectedRestoredBodyCount);
            Assert.All(cases.Where(sample => sample.Id.EndsWith("-struct", StringComparison.Ordinal) || sample.Id.EndsWith("-generic-method", StringComparison.Ordinal)),
                sample => Assert.Equal(0, sample.ExpectedRestoredBodyCount));
            Assert.Equal(3, cases.Single(sample => sample.Id.EndsWith("-byref", StringComparison.Ordinal)).ExpectedRestoredBodyCount);
            Assert.Equal(1, cases.Single(sample => sample.Id.EndsWith("-generic-owner", StringComparison.Ordinal)).ExpectedRestoredBodyCount);
            Assert.Equal(5, cases.Single(sample => sample.Id.EndsWith("-all", StringComparison.Ordinal)).ExpectedRestoredBodyCount);
            Assert.All(cases, sample => Assert.Equal("profiled", sample.Tier));
            Assert.All(cases.Where(sample => sample.Tier == "profiled"), sample => { Assert.Equal(0, sample.MaximumSurplusResources); Assert.True(sample.RequireOracleResourceParity); });
        }
    }

    [BabelMethodCorpusFact]
    public void CapturedMethodShapesMatchTheirMeasuredRecoveryAndRefusalGates()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelMethods.").FullName;
        try
        {
            var outcome = CorpusRunner.Run(Manifest, Environment.GetEnvironmentVariable("CILANTRO_BABEL12_METHOD_SAMPLES")!, directory);
            Assert.True(outcome.Passed == 18 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(sample => sample.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            foreach (var sample in CorpusRunner.LoadManifest(Manifest).Samples.Where(sample => sample.Tier == "profiled" && sample.Id.StartsWith("net48-", StringComparison.Ordinal)))
            {
                var difference = IlVerification.Against(IlVerification.Read(Sample(sample.Id)), IlVerification.Read(Path.Combine(directory, sample.Id, "cleaned.bin")));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable)); Assert.Empty(difference.Worsened);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [BabelMethodCorpusTheory]
    [InlineData("net48-instance")]
    [InlineData("net8.0-instance")]
    [InlineData("net10.0-instance")]
    public void ReceiverIdentityFieldsAndExceptionRegionsSurviveRecovery(string id)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new BabelDetectionPass().Run(context);
        var result = new BabelMethodImagePass().Run(context);
        Assert.True(result.Status == PassStatus.Success && result.Changes == 1, string.Join("; ", result.Diagnostics));
        var owner = context.Module.GetTypes().Single(type => type.Name == "Receiver");
        var method = owner.Methods.Single(method => method.Name == "Instance");
        Assert.False(method.IsStatic); Assert.Equal(2, method.Body.ExceptionHandlers.Count);
        Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out var why), why);
        Assert.True(machine!.State.Heap.TryAllocateObject(owner.FullName, out var receiver));
        Assert.True(machine.Execute(owner.FindInstanceConstructors().Single(), [receiver, StaticValue.FromInt32(11)]).Succeeded);
        var field = owner.Fields.Single(field => field.Name == "State");
        // Negative inputs are covered by the protected/cleaned/oracle CLR runs;
        // localized parameterless exception messages are outside this interpreter model.
        var values = new[] { 0, 3, 19 }; var expected = new[] { 33, 45, 105 }; var states = new[] { 12, 16, 36 };
        for (var index = 0; index < values.Length; index++)
        {
            var answer = machine.Execute(method, [receiver, StaticValue.FromInt32(values[index])]);
            Assert.True(answer.Succeeded, answer.Diagnostic); Assert.Equal(expected[index], answer.Value.AsInt32());
            Assert.True(machine.State.Heap.TryReadField(receiver, field, out var state)); Assert.Equal(states[index], state.AsInt32());
        }
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed);
    }

    [BabelMethodCorpusTheory]
    [InlineData("net48-generic-owner", 1)]
    [InlineData("net8.0-generic-owner", 1)]
    [InlineData("net10.0-generic-owner", 1)]
    [InlineData("net48-all", 5)]
    [InlineData("net8.0-all", 5)]
    [InlineData("net10.0-all", 5)]
    public void GenericOwnersRecoverOriginalFieldsAndOpenTypeOperands(string id, int count)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new BabelDetectionPass().Run(context);
        var result = new BabelMethodImagePass().Run(context);
        Assert.True(result.Status == PassStatus.Success && result.Changes == count, string.Join("; ", result.Diagnostics));
        var method = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Exchange");
        Assert.IsType<GenericVar>(method.ReturnType); Assert.IsType<GenericVar>(Assert.Single(method.MethodSig.Params));
        Assert.Contains(method.Body.Instructions, instruction => instruction.OpCode.Code == Code.Ldfld);
        Assert.Contains(method.Body.Instructions, instruction => instruction.OpCode.Code == Code.Stfld);
        Assert.DoesNotContain(method.Body.Instructions, instruction => instruction.Operand is IMethod called && called.DeclaringType.FullName == "System.Reflection.MethodBase");
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed);
    }

    [BabelMethodCorpusTheory]
    [InlineData("argument")]
    [InlineData("box")]
    [InlineData("box-type")]
    [InlineData("receiver")]
    [InlineData("tail")]
    [InlineData("locals")]
    [InlineData("base-pointer")]
    [InlineData("constraint-variance")]
    public void ChangedGenericAdaptationsRefuseWithoutCommittingBodies(string change)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-generic-owner"));
        var method = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Exchange");
        var owner = method.DeclaringType;
        Assert.NotNull(BabelGenericStub.Match(method, _ => true));
        switch (change)
        {
            case "argument": method.Body.Instructions.First(instruction => instruction.OpCode.Code == Code.Ldarg_1).OpCode = OpCodes.Ldarg_0; break;
            case "box": method.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Box).OpCode = OpCodes.Nop; break;
            case "box-type": method.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Box).Operand = context.Module.CorLibTypes.Int32.TypeDefOrRef; break;
            case "receiver": method.Body.Instructions.First(instruction => instruction.OpCode.Code == Code.Ldarg_0).OpCode = OpCodes.Ldnull; break;
            case "tail": method.Body.Instructions.Insert(0, OpCodes.Ldc_I4_0.ToInstruction()); break;
            case "locals": method.Body.InitLocals = false; break;
            case "base-pointer": owner.BaseType = new TypeSpecUser(new GenericInstSig(
                new ClassSig(context.Module.CorLibTypes.GetTypeRef("System.Collections.Generic", "List`1")),
                new PtrSig(context.Module.CorLibTypes.Int32))); break;
            case "constraint-variance": owner.GenericParameters[0].Flags = GenericParamAttributes.Covariant; break;
        }
        Assert.Null(BabelGenericStub.Match(method, _ => true));
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelGenericRefusal.").FullName;
        try
        {
            var path = Path.Combine(directory, "BabelMethodProbe.dll"); context.Module.Write(path);
            using var changed = ArtifactContext.Load(path);
            new BabelDetectionPass().Run(changed);
            var bodies = changed.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new BabelMethodImagePass().Run(changed);
            Assert.Equal(PassStatus.Unsupported, result.Status); Assert.Equal(0, result.Changes);
            Assert.All(bodies, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
            Assert.Empty(changed.Changes);
            Assert.False(changed.TryGetFact<IReadOnlyList<BabelMethodImageResourceOwnership.Pending>>(BabelMethodImageResourceOwnership.Fact, out _));
        }
        finally { Directory.Delete(directory, true); }
    }

    [BabelMethodCorpusTheory]
    [InlineData("alias")]
    [InlineData("managed")]
    [InlineData("extra-field")]
    [InlineData("model")]
    public void ArbitraryReceiverSnapshotDetectsWritesThroughConstructedFieldAliases(string change)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-generic-owner"));
        var method = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Exchange");
        var proof = Assert.IsType<BabelGenericStub>(BabelGenericStub.Match(method, _ => true));
        var types = new ParametricTypeIntrinsic(method.DeclaringType, new RawDynamicMethodIntrinsic());
        var machine = new StaticMachine(intrinsics: types); types.Attach(machine);
        var receiver = proof.Prepare(machine, types); var heap = machine.State.Heap;
        var field = Assert.Single(method.DeclaringType.Fields);
        var alias = new MemberRefUser(context.Module, field.Name, field.FieldSig, new TypeSpecUser(types.Owner));
        Assert.True(heap.TryReadField(receiver, field, out var before)); Assert.False(before.IsKnown);
        Assert.True(heap.TryReadField(receiver, alias, out var aliased)); Assert.Equal(before.ProvenanceId, aliased.ProvenanceId);
        Assert.True(heap.TryGetFieldReference(receiver, alias, out var address)); Assert.True(proof.Unchanged(heap));
        Assert.True(heap.TryReadManaged(address, out var indirect)); Assert.Equal(before.ProvenanceId, indirect.ProvenanceId);
        Assert.True(heap.TryAllocateObject(types.Owner.FullName, out var other)); heap.TryWriteField(other, alias, StaticValue.FromInt32(8));
        Assert.True(proof.Unchanged(heap));
        var replacement = machine.State.Provenance.Origin(StaticValue.Unknown, ProvenanceKind.InstanceField, "Different receiver value", field.FullName);
        switch (change)
        {
            case "alias": Assert.True(heap.TryWriteField(receiver, alias, replacement)); break;
            case "managed": Assert.True(heap.TryWriteManaged(address, replacement)); break;
            case "extra-field": Assert.True(heap.TryWriteField(receiver, new MemberRefUser(context.Module, "extra", field.FieldSig, method.DeclaringType), replacement)); break;
            case "model": Assert.True(heap.TrySetModelValue(receiver, "extra", true)); break;
        }
        Assert.False(proof.Unchanged(heap));
    }

    [BabelMethodCorpusTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void ChangedReceiverOrArgumentCannotBeReplaced(bool argument)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelReceiverRefusal.").FullName;
        try
        {
            var path = Path.Combine(directory, "BabelMethodProbe.dll");
            using (var module = ModuleDefMD.Load(Sample("net8.0-instance")))
            {
                var method = module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Instance");
                var instruction = method.Body.Instructions.Single(instruction => instruction.OpCode.Code == (argument ? Code.Ldarg_1 : Code.Ldarg_0));
                instruction.OpCode = argument ? OpCodes.Ldc_I4_0 : OpCodes.Ldnull; instruction.Operand = null;
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            new BabelDetectionPass().Run(context);
            var bodies = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new BabelMethodImagePass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status); Assert.Equal(0, result.Changes);
            Assert.All(bodies, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
            Assert.False(context.TryGetFact<IReadOnlyList<BabelMethodImageResourceOwnership.Pending>>(BabelMethodImageResourceOwnership.Fact, out _));
        }
        finally { Directory.Delete(directory, true); }
    }

    [BabelMethodCorpusTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void ChangedByrefInputsAndUninitializedStubsRefuseAtomically(bool uninitialized)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelByrefRefusal.").FullName;
        try
        {
            var path = Path.Combine(directory, "BabelMethodProbe.dll");
            using (var module = ModuleDefMD.Load(Sample("net8.0-byref")))
            {
                var method = module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "RefValue");
                if (uninitialized) method.Body.InitLocals = false;
                else method.Body.Instructions.First(instruction => instruction.OpCode.Code == Code.Ldarg_0).OpCode = OpCodes.Ldarg_1;
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            new BabelDetectionPass().Run(context);
            var bodies = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new BabelMethodImagePass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status); Assert.Equal(0, result.Changes);
            Assert.All(bodies, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
            Assert.Empty(context.Changes);
            Assert.False(context.TryGetFact<IReadOnlyList<BabelMethodImageResourceOwnership.Pending>>(BabelMethodImageResourceOwnership.Fact, out _));
        }
        finally { Directory.Delete(directory, true); }
    }
}

public sealed class BabelMethodCorpusFactAttribute : FactAttribute
{
    public BabelMethodCorpusFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_BABEL12_METHOD_SAMPLES") is not { Length: > 0 }) Skip = "Set CILANTRO_BABEL12_METHOD_SAMPLES to the pinned method-shape package.";
    }
}
public sealed class BabelMethodCorpusTheoryAttribute : TheoryAttribute
{
    public BabelMethodCorpusTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_BABEL12_METHOD_SAMPLES") is not { Length: > 0 }) Skip = "Set CILANTRO_BABEL12_METHOD_SAMPLES to the pinned method-shape package.";
    }
}
