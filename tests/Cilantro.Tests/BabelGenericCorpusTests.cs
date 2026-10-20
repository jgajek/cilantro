using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelGenericCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "babel-12-generics.manifest.json");
    private static string Root => Environment.GetEnvironmentVariable("CILANTRO_BABEL12_METHOD_SAMPLES")!;

    [BabelMethodCorpusTheory]
    [InlineData("net48-static-state")]
    [InlineData("net8.0-static-state")]
    [InlineData("net10.0-static-state")]
    public void StaticStateBodiesRecoverWithoutChangingTheirApplicationInitializer(string id)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id);
        using var context = ArtifactContext.Load(Path.Combine(Root, sample.LocalName)); new BabelDetectionPass().Run(context);
        var owner = context.Module.GetTypes().Single(type => type.Name == "StatefulBox`1");
        var initializer = owner.FindStaticConstructor(); Assert.NotNull(initializer);
        var snapshot = MethodBodySnapshot.Capture(initializer); var beforeFieldInit = owner.IsBeforeFieldInit;
        var result = new BabelMethodImagePass().Run(context);
        Assert.True(result.Status == PassStatus.Success && result.Changes == 1, string.Join("; ", result.Diagnostics));
        Assert.Same(initializer, owner.FindStaticConstructor()); Assert.True(snapshot.StructurallyEquals(initializer));
        Assert.Equal(beforeFieldInit, owner.IsBeforeFieldInit);
        var body = owner.Methods.Single(method => method.Name == "Exchange").Body;
        Assert.Contains(body.Instructions, instruction => instruction.OpCode.Code == Code.Ldsfld);
        Assert.Contains(body.Instructions, instruction => instruction.OpCode.Code == Code.Stsfld);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed);
    }

    [Fact]
    public void ManifestPinsEveryCapturedGenericOwnerShape()
    {
        var manifest = CorpusRunner.LoadManifest(Manifest);
        Assert.Equal(21, manifest.Samples.Count);
        Assert.Equal(3, manifest.Samples.Count(sample => sample.Tier == "oracle"));
        Assert.Equal(18, manifest.Samples.Count(sample => sample.Tier == "profiled"));
        Assert.DoesNotContain(manifest.Samples, sample => sample.Tier == "exploratory");
        Assert.All(manifest.Samples.Where(sample => sample.Tier == "profiled"), sample =>
        {
            Assert.Equal(1, sample.ExpectedRestoredBodyCount);
            Assert.Equal(0, sample.MaximumRemainingStubs);
            Assert.True(sample.RequireOracleResourceParity);
        });
        Assert.All(manifest.Samples.Where(sample => sample.Tier == "exploratory"), sample => Assert.NotNull(sample.ExpectUnsupportedReason));
    }

    [BabelMethodCorpusTheory]
    [InlineData("net48-open-owner")]
    [InlineData("net8.0-open-owner")]
    [InlineData("net10.0-open-owner")]
    public void InheritedOwnersRestoreTheDeclaringBaseFieldAndOriginalGenericSignature(string id)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id);
        using var context = ArtifactContext.Load(Path.Combine(Root, sample.LocalName)); new BabelDetectionPass().Run(context);
        var result = new BabelMethodImagePass().Run(context);
        Assert.True(result.Status == PassStatus.Success && result.Changes == 1, string.Join("; ", result.Diagnostics));
        var owner = context.Module.GetTypes().Single(type => type.Name == "OpenBox`1"); Assert.False(owner.IsSealed);
        var method = owner.Methods.Single(method => method.Name == "Exchange");
        Assert.IsType<GenericVar>(method.ReturnType); Assert.Equal(2, method.Parameters.Count);
        var fields = method.Body.Instructions.Select(instruction => instruction.Operand).OfType<IField>().ToArray();
        Assert.Equal(2, fields.Length); Assert.All(fields, field => Assert.Same(owner, field.ResolveFieldDef()!.DeclaringType));
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed);
    }

    [BabelMethodCorpusTheory]
    [InlineData("net48-static-method")]
    [InlineData("net8.0-static-method")]
    [InlineData("net10.0-static-method")]
    public void StaticGenericOwnersRestoreBothExplicitArgumentsWithoutAReceiver(string id)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id);
        using var context = ArtifactContext.Load(Path.Combine(Root, sample.LocalName)); new BabelDetectionPass().Run(context);
        var result = new BabelMethodImagePass().Run(context);
        Assert.True(result.Status == PassStatus.Success && result.Changes == 1, string.Join("; ", result.Diagnostics));
        var owner = context.Module.GetTypes().Single(type => type.Name == "StaticBox`1");
        var method = owner.Methods.Single(method => method.Name == "Choose");
        Assert.True(method.IsStatic); Assert.Equal(2, method.Parameters.Count);
        Assert.Equal(Code.Ldarg_0, method.Body.Instructions[0].OpCode.Code);
        Assert.Equal(Code.Ret, method.Body.Instructions[1].OpCode.Code);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed);
    }

    [BabelMethodCorpusFact]
    public void StaticOwnerTokenRepresentsUnknownClosedArgumentsRatherThanOpenMetadataParameters()
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == "net8.0-static-method");
        using var context = ArtifactContext.Load(Path.Combine(Root, sample.LocalName));
        var owner = context.Module.GetTypes().Single(type => type.Name == "StaticBox`1"); var method = owner.Methods.Single(method => method.Name == "Choose");
        var proof = Assert.IsType<BabelGenericStub>(BabelGenericStub.Match(method, _ => true));
        var types = new Cilantro.Core.Interpretation.ParametricTypeIntrinsic(owner, new Cilantro.Core.Interpretation.RawDynamicMethodIntrinsic());
        var machine = new Cilantro.Core.Interpretation.StaticMachine(intrinsics: types); types.Attach(machine); machine.State.RegisterModuleMetadata(context.Module);
        proof.Prepare(machine, types);
        Assert.True(machine.State.Heap.TryAllocateMetadataHandle(method.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Ldtoken).Operand, out var handle));
        var invoke = new Cilantro.Core.Interpretation.IntrinsicContext(machine.State, Frames: [method]); var importer = new Importer(context.Module);
        var bound = types.Invoke(invoke, importer.Import(typeof(Type).GetMethod("GetTypeFromHandle")!), [handle]);
        Assert.Equal(Cilantro.Core.Interpretation.StaticExecutionStatus.Completed, bound.Status);
        var arguments = types.Invoke(invoke, importer.Import(typeof(Type).GetMethod("GetGenericArguments")!), [bound.Value]);
        Assert.True(machine.State.Heap.TryReadArray(arguments.Value, 0, out var argument));
        var query = types.Invoke(invoke, importer.Import(typeof(Type).GetProperty("IsGenericParameter")!.GetMethod!), [argument]);
        Assert.Equal(Cilantro.Core.Interpretation.StaticExecutionStatus.Unknown, query.Status);
    }

    [BabelMethodCorpusFact]
    public void StaticOwnerDoesNotNeedASealedReceiverAndAllocatesNoReceiverState()
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == "net8.0-static-method");
        using var context = ArtifactContext.Load(Path.Combine(Root, sample.LocalName));
        var owner = context.Module.GetTypes().Single(type => type.Name == "StaticBox`1"); owner.IsSealed = false;
        var method = owner.Methods.Single(method => method.Name == "Choose");
        var proof = Assert.IsType<BabelGenericStub>(BabelGenericStub.Match(method, _ => true));
        var types = new Cilantro.Core.Interpretation.ParametricTypeIntrinsic(owner, new Cilantro.Core.Interpretation.RawDynamicMethodIntrinsic());
        var machine = new Cilantro.Core.Interpretation.StaticMachine(intrinsics: types); types.Attach(machine);
        var before = machine.State.Heap.AllocatedBytes;
        Assert.Equal(Cilantro.Core.Interpretation.StaticValue.Null, proof.Prepare(machine, types));
        Assert.Equal(before, machine.State.Heap.AllocatedBytes); Assert.True(proof.Unchanged(machine.State.Heap));
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelUnsealedStatic.").FullName;
        try
        {
            var path = Path.Combine(directory, "BabelGenericProbe.dll"); context.Module.Write(path);
            using var changed = ArtifactContext.Load(path); new BabelDetectionPass().Run(changed);
            var result = new BabelMethodImagePass().Run(changed);
            Assert.True(result.Status == PassStatus.Success && result.Changes == 1, string.Join("; ", result.Diagnostics));
        }
        finally { Directory.Delete(directory, true); }
    }

    [BabelMethodCorpusTheory]
    [InlineData("owner-definition")]
    [InlineData("owner-argument")]
    [InlineData("owner-kind")]
    [InlineData("owner-index")]
    [InlineData("receiver")]
    [InlineData("slot")]
    [InlineData("box-type")]
    public void ChangedStaticContextsAndArgumentPackingRefuseAtomically(string change)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == "net8.0-static-method");
        using var context = ArtifactContext.Load(Path.Combine(Root, sample.LocalName));
        var owner = context.Module.GetTypes().Single(type => type.Name == "StaticBox`1");
        var method = owner.Methods.Single(method => method.Name == "Choose");
        Assert.NotNull(BabelGenericStub.Match(method, _ => true));
        var token = method.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Ldtoken);
        switch (change)
        {
            case "owner-definition": token.Operand = owner; break;
            case "owner-argument": token.Operand = new TypeSpecUser(new GenericInstSig(new ClassSig(owner), context.Module.CorLibTypes.Int32)); break;
            case "owner-kind": token.Operand = new TypeSpecUser(new GenericInstSig(new ValueTypeSig(owner), new GenericVar(0, owner))); break;
            case "owner-index": token.Operand = new TypeSpecUser(new GenericInstSig(new ClassSig(owner), new GenericVar(1, owner))); break;
            case "receiver": method.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Ldnull).OpCode = OpCodes.Ldarg_0; break;
            case "slot": method.Body.Instructions.First(instruction => instruction.IsLdcI4() && instruction.GetLdcI4Value() == 0).OpCode = OpCodes.Ldc_I4_1; break;
            case "box-type": method.Body.Instructions.First(instruction => instruction.OpCode.Code == Code.Box).Operand = context.Module.CorLibTypes.Int32.TypeDefOrRef; break;
        }
        Assert.Null(BabelGenericStub.Match(method, _ => true));
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelStaticGeneric.").FullName;
        try
        {
            var path = Path.Combine(directory, "BabelGenericProbe.dll"); context.Module.Write(path);
            using var changed = ArtifactContext.Load(path); new BabelDetectionPass().Run(changed);
            var snapshots = changed.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
                .ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new BabelMethodImagePass().Run(changed);
            Assert.Equal(PassStatus.Unsupported, result.Status); Assert.Equal(0, result.Changes);
            Assert.All(snapshots, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
            Assert.Empty(changed.Changes);
        }
        finally { Directory.Delete(directory, true); }
    }

    [BabelMethodCorpusTheory]
    [InlineData("net48-new-constraint")]
    [InlineData("net8.0-new-constraint")]
    [InlineData("net10.0-new-constraint")]
    public void ZeroArgumentConstructionRestoresTheGenericCallInTheOriginalCoreLibrary(string id)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id);
        using var context = ArtifactContext.Load(Path.Combine(Root, sample.LocalName)); new BabelDetectionPass().Run(context);
        var result = new BabelMethodImagePass().Run(context);
        Assert.True(result.Status == PassStatus.Success && result.Changes == 1, string.Join("; ", result.Diagnostics));
        var owner = context.Module.GetTypes().Single(type => type.Name == "NewBox`1");
        Assert.True(owner.GenericParameters[0].HasDefaultConstructorConstraint);
        var method = owner.Methods.Single(method => method.Name == "Create");
        var call = Assert.Single(method.Body.Instructions.Select(instruction => instruction.Operand).OfType<MethodSpec>());
        Assert.Equal("System.Activator", call.DeclaringType.FullName); Assert.Equal("CreateInstance", call.Name.String);
        Assert.IsType<GenericVar>(Assert.Single(call.GenericInstMethodSig.GenericArguments));
        Assert.Equal(context.Module.CorLibTypes.AssemblyRef.FullName, call.DeclaringType.DefinitionAssembly.FullName);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed);
    }

    [BabelMethodCorpusTheory]
    [InlineData("net48-struct-constraint")]
    [InlineData("net8.0-struct-constraint")]
    [InlineData("net10.0-struct-constraint")]
    public void StructConstrainedBodiesRetainTheirGenericLocalAndConstraint(string id)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id);
        using var context = ArtifactContext.Load(Path.Combine(Root, sample.LocalName));
        new BabelDetectionPass().Run(context);
        var result = new BabelMethodImagePass().Run(context);
        Assert.True(result.Status == PassStatus.Success && result.Changes == 1, string.Join("; ", result.Diagnostics));
        var owner = context.Module.GetTypes().Single(type => type.Name == "StructBox`1");
        Assert.True(owner.GenericParameters[0].HasNotNullableValueTypeConstraint);
        var method = owner.Methods.Single(method => method.Name == "Choose");
        Assert.Contains(method.Body.Variables, local => local.Type is GenericVar { Number: 0 });
        Assert.Contains(method.Body.Instructions, instruction => instruction.OpCode.Code == Code.Initobj);
        Assert.Contains(method.Body.Instructions, instruction => instruction.OpCode.Code == Code.Constrained);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed);
    }

    [BabelMethodCorpusFact]
    public void CapturesMatchRecoveryAndRefusalExpectations()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelGenerics.").FullName;
        try
        {
            var outcome = CorpusRunner.Run(Manifest, Root, directory);
            Assert.True(outcome.Passed == 18 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(sample => sample.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            foreach (var sample in CorpusRunner.LoadManifest(Manifest).Samples.Where(sample => sample.Tier == "profiled" && sample.Id.StartsWith("net48-", StringComparison.Ordinal)))
            {
                var difference = IlVerification.Against(IlVerification.Read(Path.Combine(Root, sample.LocalName)), IlVerification.Read(Path.Combine(directory, sample.Id, "cleaned.bin")));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                Assert.Empty(difference.Worsened);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [BabelMethodCorpusTheory]
    [InlineData("argument")]
    [InlineData("receiver")]
    [InlineData("extra-stack")]
    public void ZeroArgumentStubRequiresExactNullArgumentTransport(string change)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == "net8.0-new-constraint");
        using var context = ArtifactContext.Load(Path.Combine(Root, sample.LocalName));
        var method = context.Module.GetTypes().Single(type => type.Name == "NewBox`1").Methods.Single(method => method.Name == "Create");
        Assert.NotNull(BabelGenericStub.Match(method, _ => true));
        switch (change)
        {
            case "argument": method.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Ldnull).OpCode = OpCodes.Ldarg_0; break;
            case "receiver": method.Body.Instructions.First(instruction => instruction.OpCode.Code == Code.Ldarg_0).OpCode = OpCodes.Ldnull; break;
            case "extra-stack": method.Body.Instructions.Insert(0, OpCodes.Ldc_I4_0.ToInstruction()); break;
        }
        Assert.Null(BabelGenericStub.Match(method, _ => true));
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelEmptyGeneric.").FullName;
        try
        {
            var path = Path.Combine(directory, "BabelGenericProbe.dll");
            context.Module.Write(path);
            using var changed = ArtifactContext.Load(path);
            new BabelDetectionPass().Run(changed);
            var snapshots = changed.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
                .ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new BabelMethodImagePass().Run(changed);
            Assert.Equal(PassStatus.Unsupported, result.Status);
            Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Contains("unsupported argument adaptation", StringComparison.Ordinal));
            Assert.Equal(0, result.Changes);
            Assert.All(snapshots, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
            Assert.Empty(changed.Changes);
        }
        finally { Directory.Delete(directory, true); }
    }
}
