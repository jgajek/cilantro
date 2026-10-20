using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelDelegateNameTests
{
    private static byte[] Sample(string id) => File.ReadAllBytes(SamplePath(id));
    private static string SamplePath(string id)
    {
        var manifest = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-methods.manifest.json"));
        return Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_METHOD_SAMPLES")!,
            manifest.Samples.Single(sample => sample.Id == id).LocalName);
    }

    [BabelMethodCorpusTheory]
    [InlineData("net48-generic-owner")]
    [InlineData("net8.0-generic-owner")]
    [InlineData("net10.0-generic-owner")]
    [InlineData("net48-all")]
    [InlineData("net8.0-all")]
    [InlineData("net10.0-all")]
    public void ReviewedNameConsumersMatchWithoutEditingOriginalBodies(string id)
    {
        var bytes = Sample(id); using var module = ModuleDefMD.Load(bytes);
        var before = module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
            .Select(method => string.Join('\n', method.Body.Instructions)).ToArray();
        var contract = Assert.IsType<BabelDelegateNameContract>(BabelDelegateNameContract.Find(module, bytes));
        Assert.Same(contract.Formatter.DeclaringType, contract.Caller.DeclaringType);
        Assert.Same(contract.Caller.DeclaringType, contract.Builder.DeclaringType);
        Assert.Equal(before, module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
            .Select(method => string.Join('\n', method.Body.Instructions)).ToArray());
    }

    [BabelMethodCorpusTheory]
    [InlineData("formatter")]
    [InlineData("cache")]
    [InlineData("builder")]
    [InlineData("extra-reader")]
    [InlineData("extra-formatter-caller")]
    [InlineData("image-disagreement")]
    [InlineData("field-disagreement")]
    [InlineData("consumer-disagreement")]
    [InlineData("formatter-caller-disagreement")]
    [InlineData("missing-body-disagreement")]
    public void ChangedConsumersDoNotSupplyANameAbstraction(string scenario)
    {
        var bytes = Sample("net8.0-generic-owner"); using var module = ModuleDefMD.Load(bytes);
        var contract = Assert.IsType<BabelDelegateNameContract>(BabelDelegateNameContract.Find(module, bytes));
        switch (scenario)
        {
            case "formatter":
            case "image-disagreement":
                contract.Formatter.Body.Instructions.First(instruction => instruction.OpCode.Code == Code.Ldstr).Operand = "changed"; break;
            case "cache":
                contract.Caller.Body.Instructions.Single(instruction => instruction.Operand is IMethod called && called.Name == "set_Item").OpCode = OpCodes.Call; break;
            case "field-disagreement": contract.Cache.Attributes ^= FieldAttributes.InitOnly; break;
            case "missing-body-disagreement": contract.Formatter.Body = null; break;
            case "builder":
                contract.Builder.Body.Instructions.First(instruction => instruction.OpCode.Code == Code.Ldstr).Operand = "ChangedInvoke"; break;
            case "extra-reader":
            case "consumer-disagreement":
                var reader = new MethodDefUser("ReadName", MethodSig.CreateInstance(module.CorLibTypes.String), MethodAttributes.Private) { Body = new CilBody() };
                contract.Name.DeclaringType.Methods.Add(reader);
                reader.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); reader.Body.Instructions.Add(OpCodes.Ldfld.ToInstruction(contract.Name)); reader.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); break;
            case "extra-formatter-caller":
            case "formatter-caller-disagreement":
                var other = new MethodDefUser("FormatAgain", contract.Formatter.MethodSig.Clone(), MethodAttributes.Static) { Body = new CilBody() };
                contract.Formatter.DeclaringType.Methods.Add(other);
                other.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); other.Body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction());
                other.Body.Instructions.Add(OpCodes.Call.ToInstruction(contract.Formatter)); other.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); break;
        }
        if (scenario is "image-disagreement" or "field-disagreement" or "consumer-disagreement" or "formatter-caller-disagreement" or "missing-body-disagreement")
        { Assert.Null(BabelDelegateNameContract.Find(module, bytes)); return; }
        using var output = new MemoryStream(); module.Write(output); var changed = output.ToArray(); using var changedModule = ModuleDefMD.Load(changed);
        Assert.Null(BabelDelegateNameContract.Find(changedModule, changed));
    }

    [Theory]
    [InlineData("fresh", true)]
    [InlineData("occupied-cache", false)]
    [InlineData("existing-name", false)]
    [InlineData("declared-module", false)]
    [InlineData("wrong-type", false)]
    [InlineData("duplicate", false)]
    public void SummaryRequiresTheCertifiedCallerAndFreshConstructionState(string scenario, bool accepted)
    {
        using var fixture = new Fixture(); var registry = new BabelDelegateNameIntrinsic(fixture.Contract, StaticIntrinsicRegistry.CreateDefault(), "trial");
        var machine = registry.CreateMachine(new StaticMachineLimits()); machine.State.RegisterModuleMetadata(fixture.Module);
        var heap = machine.State.Heap;
        var (receiver, descriptor, packed, module) = fixture.Inputs(machine, registry);
        if (scenario == "occupied-cache")
        {
            Assert.True(heap.TryReadField(receiver, fixture.Contract.Cache, out var cache));
            Assert.True(heap.TryGetModelValue<Dictionary<StaticValue, StaticValue>>(cache, "Entries", out var entries));
            entries![StaticValue.FromInt32(1)] = StaticValue.Null;
        }
        if (scenario == "existing-name") { heap.TryAllocateString("already named", out var name); heap.TryWriteField(descriptor, fixture.Contract.Name, name); }
        if (scenario == "wrong-type") heap.TryWriteArray(packed, 0, StaticValue.Null);
        if (scenario == "declared-module") Assert.True(machine.Execute(fixture.Declare, [module]).Succeeded);
        if (scenario == "duplicate") Assert.True(machine.Execute(fixture.Contract.Caller, [receiver, descriptor, packed]).Succeeded);
        var result = machine.Execute(fixture.Contract.Caller, [receiver, descriptor, packed]); Assert.True(accepted == result.Succeeded, result.Diagnostic);
        Assert.Equal(accepted || scenario == "duplicate" ? 1 : 0,
            machine.State.LoaderEvidence.Observations.Count(item => item.Kind == LoaderObservationKind.ProvedMethodSummary));
        if (accepted) { Assert.True(heap.TryGetString(result.Value, out var key)); Assert.StartsWith("Cilantro.ParametricDelegate.trial.", key); Assert.Equal(1, registry.Summaries); }
    }

    [Fact]
    public void SymbolicCacheAndPrivateFieldMetadataCannotEscapeTheCertifiedCaller()
    {
        using var fixture = new Fixture(); var registry = new BabelDelegateNameIntrinsic(fixture.Contract, StaticIntrinsicRegistry.CreateDefault(), "trial");
        var machine = registry.CreateMachine(new StaticMachineLimits()); var inputs = fixture.Inputs(machine, registry);
        var result = machine.Execute(fixture.Contract.Caller, [inputs.Receiver, inputs.Descriptor, inputs.Packed]); Assert.True(result.Succeeded);
        var heap = machine.State.Heap; Assert.True(heap.TryReadField(inputs.Receiver, fixture.Contract.Cache, out var cache));
        var get = new Importer(fixture.Module).Import(typeof(System.Collections.Hashtable).GetProperty("Item")!.GetMethod!);
        Assert.NotEqual(StaticExecutionStatus.Completed, registry.Invoke(new(machine.State), get, [cache, result.Value]).Status);
        var count = new Importer(fixture.Module).Import(typeof(System.Collections.Hashtable).GetProperty("Count")!.GetMethod!);
        Assert.NotEqual(StaticExecutionStatus.Completed, registry.Invoke(new(machine.State, Frames: [fixture.Contract.Caller]), count, [cache]).Status);
        Assert.True(heap.TryAllocateObject("System.Reflection.FieldInfo", out var info)); heap.TrySetModelValue(info, "Metadata", (IField)fixture.Contract.Name);
        var name = new Importer(fixture.Module).Import(typeof(System.Reflection.MemberInfo).GetProperty("Name")!.GetMethod!);
        Assert.NotEqual(StaticExecutionStatus.Completed, registry.Invoke(new(machine.State), name, [info]).Status);
    }

    [Fact]
    public void AnUnobservedHashtableConstructorDoesNotProveDefaultComparerUse()
    {
        using var fixture = new Fixture(); var registry = new BabelDelegateNameIntrinsic(fixture.Contract, StaticIntrinsicRegistry.CreateDefault(), "trial");
        var machine = registry.CreateMachine(new StaticMachineLimits()); var inputs = fixture.Inputs(machine, registry); var heap = machine.State.Heap;
        Assert.True(heap.TryAllocateObject("System.Collections.Hashtable", out var unproved));
        heap.TrySetModelValue(unproved, "Entries", new Dictionary<StaticValue, StaticValue>()); heap.TryWriteField(inputs.Receiver, fixture.Contract.Cache, unproved);
        Assert.False(machine.Execute(fixture.Contract.Caller, [inputs.Receiver, inputs.Descriptor, inputs.Packed]).Succeeded); Assert.Equal(0, registry.Summaries);
    }

    [Fact]
    public void DirectCallsAndOtherMachinesCannotBorrowCallerOrFreshnessEvidence()
    {
        using var fixture = new Fixture(); var registry = new BabelDelegateNameIntrinsic(fixture.Contract, StaticIntrinsicRegistry.CreateDefault(), "trial");
        var machine = registry.CreateMachine(new StaticMachineLimits()); var inputs = fixture.Inputs(machine, registry);
        var forged = registry.Invoke(new(machine.State, Frames: [fixture.Contract.Caller]), fixture.Contract.Formatter, [StaticValue.Null, inputs.Packed]);
        Assert.NotEqual(StaticExecutionStatus.Completed, forged.Status);
        var foreign = registry.Invoke(new(new StaticMachine().State), fixture.Contract.Formatter, []); Assert.NotEqual(StaticExecutionStatus.Completed, foreign.Status);
        Assert.Throws<InvalidOperationException>(() => registry.CreateMachine(new StaticMachineLimits()));
    }

    [Fact]
    public void IndependentFreshModulesReceiveDistinctNames()
    {
        using var fixture = new Fixture(); var registry = new BabelDelegateNameIntrinsic(fixture.Contract, StaticIntrinsicRegistry.CreateDefault(), "trial");
        var machine = registry.CreateMachine(new StaticMachineLimits()); var first = fixture.Inputs(machine, registry); var second = fixture.Inputs(machine, registry);
        var left = machine.Execute(fixture.Contract.Caller, [first.Receiver, first.Descriptor, first.Packed]);
        var right = machine.Execute(fixture.Contract.Caller, [second.Receiver, second.Descriptor, second.Packed]); Assert.True(left.Succeeded); Assert.True(right.Succeeded);
        Assert.True(machine.State.Heap.TryGetString(left.Value, out var a)); Assert.True(machine.State.Heap.TryGetString(right.Value, out var b)); Assert.NotEqual(a, b);
    }

    [Fact]
    public void SummaryPreservesTypeInitializationAndNormalArgumentValidation()
    {
        using var fixture = new Fixture(); var owner = fixture.Contract.Formatter.DeclaringType;
        var field = new FieldDefUser("Initialized", new FieldSig(fixture.Module.CorLibTypes.Int32), FieldAttributes.Static); owner.Fields.Add(field);
        var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(fixture.Module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() }; owner.Methods.Add(initializer);
        initializer.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); initializer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field)); initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var registry = new BabelDelegateNameIntrinsic(fixture.Contract, StaticIntrinsicRegistry.CreateDefault(), "trial"); var machine = registry.CreateMachine(new StaticMachineLimits());
        machine.State.RegisterModuleMetadata(fixture.Module); var inputs = fixture.Inputs(machine, registry);
        Assert.True(machine.Execute(fixture.Contract.Caller, [inputs.Receiver, inputs.Descriptor, inputs.Packed]).Succeeded);
        Assert.Equal(1, machine.State.ReadStaticField(field).AsInt32());
        Assert.Single(machine.State.LoaderEvidence.Observations, item => item.Kind == LoaderObservationKind.ProvedMethodSummary);
        var invalid = machine.Execute(fixture.Contract.Formatter, []); Assert.Equal(StaticExecutionStatus.InvalidProgram, invalid.Status); Assert.Equal(1, registry.Summaries);
    }

    [BabelMethodCorpusTheory]
    [InlineData("net48-generic-owner")]
    [InlineData("net8.0-generic-owner")]
    [InlineData("net10.0-generic-owner")]
    [InlineData("net48-all")]
    [InlineData("net8.0-all")]
    [InlineData("net10.0-all")]
    public void CertifiedFreshNamesAllowTheOriginalDecoderToPreserveOpenTypeOperands(string id)
    {
        var bytes = Sample(id); using var context = ArtifactContext.Load(SamplePath(id));
        new BabelDetectionPass().Run(context); new BabelCheckPass().Run(context);
        var contract = Assert.IsType<BabelDelegateNameContract>(BabelDelegateNameContract.Find(context.Module, bytes));
        var stub = context.Module.GetTypes().Single(type => type.Name == "Box`1").Methods.Single(method => method.Name == "Exchange");
        var original = stub.Body.Instructions.Select(instruction => instruction.ToString()).ToArray();
        foreach (var label in new[] { "first", "second" })
        {
            var raw = new RawDynamicMethodIntrinsic(); var parametric = new ParametricTypeIntrinsic(stub.DeclaringType, raw);
            var names = new BabelDelegateNameIntrinsic(contract, parametric, label); var machine = names.CreateMachine(BootstrapMachine.Limits(4_000_000)); parametric.Attach(machine);
            Assert.True(BootstrapMachine.TryTell(context, machine, out var why), why);
            if (context.TryGetFact<HashSet<uint>>(BabelCheckPass.NeutralizedFact, out var guards) && guards is not null)
                foreach (var guard in guards) machine.State.RegisterNeutralizedMethod(guard);
            var heap = machine.State.Heap; var owner = parametric.Owner.ToTypeDefOrRef();
            Assert.True(heap.TryAllocateObject(owner.FullName, out var receiver));
            Assert.True(heap.TryAllocateObject("System.Reflection.MethodInfo", out var method)); heap.TrySetModelValue(method, "Metadata", (IMethod)new MemberRefUser(context.Module, stub.Name, stub.MethodSig, owner));
            var input = machine.State.Provenance.Origin(StaticValue.Unknown, ProvenanceKind.Argument, "descriptor-only input", "T");
            Assert.True(heap.TryAllocateArray(context.Module.CorLibTypes.Object, 1, out var packed)); heap.TryWriteArray(packed, 0, input);
            var dispatch = stub.Body.Instructions.Select(instruction => instruction.Operand).OfType<IMethod>().Single(called => called.MethodSig.Params.Count == 4 && called.MethodSig.Params[0].ElementType == ElementType.I4);
            var index = stub.Body.Instructions.Where(instruction => instruction.IsLdcI4()).Last().GetLdcI4Value();
            MethodDef? captured = null;
            raw.Invoking = (capture, supplied) =>
            {
                captured = capture.Assembled; Assert.Equal(receiver, supplied[0]); Assert.Equal(input, supplied[1]);
                Assert.Same(parametric.Variables[0], capture.Returns); Assert.Same(parametric.Variables[0], capture.Parameters[1]);
                Assert.True(parametric.Contains(Assert.IsType<GenericInstSig>(capture.Parameters[0]))); throw new Captured();
            };
            if (context.Module.GlobalType.FindStaticConstructor() is { } startup) Assert.True(machine.Execute(startup).Succeeded);
            StaticExecutionResult? failure = null;
            var stopped = Record.Exception(() => { failure = machine.Invoke(dispatch, [StaticValue.FromInt32(index), method, receiver, packed]); });
            Assert.True(stopped is Captured, failure?.Diagnostic ?? stopped?.ToString());
            Assert.NotNull(captured); Assert.Equal(1, names.Summaries);
            Assert.Equal(new[] { Code.Ldarg_0, Code.Ldfld, Code.Ldarg_0, Code.Ldarg_1, Code.Stfld, Code.Ret }, captured.Body.Instructions.Select(instruction => instruction.OpCode.Code));
            Assert.All(captured.Body.Instructions.Select(instruction => instruction.Operand).OfType<IField>(), field => Assert.IsType<GenericVar>(field.FieldSig.Type));
            Assert.All(captured.Body.Instructions.Select(instruction => instruction.Operand).OfType<IField>(), field => Assert.True(parametric.Contains(field.DeclaringType.ToTypeSig())));
        }
        // This test proves the decoder/name abstraction, not the source stub's boxing or receiver
        // adaptation. Production recovery still refuses this fixture until those proofs exist.
        Assert.Equal(original, stub.Body.Instructions.Select(instruction => instruction.ToString()).ToArray());
    }

    private sealed class Captured : Exception;

    private sealed class Fixture : IDisposable
    {
        internal ModuleDefUser Module { get; } = new("NameContract");
        internal BabelDelegateNameContract Contract { get; }
        internal MethodDef Declare { get; }
        internal Fixture()
        {
            var module = Module; var factory = new TypeDefUser("Probe", "Factory", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(factory);
            var descriptor = new TypeDefUser("Probe", "Descriptor", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(descriptor);
            var type = new ClassSig(module.CorLibTypes.GetTypeRef("System", "Type")); var parameters = new SZArraySig(type);
            var name = new FieldDefUser("Name", new FieldSig(module.CorLibTypes.String)); descriptor.Fields.Add(name);
            var cache = new FieldDefUser("Cache", new FieldSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections", "Hashtable")))); factory.Fields.Add(cache);
            var builder = new ClassSig(module.CorLibTypes.GetTypeRef("System.Reflection.Emit", "ModuleBuilder")); var emitted = new FieldDefUser("Module", new FieldSig(builder)); factory.Fields.Add(emitted);
            var formatter = new MethodDefUser("Format", MethodSig.CreateStatic(module.CorLibTypes.String, type, parameters), MethodAttributes.Static) { Body = new CilBody() };
            factory.Methods.Add(formatter); formatter.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); formatter.Body.Instructions.Add(OpCodes.Throw.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateInstance(module.CorLibTypes.String, new ClassSig(descriptor), parameters)) { Body = new CilBody() }; factory.Methods.Add(caller);
            caller.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(new Importer(module).Import(typeof(Type).GetMethod("GetTypeFromHandle")!)));
            caller.Body.Instructions.Add(OpCodes.Ldarg_2.ToInstruction()); caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(formatter)); caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            Declare = new MethodDefUser("Declare", MethodSig.CreateStatic(module.CorLibTypes.Void, builder), MethodAttributes.Static) { Body = new CilBody() }; factory.Methods.Add(Declare);
            Declare.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); Declare.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("PriorType"));
            Declare.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new Importer(module).Import(typeof(System.Reflection.Emit.ModuleBuilder).GetMethod("DefineType", [typeof(string)])!)));
            Declare.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); Declare.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            Contract = new(formatter, caller, caller, cache, emitted, name);
        }
        internal (StaticValue Receiver, StaticValue Descriptor, StaticValue Packed, StaticValue Module) Inputs(StaticMachine machine, BabelDelegateNameIntrinsic registry)
        {
            var heap = machine.State.Heap;
            Assert.True(heap.TryAllocateObject(Contract.Caller.DeclaringType.FullName, out var receiver));
            Assert.True(heap.TryAllocateObject(Contract.Name.DeclaringType.FullName, out var descriptor)); heap.TryWriteField(descriptor, Contract.Name, StaticValue.Null);
            Assert.True(heap.TryAllocateObject("System.Collections.Hashtable", out var cache)); Assert.Equal(StaticExecutionStatus.Completed, registry.Invoke(new(machine.State), new Importer(Module).Import(typeof(System.Collections.Hashtable).GetConstructor(Type.EmptyTypes)!), [cache]).Status);
            Assert.True(heap.TryAllocateObject("System.Reflection.Emit.ModuleBuilder", out var module)); heap.TryWriteField(receiver, Contract.Cache, cache); heap.TryWriteField(receiver, Contract.Module, module);
            Assert.True(heap.TryAllocateArray(null, 1, out var packed)); Assert.True(heap.TryAllocateObject("System.Type", out var type)); heap.TrySetModelValue(type, "Metadata", Module.CorLibTypes.Int32);
            heap.TryWriteArray(packed, 0, type); return (receiver, descriptor, packed, module);
        }
        public void Dispose() => Module.Dispose();
    }
}
