using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelNumericArrayTests
{
    private static string Sample(string id)
    {
        var manifest = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-baseline.manifest.json"));
        return Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!, manifest.Samples.Single(sample => sample.Id == id).LocalName);
    }

    [Babel12CorpusTheory]
    [InlineData("net48-values")]
    [InlineData("net8.0-values")]
    [InlineData("net10.0-values")]
    public void LiteralRecoveryRetiresTheLastNumericConsumerAndItsTable(string id)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        Assert.Equal(28, new NumericTableRecoveryPass().Run(context).Changes);
        var factory = Assert.Single(BabelNumericArrayShape.Find(context.Module)).Factory;
        var result = new BabelNumericArrayPass().Run(context);
        Assert.True(result.Changes == 1, string.Join("; ", result.Diagnostics));
        Assert.DoesNotContain(context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).SelectMany(method => method.Body.Instructions),
            instruction => (instruction.Operand as IMethod)?.ResolveMethodDef() == factory);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed);
        Assert.True(context.TryGetFact<IReadOnlyList<RetiredBabelArrayData>>(RetiredBabelArrayData.Fact, out var proofs));
        var proof = Assert.Single(proofs!);
        var otherData = context.Module.GetTypes().SelectMany(type => type.Fields).Where(field => field.HasFieldRVA && field != proof.Source).ToArray();
        Assert.Equal(PassStatus.Success, new BabelNumericArrayCleanupPass().Run(context).Status);
        Assert.DoesNotContain(proof.Source, context.Module.GetTypes().SelectMany(type => type.Fields));
        Assert.DoesNotContain(proof.Storage, context.Module.GetTypes());
        Assert.All(otherData, field => Assert.Contains(field, context.Module.GetTypes().SelectMany(type => type.Fields)));
        Assert.Equal(1, new ProtectorResourceCleanupPass().Run(context).Changes);
        Assert.Equal("BabelProbe.Secret.txt", Assert.Single(context.Module.Resources).Name.String);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed);
    }

    [Babel12CorpusTheory]
    [InlineData("net48-values", false, false)]
    [InlineData("net8.0-values", false, false)]
    [InlineData("net10.0-values", false, false)]
    [InlineData("net8.0-values", true, false)]
    [InlineData("net8.0-values", false, true)]
    public void ReviewedDormantCodecHelpersRetireUnlessApplicationCodeStillUsesThem(string id, bool live, bool liveLayout)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        var runtime = Assert.Single(BabelNumericArrayShape.Find(context.Module));
        var graph = GeneratedRuntimeShape.Read(runtime.Codec);
        var helper = Assert.Single(graph.Types, type => type.Fields.Count == 2 && type.Fields.Any(field => field.FieldType.FullName == "System.Int32[]") &&
            type.Fields.Any(field => field.FieldType.ElementType == ElementType.I4));
        var layouts = graph.Types.Where(type => type.IsValueType && type.Methods.Count == 0).ToArray();
        Assert.NotEmpty(layouts);
        var application = new TypeDefUser("Probe", "UnusedApplicationPair", context.Module.CorLibTypes.GetTypeRef("System", "ValueType"))
            { Attributes = TypeAttributes.Sealed | TypeAttributes.SequentialLayout };
        application.Fields.Add(new FieldDefUser("First", new FieldSig(context.Module.CorLibTypes.Int32), FieldAttributes.Public));
        application.Fields.Add(new FieldDefUser("Second", new FieldSig(context.Module.CorLibTypes.Int32), FieldAttributes.Public));
        if (live)
        {
            var main = context.Module.EntryPoint;
            main.Body.Instructions.Insert(0, OpCodes.Newobj.ToInstruction(helper.FindInstanceConstructors().Single()));
            main.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        if (liveLayout)
        {
            context.Module.EntryPoint.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(layouts[0]));
            context.Module.EntryPoint.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        Assert.Equal(28, new NumericTableRecoveryPass().Run(context).Changes);
        Assert.Equal(1, new BabelNumericArrayPass().Run(context).Changes);
        context.Module.Types.Add(application);
        Assert.Contains(helper.MDToken.Raw, RecoveryOrphans.TypesOf(context));
        Assert.All(helper.Methods, method => Assert.Contains(method.MDToken.Raw, RecoveryOrphans.Of(context)));
        Assert.Equal(PassStatus.Success, new BabelNumericArrayCleanupPass().Run(context).Status);
        Assert.Equal(live, context.Module.GetTypes().Contains(helper));
        Assert.All(layouts, layout => Assert.Equal(liveLayout && layout == layouts[0], context.Module.GetTypes().Contains(layout)));
        Assert.Contains(application, context.Module.GetTypes());
    }

    [Babel12CorpusTheory]
    [InlineData("source-bytes")]
    [InlineData("source-flags")]
    [InlineData("source-name")]
    [InlineData("layout")]
    [InlineData("replacement-body")]
    [InlineData("replacement-data")]
    [InlineData("replacement-layout")]
    [InlineData("replacement-flags")]
    [InlineData("live-field")]
    [InlineData("reflected-owner")]
    [InlineData("numeric-token")]
    public void EncryptedRvaRetirementRequiresIntactReplacementAndNoConsumers(string change)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-values"));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        Assert.Equal(28, new NumericTableRecoveryPass().Run(context).Changes);
        Assert.Equal(1, new BabelNumericArrayPass().Run(context).Changes);
        Assert.True(context.TryGetFact<IReadOnlyList<RetiredBabelArrayData>>(RetiredBabelArrayData.Fact, out var proofs));
        var proof = Assert.Single(proofs!);
        var caller = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Main");
        switch (change)
        {
            case "source-bytes": proof.Source.InitialValue[0] ^= 1; break;
            case "source-flags": proof.Source.Attributes ^= FieldAttributes.InitOnly; break;
            case "source-name": proof.Source.Name += "changed"; break;
            case "layout": proof.Storage.ClassLayout.ClassSize++; break;
            case "replacement-body": caller.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction()); break;
            case "replacement-data":
                context.Module.GetTypes().Single(type => type.Namespace == "Cilantro.Recovered").Fields.Single().InitialValue[0] ^= 1; break;
            case "replacement-layout":
                context.Module.GetTypes().Single(type => type.Namespace == "Cilantro.Recovered").ClassLayout.ClassSize++; break;
            case "replacement-flags": caller.Attributes ^= MethodAttributes.Static; break;
            case "live-field" or "reflected-owner" or "numeric-token":
                var consumer = new TypeDefUser("Tests", "ArrayConsumer", context.Module.CorLibTypes.Object.TypeDefOrRef)
                    { Attributes = TypeAttributes.Public };
                context.Module.Types.Add(consumer);
                var signature = change == "numeric-token"
                    ? MethodSig.CreateStatic(context.Module.CorLibTypes.Void, new ClassSig(context.Module.CorLibTypes.GetTypeRef("System.Reflection", "Module")))
                    : MethodSig.CreateStatic(context.Module.CorLibTypes.Void);
                var read = new MethodDefUser("Read", signature, MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
                consumer.Methods.Add(read);
                if (change == "numeric-token")
                {
                    var resolve = new Importer(context.Module).Import(typeof(System.Reflection.Module).GetMethod("ResolveField", [typeof(int)])!);
                    read.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                    read.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction((int)proof.Source.MDToken.Raw));
                    read.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(resolve));
                }
                else read.Body.Instructions.Add(change == "live-field" ? OpCodes.Ldtoken.ToInstruction(proof.Source) : OpCodes.Ldtoken.ToInstruction(proof.Source.DeclaringType));
                read.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                Assert.True(proof.IsPreserved(context.Module));
                break;
        }
        new BabelNumericArrayCleanupPass().Run(context);
        Assert.Contains(proof.Source, context.Module.GetTypes().SelectMany(type => type.Fields));
        Assert.Contains(proof.Storage, context.Module.GetTypes());
    }

    [Babel12CorpusFact]
    public void SharedRvaLayoutAndUnattributedDataSurviveFieldRetirement()
    {
        using var context = ArtifactContext.Load(Sample("net8.0-values"));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        new NumericTableRecoveryPass().Run(context);
        Assert.Equal(1, new BabelNumericArrayPass().Run(context).Changes);
        Assert.True(context.TryGetFact<IReadOnlyList<RetiredBabelArrayData>>(RetiredBabelArrayData.Fact, out var proofs));
        var proof = Assert.Single(proofs!);
        var shared = new FieldDefUser("ApplicationRva", new FieldSig(proof.Source.FieldType), proof.Source.Attributes)
            { InitialValue = proof.Source.InitialValue.ToArray() };
        proof.Source.DeclaringType.Fields.Add(shared);
        var holder = context.Module.GetTypes().Single(type => type.Methods.Any(method => method.Name == "Main"));
        var consumer = new MethodDefUser("KeepArrayData", MethodSig.CreateStatic(context.Module.CorLibTypes.Void),
            MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
        consumer.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(proof.Source));
        consumer.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); consumer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        holder.Methods.Add(consumer);
        new BabelNumericArrayCleanupPass().Run(context);
        Assert.Contains(proof.Source, context.Module.GetTypes().SelectMany(type => type.Fields));
        consumer.Body.Instructions.Clear(); consumer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        context.TryGetFact<int>("cleanup.removedFieldCount", out var earlierFields);
        context.TryGetFact<int>("cleanup.removedTypeCount", out var earlierTypes);
        context.TryGetFact<int>("cleanup.removedMethodCount", out var earlierMethods);
        new BabelNumericArrayCleanupPass().Run(context);
        Assert.DoesNotContain(proof.Source, context.Module.GetTypes().SelectMany(type => type.Fields));
        Assert.Contains(shared, context.Module.GetTypes().SelectMany(type => type.Fields));
        Assert.Contains(proof.Storage, context.Module.GetTypes());
        Assert.True(context.TryGetFact<int>("cleanup.removedFieldCount", out var removedFields));
        Assert.Equal(earlierFields + 1, removedFields);
        context.TryGetFact<int>("cleanup.removedTypeCount", out var removedTypes);
        context.TryGetFact<int>("cleanup.removedMethodCount", out var removedMethods);
        Assert.Equal(earlierTypes, removedTypes); Assert.Equal(earlierMethods, removedMethods);
        var fields = context.Module.GetTypes().SelectMany(type => type.Fields).Count();
        new BabelNumericArrayCleanupPass().Run(context);
        Assert.Equal(fields, context.Module.GetTypes().SelectMany(type => type.Fields).Count());
    }

    [Babel12CorpusTheory]
    [InlineData("read")]
    [InlineData("write")]
    [InlineData("corrupt-input")]
    [InlineData("entry")]
    [InlineData("foreign-byte-type")]
    [InlineData("rva-size")]
    public void ChangedGraphsAndUnboundLiteralInputsRemainIntact(string change)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelArrayRefusal.").FullName;
        try
        {
            var path = Path.Combine(directory, "BabelProbe.dll");
            using (var module = ModuleDefMD.Load(Sample("net8.0-values")))
            {
                var runtime = Assert.Single(BabelNumericArrayShape.Find(module));
                if (change is "read" or "write")
                {
                    var field = module.GetTypes().SelectMany(type => type.Fields).Single(field => field.Name == "calls");
                    runtime.Factory.Body.Instructions.Insert(0, change == "read" ? OpCodes.Ldsfld.ToInstruction(field) : OpCodes.Ldc_I4_7.ToInstruction());
                    runtime.Factory.Body.Instructions.Insert(1, change == "read" ? OpCodes.Pop.ToInstruction() : OpCodes.Stsfld.ToInstruction(field));
                }
                else
                {
                    var caller = module.GetTypes().SelectMany(type => type.Methods).Single(method => method.HasBody && method.Body.Instructions.Any(instruction =>
                        (instruction.Operand as IMethod)?.ResolveMethodDef() == runtime.Factory));
                    var at = caller.Body.Instructions.IndexOf(caller.Body.Instructions.Single(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef() == runtime.Factory));
                    if (change == "foreign-byte-type")
                        caller.Body.Instructions[at - 4].Operand = new TypeRefUser(module, "System", "Byte", new AssemblyRefUser("Foreign"));
                    else if (change == "rva-size")
                        ((IField)caller.Body.Instructions[at - 2].Operand).ResolveFieldDef().FieldType.ToTypeDefOrRef().ResolveTypeDef().ClassLayout.ClassSize--;
                    else if (change == "corrupt-input")
                        ((IField)caller.Body.Instructions[at - 2].Operand).ResolveFieldDef().InitialValue = new byte[117];
                    else
                    {
                        var duplicate = caller.Body.Instructions[at - 3];
                        caller.Body.Instructions.Insert(0, OpCodes.Ldnull.ToInstruction());
                        caller.Body.Instructions.Insert(1, OpCodes.Br.ToInstruction(duplicate));
                    }
                }
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
            new NumericTableRecoveryPass().Run(context);
            var changes = context.Changes.Count;
            var bodies = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var count = context.Module.GetTypes().Count();
            Assert.Equal(0, new BabelNumericArrayPass().Run(context).Changes);
            Assert.Equal(count, context.Module.GetTypes().Count());
            Assert.All(bodies, item => Assert.True(item.Value.StructurallyEquals(item.Key)));
            Assert.Equal(changes, context.Changes.Count);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Babel12CorpusFact]
    public void PrivateCacheIdentityChangesAreNotHiddenByEqualArrayContents()
    {
        using var context = ArtifactContext.Load(Sample("net8.0-values"));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        Assert.Equal(28, new NumericTableRecoveryPass().Run(context).Changes);
        var runtime = Assert.Single(BabelNumericArrayShape.Find(context.Module));
        var owner = runtime.Reader.DeclaringType;
        var holder = owner.Fields.Single(field => field.IsStatic && field.FieldType.FullName == owner.FullName);
        var array = owner.Fields.Single(field => !field.IsStatic && field.FieldType.FullName == "System.Int32[]");
        var local = new Local(new SZArraySig(context.Module.CorLibTypes.Int32));
        runtime.Factory.Body.Variables.Add(local); runtime.Factory.Body.InitLocals = true;
        var at = runtime.Factory.Body.Instructions.IndexOf(runtime.Factory.Body.Instructions.Last(instruction => instruction.OpCode.Code == Code.Ret));
        Instruction[] mutation = [OpCodes.Dup.ToInstruction(), OpCodes.Castclass.ToInstruction(new TypeSpecUser(local.Type)),
            OpCodes.Stloc.ToInstruction(local), OpCodes.Ldsfld.ToInstruction(holder), OpCodes.Ldloc.ToInstruction(local), OpCodes.Stfld.ToInstruction(array)];
        foreach (var instruction in mutation) runtime.Factory.Body.Instructions.Insert(at++, instruction);
        var before = MethodBodySnapshot.Capture(runtime.Factory);
        var result = new BabelNumericArrayPass().Run(context);
        Assert.Equal(0, result.Changes);
        Assert.True(result.Diagnostics.Any(note => note.Contains("post-initialization effects", StringComparison.Ordinal)), string.Join("; ", result.Diagnostics));
        Assert.True(before.StructurallyEquals(runtime.Factory));
    }

    [Babel12CorpusFact]
    public void KeepingRuntimePreservesArrayCallsAndMetadata()
    {
        using var context = ArtifactContext.Load(Sample("net8.0-values"));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", false);
        var count = context.Module.GetTypes().Count();
        Assert.Equal(0, new BabelNumericArrayPass().Run(context).Changes);
        Assert.Equal(count, context.Module.GetTypes().Count()); Assert.Empty(context.Changes);
    }

    [Theory]
    [InlineData("System.Boolean", "0001")]
    [InlineData("System.SByte", "807f")]
    [InlineData("System.Byte", "00ff")]
    [InlineData("System.Int16", "0080ff7f")]
    [InlineData("System.UInt16", "0000ffff")]
    [InlineData("System.Char", "0000ffff")]
    [InlineData("System.Int32", "00000080ffffff7f")]
    [InlineData("System.UInt32", "00000000ffffffff")]
    [InlineData("System.Int64", "0000000000000080ffffffffffffff7f")]
    [InlineData("System.UInt64", "0000000000000000ffffffffffffffff")]
    [InlineData("System.Single", "000000802301c07f")]
    [InlineData("System.Double", "0000000000000080230100000000f87f")]
    [InlineData("System.Int32", "")]
    public void MaterializedArraysPreservePrimitiveBitsAndFreshMutableIdentity(string element, string hex)
    {
        // Execute only a source-built literal emitter, never a protected sample.
        using var context = SyntheticContext.Build(module => SyntheticContext.AddType(module, "Host"));
        var module = context.Module; var host = module.Types.Single(type => type.Name == "Host"); host.Visibility = TypeAttributes.Public;
        var type = Element(module, element); var bytes = Convert.FromHexString(hex);
        var width = element is "System.Boolean" or "System.Byte" or "System.SByte" ? 1 : element is "System.Int16" or "System.UInt16" or "System.Char" ? 2 :
            element is "System.Int64" or "System.UInt64" or "System.Double" ? 8 : 4;
        FieldDef? field = null;
        if (bytes.Length != 0)
        {
            var data = new TypeDefUser("Synthetic", "Data", module.CorLibTypes.GetTypeRef("System", "ValueType"))
                { Attributes = TypeAttributes.NotPublic | TypeAttributes.ExplicitLayout | TypeAttributes.Sealed, ClassLayout = new ClassLayoutUser(1, (uint)bytes.Length) };
            field = new FieldDefUser("Bytes", new FieldSig(new ValueTypeSig(data)), FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.InitOnly | FieldAttributes.HasFieldRVA)
                { InitialValue = bytes }; data.Fields.Add(field); module.Types.Add(data);
        }
        var run = new MethodDefUser("Run", MethodSig.CreateStatic(new SZArraySig(type)), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
        host.Methods.Add(run);
        foreach (var instruction in BabelNumericArrayPass.Materialize(module, new(element, bytes.Length / width, bytes), field)) run.Body.Instructions.Add(instruction);
        run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        using var stream = new MemoryStream(); module.Write(stream); stream.Position = 0;
        var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), true);
        try
        {
            var loaded = loader.LoadFromStream(stream).GetType(host.FullName)!.GetMethod("Run")!;
            var first = Assert.IsAssignableFrom<Array>(loaded.Invoke(null, null));
            var second = Assert.IsAssignableFrom<Array>(loaded.Invoke(null, null));
            Assert.NotSame(first, second); Assert.Equal(element, first.GetType().GetElementType()!.FullName);
            var actual = new byte[Buffer.ByteLength(first)]; Buffer.BlockCopy(first, 0, actual, 0, actual.Length); Assert.Equal(bytes, actual);
            if (first.Length != 0) first.SetValue(Activator.CreateInstance(first.GetType().GetElementType()!), 0);
            var again = Assert.IsAssignableFrom<Array>(loaded.Invoke(null, null));
            var restored = new byte[Buffer.ByteLength(again)]; Buffer.BlockCopy(again, 0, restored, 0, restored.Length); Assert.Equal(bytes, restored);
        }
        finally { loader.Unload(); }
    }

    [Fact]
    public void PrimitiveNamesOnLocalEnumsDoNotBecomeBuiltinArrayTypes()
    {
        using var module = new ModuleDefUser("array-types");
        var fake = new TypeDefUser("System", "Int32", module.CorLibTypes.GetTypeRef("System", "Enum"));
        fake.Fields.Add(new FieldDefUser("value__", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.SpecialName | FieldAttributes.RTSpecialName));
        module.Types.Add(fake);
        var machine = new StaticMachine();
        Assert.True(machine.State.Heap.TryAllocateArray(new ValueTypeSig(fake), 1, out var array));
        Assert.True(machine.State.Heap.TryGetArrayElementType(array, out var name)); Assert.Equal("System.Int32", name);
        Assert.False(BabelNumericArrayPass.TrySnapshot(machine, module, array, out _));
        Assert.True(machine.State.Heap.TryCloneArray(array, out var clone));
        Assert.False(machine.State.Heap.HasPrimitiveArrayElement(clone));
    }

    private static CorLibTypeSig Element(ModuleDef module, string name) => name switch
    {
        "System.Boolean" => module.CorLibTypes.Boolean, "System.SByte" => module.CorLibTypes.SByte, "System.Byte" => module.CorLibTypes.Byte,
        "System.Int16" => module.CorLibTypes.Int16, "System.UInt16" => module.CorLibTypes.UInt16, "System.Char" => module.CorLibTypes.Char,
        "System.Int32" => module.CorLibTypes.Int32, "System.UInt32" => module.CorLibTypes.UInt32, "System.Int64" => module.CorLibTypes.Int64,
        "System.UInt64" => module.CorLibTypes.UInt64, "System.Single" => module.CorLibTypes.Single, _ => module.CorLibTypes.Double
    };
}
