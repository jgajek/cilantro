using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelHashStringTests
{
    private static string Sample(string id)
    {
        var manifest = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-baseline.manifest.json"));
        return Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!, manifest.Samples.Single(sample => sample.Id == id).LocalName);
    }

    [Babel12CorpusTheory]
    [InlineData("net8.0-strings-hash")]
    [InlineData("net10.0-strings-hash")]
    [InlineData("net8.0-combined")]
    [InlineData("net10.0-combined")]
    public void CompleteCacheIsMaterializedWithoutChangingItsLookup(string id)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        if (id.EndsWith("combined", StringComparison.Ordinal))
            Assert.Equal(PassStatus.Success, new BabelResourceRestorationPass().Run(context).Status);
        var cache = Assert.Single(BabelHashStringShape.Find(context.Module));
        var codecTypes = GeneratedRuntimeShape.Read(cache.StreamDecoder).Types;
        var getter = MethodBodySnapshot.Capture(cache.Getter);
        var result = new BabelHashStringPass().Run(context);
        Assert.True(result.Status == PassStatus.Success, string.Join("; ", result.Diagnostics));
        Assert.Equal(id.EndsWith("combined", StringComparison.Ordinal) ? 6 : 7, result.Changes);
        Assert.True(getter.StructurallyEquals(cache.Getter));
        Assert.DoesNotContain(cache.Constructor.Body.Instructions, instruction => instruction.OpCode.Code == Code.Ldstr || instruction.Operand is IMethod called && called.Name == "GetManifestResourceStream");
        Assert.Contains(cache.Constructor.Body.Instructions, instruction => instruction.Operand is IMethod called && called.FullName == "System.Void System.String::.ctor(System.Char[])");
        Assert.Equal(3, cache.Initializer.Body.Instructions.Count);
        Assert.All(codecTypes, type => Assert.Contains(type.MDToken.Raw, RecoveryOrphans.TypesOf(context)));
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed);
        if (id.EndsWith("strings-hash", StringComparison.Ordinal))
        {
            var layouts = codecTypes.Where(type => type.IsValueType && type.Methods.Count == 0).ToArray(); Assert.NotEmpty(layouts);
            Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
            Assert.DoesNotContain(layouts, layout => context.Module.GetTypes().Contains(layout));
            Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed);
        }
    }

    [Babel12CorpusTheory]
    [InlineData("getter")]
    [InlineData("foreign-write")]
    [InlineData("foreign-call")]
    [InlineData("layout")]
    public void ChangedRuntimeDeclinesWithoutMutation(string change)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelHashRefusal.").FullName;
        try
        {
            var path = Path.Combine(directory, "BabelProbe.dll");
            using (var module = ModuleDefMD.Load(Sample("net8.0-strings-hash")))
            {
                var cache = Assert.Single(BabelHashStringShape.Find(module));
                if (change == "getter") cache.Getter.Body.Instructions.Insert(0, OpCodes.Break.ToInstruction());
                if (change == "foreign-write")
                {
                    var field = module.GetTypes().SelectMany(type => type.Fields).Single(field => field.Name == "calls");
                    cache.StreamDecoder.Body.Instructions.Insert(0, OpCodes.Ldc_I4_7.ToInstruction());
                    cache.StreamDecoder.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(field));
                }
                if (change == "foreign-call")
                {
                    var gc = new TypeRefUser(module, "System", "GC", module.CorLibTypes.AssemblyRef);
                    cache.StreamDecoder.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(new MemberRefUser(module, "Collect", MethodSig.CreateStatic(module.CorLibTypes.Void), gc)));
                }
                if (change == "layout")
                {
                    var layout = GeneratedRuntimeShape.Read(cache.StreamDecoder).Types.First(type => type.IsValueType && type.Methods.Count == 0);
                    layout.ClassLayout = new ClassLayoutUser(1, 16);
                }
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
            var bodies = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new BabelHashStringPass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status); Assert.Equal(0, result.Changes);
            Assert.All(bodies, item => Assert.True(item.Value.StructurallyEquals(item.Key)));
            Assert.Empty(context.Changes);
            Assert.Empty(RecoveryOrphans.TypesOf(context));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Babel12CorpusFact]
    public void RuntimeRetentionPreservesEncryptedConstruction()
    {
        using var context = ArtifactContext.Load(Sample("net8.0-strings-hash"));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", false);
        var cache = Assert.Single(BabelHashStringShape.Find(context.Module));
        var before = MethodBodySnapshot.Capture(cache.Constructor);
        Assert.Equal(0, new BabelHashStringPass().Run(context).Changes);
        Assert.True(before.StructurallyEquals(cache.Constructor));
    }

    [Babel12CorpusFact]
    public void MaterializedStringsPreserveAliasingInterningUtf16AndUnknownKeyExceptions()
    {
        // Execute only the source-built benign probe with explicitly supplied table data.
        using var module = ModuleDefMD.Load(Sample("net8.0-strings-hash"));
        var cache = Assert.Single(BabelHashStringShape.Find(module));
        var text = "CilantroHashIdentity_" + Guid.NewGuid().ToString("N") + "\ud800";
        Assert.Null(string.IsInterned(text));
        cache.Constructor.Body = BabelHashStringPass.BuildConstructor(cache,
            [new(1, text, 0), new(2, text, 1), new(3, text, 0), new(4, "", 2)]);
        cache.Initializer.Body = new CilBody();
        cache.Initializer.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(cache.Constructor));
        cache.Initializer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(cache.Singleton));
        cache.Initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        using var stream = new MemoryStream(); module.Write(stream); stream.Position = 0;
        var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), true);
        try
        {
            var assembly = loader.LoadFromStream(stream);
            var type = assembly.GetType(cache.Wrapper.DeclaringType.FullName)!;
            var lookup = type.GetMethod(cache.Wrapper.Name, System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic)!;
            object? Read(int key) => lookup.Invoke(null, [key]);
            var first = Assert.IsType<string>(Read(1));
            Assert.Equal(text, first); Assert.Same(first, Read(1)); Assert.Same(first, Read(3));
            Assert.Equal(first, Read(2)); Assert.NotSame(first, Read(2)); Assert.Null(string.IsInterned(first));
            Assert.Same(string.Empty, Read(4));
            var exception = Assert.Throws<System.Reflection.TargetInvocationException>(() => Read(int.MinValue));
            Assert.IsType<KeyNotFoundException>(exception.InnerException);
        }
        finally { loader.Unload(); }
    }

    [Babel12CorpusTheory]
    [InlineData("preserved", true)]
    [InlineData("constructor", false)]
    [InlineData("initializer", false)]
    [InlineData("getter", false)]
    [InlineData("wrapper", false)]
    [InlineData("dictionary", false)]
    [InlineData("singleton", false)]
    [InlineData("source", false)]
    [InlineData("duplicate-source", false)]
    [InlineData("detached-method", false)]
    [InlineData("detached-field", false)]
    public void EncryptedTableRetirementRequiresTheExactVerifiedReplacement(string scenario, bool preserved)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-strings-hash"));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        var cache = Assert.Single(BabelHashStringShape.Find(context.Module));
        Assert.Equal(PassStatus.Success, new BabelHashStringPass().Run(context).Status);
        Assert.True(context.TryGetFact<IReadOnlyList<RetiredBabelHashResource>>(RetiredBabelHashResource.Fact, out var proofs));
        var proof = Assert.Single(proofs!);
        Assert.True(proof.IsPreserved(context.Module));
        var method = scenario switch
        {
            "constructor" => cache.Constructor, "initializer" => cache.Initializer,
            "getter" => cache.Getter, "wrapper" => cache.Wrapper, _ => null
        };
        method?.Body.Instructions.Insert(0, OpCodes.Break.ToInstruction());
        if (scenario == "dictionary") cache.Dictionary.Attributes ^= FieldAttributes.InitOnly;
        if (scenario == "singleton") cache.Singleton.Name += "changed";
        if (scenario == "source")
        {
            var at = context.Module.Resources.IndexOf(context.Module.Resources.Single(resource => resource.Name == proof.Source.Name));
            context.Module.Resources[at] = new EmbeddedResource(proof.Source.Name, [9], ManifestResourceAttributes.Private);
        }
        if (scenario == "duplicate-source") context.Module.Resources.Add(new EmbeddedResource(proof.Source.Name, [9], ManifestResourceAttributes.Private));
        if (scenario == "detached-method") cache.Constructor.DeclaringType.Methods.Remove(cache.Constructor);
        if (scenario == "detached-field") cache.Dictionary.DeclaringType.Fields.Remove(cache.Dictionary);
        Assert.Equal(preserved, proof.IsPreserved(context.Module));
    }

    [Babel12CorpusTheory]
    [InlineData("net8.0-strings-hash")]
    [InlineData("net10.0-strings-hash")]
    public void CleanupRemovesTheRetiredTableAndNameDelegateButPreservesApplicationResources(string id)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        var cache = Assert.Single(BabelHashStringShape.Find(context.Module));
        var nameDelegate = cache.Constructor.DeclaringType.Fields.Single(field => field != cache.Singleton && field != cache.Dictionary);
        var delegateType = nameDelegate.FieldType.ToTypeDefOrRef().ResolveTypeDef();
        Assert.Equal(PassStatus.Success, new BabelHashStringPass().Run(context).Status);
        Assert.True(context.TryGetFact<IReadOnlyList<RetiredBabelHashResource>>(RetiredBabelHashResource.Fact, out var proofs));
        var source = Assert.Single(proofs!).Source;
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.DoesNotContain(nameDelegate, cache.Constructor.DeclaringType.Fields);
        Assert.DoesNotContain(delegateType, context.Module.GetTypes());
        var cleanup = new ProtectorResourceCleanupPass().Run(context);
        Assert.Equal(PassStatus.Success, cleanup.Status); Assert.Equal(1, cleanup.Changes);
        Assert.DoesNotContain(context.Module.Resources, resource => resource.Name == source.Name);
        Assert.Contains(context.Module.Resources, resource => resource.Name == "BabelProbe.Secret.txt");
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed);
    }
}
