using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Proxy;
using Cilantro.Core.Recovery;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class BabelProxyInitializationTests
{
    private static string Sample(string id)
    {
        var manifest = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-baseline.manifest.json"));
        return Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!, manifest.Samples.Single(sample => sample.Id == id).LocalName);
    }

    [Babel12CorpusTheory]
    [InlineData("net48-proxies")]
    [InlineData("net8.0-proxies")]
    [InlineData("net10.0-proxies")]
    [InlineData("net48-combined")]
    [InlineData("net8.0-combined")]
    [InlineData("net10.0-combined")]
    public void ClosedGeneratedInitializersRetireAfterAllLiveFieldConsumersAreRecovered(string id)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        var bindings = new BabelProxyRecoveryPass().Run(context);
        Assert.True(context.TryGetFact<bool>(BabelProxyRecoveryPass.CompleteFact, out var complete) && complete, string.Join("; ", bindings.Diagnostics));
        var result = new BabelProxyInitializationPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(19, result.Changes);
        Assert.DoesNotContain(context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).SelectMany(method => method.Body.Instructions),
            instruction => instruction.Operand is dnlib.DotNet.IMethod called && called.Name == "RunClassConstructor");
        var inlined = new BabelProxyInliningPass().Run(context);
        Assert.Equal(PassStatus.Success, inlined.Status); Assert.True(inlined.Changes > 0);
    }

    [Babel12CorpusTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void RuntimeRetentionAndBindingMismatchKeepOriginalInitializers(bool mismatch)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-proxies"));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", mismatch);
        new BabelProxyRecoveryPass().Run(context);
        if (mismatch)
        {
            Assert.True(context.TryGetFact<IReadOnlyDictionary<uint, string>>(BabelProxyRecoveryPass.BindingsFact, out var fingerprints));
            context.SetFact<IReadOnlyDictionary<uint, string>>(BabelProxyRecoveryPass.BindingsFact, fingerprints!.ToDictionary(item => item.Key, _ => "different binding"));
        }
        var bodies = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
            .ToDictionary(method => method, Cilantro.Core.Verification.MethodBodySnapshot.Capture);
        Assert.Equal(0, new BabelProxyInitializationPass().Run(context).Changes);
        Assert.Equal(0, new BabelProxyInliningPass().Run(context).Changes);
        Assert.All(bodies, item => Assert.True(item.Value.StructurallyEquals(item.Key)));
    }

    [Babel12CorpusTheory]
    [InlineData("binder-write")]
    [InlineData("mutable-read")]
    [InlineData("initializer-write")]
    [InlineData("cache-writer")]
    [InlineData("cache-attribute")]
    public void ChangesAfterBindingRecoveryCannotBeHiddenByOriginalByteTrials(string change)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-proxies"));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        new BabelProxyRecoveryPass().Run(context);
        Assert.True(context.TryGetFact<IReadOnlyDictionary<uint, string>>(BabelProxyRecoveryPass.BindingsFact, out var fingerprints));
        var initializer = (dnlib.DotNet.MethodDef)context.Module.ResolveToken(fingerprints!.Keys.First());
        var binder = initializer.Body.Instructions.Select(instruction => (instruction.Operand as dnlib.DotNet.IMethod)?.ResolveMethodDef()).OfType<dnlib.DotNet.MethodDef>().Single();
        var field = context.Module.GetTypes().SelectMany(type => type.Fields).Single(field => field.Name == "calls");
        var method = change == "initializer-write" ? initializer : binder;
        if (change == "cache-writer")
        {
            var cache = binder.DeclaringType.Fields.Single();
            var writer = new MethodDefUser("OverwriteHandle", MethodSig.CreateStatic(context.Module.CorLibTypes.Void, cache.FieldType), MethodAttributes.Private | MethodAttributes.Static)
                { Body = new dnlib.DotNet.Emit.CilBody() };
            writer.Body.Instructions.Add(dnlib.DotNet.Emit.OpCodes.Ldarg_0.ToInstruction());
            writer.Body.Instructions.Add(dnlib.DotNet.Emit.OpCodes.Stsfld.ToInstruction(cache));
            writer.Body.Instructions.Add(dnlib.DotNet.Emit.OpCodes.Ret.ToInstruction()); binder.DeclaringType.Methods.Add(writer);
        }
        else if (change == "cache-attribute")
        {
            var type = new TypeRefUser(context.Module, "System", "ThreadStaticAttribute", context.Module.CorLibTypes.AssemblyRef);
            binder.DeclaringType.Fields.Single().CustomAttributes.Add(new CustomAttribute(
                new MemberRefUser(context.Module, ".ctor", MethodSig.CreateInstance(context.Module.CorLibTypes.Void), type)));
        }
        else if (change == "mutable-read")
        {
            method.Body.Instructions.Insert(0, dnlib.DotNet.Emit.OpCodes.Ldsfld.ToInstruction(field));
            method.Body.Instructions.Insert(1, dnlib.DotNet.Emit.OpCodes.Pop.ToInstruction());
        }
        else
        {
            method.Body.Instructions.Insert(0, dnlib.DotNet.Emit.OpCodes.Ldc_I4_7.ToInstruction());
            method.Body.Instructions.Insert(1, dnlib.DotNet.Emit.OpCodes.Stsfld.ToInstruction(field));
        }
        var before = Cilantro.Core.Verification.MethodBodySnapshot.Capture(initializer);
        var result = new BabelProxyInitializationPass().Run(context);
        Assert.True(result.Changes < 19);
        Assert.True(before.StructurallyEquals(initializer));
    }
}
