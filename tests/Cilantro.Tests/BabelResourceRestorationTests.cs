using System.Security.Cryptography;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelResourceRestorationTests
{
    private static string Sample(string id)
    {
        var manifest = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-baseline.manifest.json"));
        return Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!, manifest.Samples.Single(sample => sample.Id == id).LocalName);
    }

    [Babel12CorpusTheory]
    [InlineData("net48-resources", 1)]
    [InlineData("net8.0-resources", 1)]
    [InlineData("net10.0-resources", 1)]
    [InlineData("net48-combined", 4)]
    [InlineData("net8.0-combined", 4)]
    [InlineData("net10.0-combined", 4)]
    public void EntireResourceTableIsRestoredAndItsChooserRetired(string id, int entries)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new BabelDetectionPass().Run(context);
        context.SetFact("options.removeRuntime", true);
        var initializer = Assert.Single(BabelResourceShape.Find(context.Module)).Initializer;
        var result = new BabelResourceRestorationPass().Run(context);
        Assert.True(result.Status == PassStatus.Success, string.Join("; ", result.Diagnostics));
        Assert.Equal(entries, result.Changes);
        Assert.Equal(Code.Ret, Assert.Single(initializer.Body.Instructions).OpCode.Code);
        var resource = Assert.Single(context.Module.Resources.OfType<EmbeddedResource>(), resource => resource.Name == "BabelProbe.Secret.txt");
        Assert.Equal("55b9b921378bd858ab954ee0e81f05165ca23ebdac6a134674ab76312da231dd", Convert.ToHexStringLower(SHA256.HashData(resource.CreateReader().ToArray())));
        Assert.DoesNotContain(context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).SelectMany(method => method.Body.Instructions),
            instruction => instruction.Operand is IMethod called && called.Name == "add_ResourceResolve");
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed);
    }

    [Babel12CorpusTheory]
    [InlineData("comparison")]
    [InlineData("foreign-write")]
    [InlineData("registration")]
    [InlineData("wire-key")]
    [InlineData("collision")]
    public void ChangedChooserOrUnownedConstructionEffectsDeclineAtomically(string change)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelResourceRefusal.").FullName;
        try
        {
            var path = Path.Combine(directory, "BabelProbe.exe");
            using (var module = ModuleDefMD.Load(Sample("net48-resources")))
            {
                var resolver = Assert.Single(BabelResourceShape.Find(module));
                if (change == "comparison")
                {
                    var lookup = resolver.Initializer.DeclaringType.Methods.Single(method => method.MethodSig.Params.Count == 1 && method.MethodSig.Params[0].ElementType == ElementType.String);
                    var call = lookup.Body.Instructions.Single(instruction => instruction.Operand is IMethod called && called.FullName == "System.Boolean System.String::Equals(System.String,System.String,System.StringComparison)");
                    var literal = lookup.Body.Instructions[lookup.Body.Instructions.IndexOf(call) - 1]; literal.OpCode = OpCodes.Ldc_I4_4; literal.Operand = null;
                }
                if (change == "foreign-write")
                {
                    var field = module.GetTypes().SelectMany(type => type.Fields).Single(field => field.Name == "calls");
                    resolver.StreamDecoder.Body.Instructions.Insert(0, OpCodes.Ldc_I4_7.ToInstruction());
                    resolver.StreamDecoder.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(field));
                }
                if (change == "registration")
                {
                    var domain = new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef);
                    var handler = new TypeRefUser(module, "System", "ResolveEventHandler", module.CorLibTypes.AssemblyRef);
                    Instruction[] prefix = [OpCodes.Call.ToInstruction(new MemberRefUser(module, "get_CurrentDomain", MethodSig.CreateStatic(new ClassSig(domain)), domain)),
                        OpCodes.Ldnull.ToInstruction(), OpCodes.Ldftn.ToInstruction(resolver.Handler),
                        OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr), handler)),
                        OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "add_ResourceResolve", MethodSig.CreateInstance(module.CorLibTypes.Void, new ClassSig(handler)), domain))];
                    for (var index = 0; index < prefix.Length; index++) resolver.StreamDecoder.Body.Instructions.Insert(index, prefix[index]);
                }
                if (change == "wire-key")
                {
                    var il = resolver.Reader.Body.Instructions;
                    var at = Enumerable.Range(2, il.Count - 2).Single(index => il[index].OpCode.Code == Code.Xor && il[index - 1].IsLdcI4() &&
                        il[index - 2].Operand is IMethod called && called.Name == "get_Chars");
                    il[at - 1].Operand = il[at - 1].GetLdcI4Value() ^ 1;
                }
                if (change == "collision") module.Resources.Add(new EmbeddedResource("BabelProbe.Secret.txt", [1, 2, 3], ManifestResourceAttributes.Public));
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
            var bodies = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var resources = context.Module.Resources.OfType<EmbeddedResource>().ToDictionary(resource => resource.Name.String, resource => resource.CreateReader().ToArray());
            var result = new BabelResourceRestorationPass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status); Assert.Equal(0, result.Changes);
            Assert.All(bodies, item => Assert.True(item.Value.StructurallyEquals(item.Key)));
            Assert.Equal(resources.Count, context.Module.Resources.Count);
            Assert.All(context.Module.Resources.OfType<EmbeddedResource>(), resource => Assert.Equal(resources[resource.Name], resource.CreateReader().ToArray()));
            Assert.Empty(context.Changes);
            if (change is "foreign-write" or "registration") Assert.Contains(result.Diagnostics, note => note.Contains("outside the reviewed chooser", StringComparison.Ordinal));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void ResourceSatellitesWithCodeOrIncompleteNameTablesAreRefused()
    {
        using var module = new ModuleDefUser("resources") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("resources", new Version(1, 0)); assembly.Modules.Add(module);
        module.Resources.Add(new EmbeddedResource("payload.txt", [1], ManifestResourceAttributes.Public));
        var names = new HashSet<string>(StringComparer.Ordinal) { "payload.txt" };
        Assert.True(BabelResourceRestorationPass.IsResourceOnly(module, names));
        Assert.False(BabelResourceRestorationPass.IsResourceOnly(module, new HashSet<string> { "other.txt" }));
        var injected = new MethodDefUser("Initialize", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static) { Body = new CilBody() };
        injected.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); module.GlobalType.Methods.Add(injected);
        Assert.False(BabelResourceRestorationPass.IsResourceOnly(module, names));
    }

    [Babel12CorpusFact]
    public void RuntimeRetentionLeavesTheOriginalResourceHookAndMetadata()
    {
        using var context = ArtifactContext.Load(Sample("net48-resources"));
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", false);
        var initializer = Assert.Single(BabelResourceShape.Find(context.Module)).Initializer;
        var snapshot = MethodBodySnapshot.Capture(initializer);
        var resources = context.Module.Resources.Count;
        var result = new BabelResourceRestorationPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status); Assert.Equal(0, result.Changes);
        Assert.True(snapshot.StructurallyEquals(initializer)); Assert.Equal(resources, context.Module.Resources.Count);
        Assert.Empty(context.Changes);
    }
}
