using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class SharedInitializationCompletionTests
{
    [Babel12CorpusTheory]
    [InlineData("net48-strings-hash", false)]
    [InlineData("net48-combined", true)]
    public void RecoveredBabelStringsReleaseUnobservedSharedInitialization(string id, bool shared)
    {
        var manifest = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-baseline.manifest.json"));
        var input = Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!,
            manifest.Samples.Single(sample => sample.Id == id).LocalName);
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelSharedInitialization.").FullName;
        try
        {
            var result = new Cilantro.Core.CilantroPipeline().Run(input, new Cilantro.Core.PipelineOptions(
                OutputPath: Path.Combine(directory, "cleaned.exe"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.True(result.Success);
            using var changes = System.Text.Json.JsonDocument.Parse(File.ReadAllText(result.ChangesReportPath));
            Assert.Equal(shared, changes.RootElement.EnumerateArray().Any(change =>
                change.GetProperty("Kind").GetString() == "retire-unobserved-shared-initialization"));
            using var module = ModuleDefMD.Load(result.OutputPath!);
            Assert.DoesNotContain(module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
                .SelectMany(method => method.Body.Instructions), instruction =>
                    instruction.Operand is IMethod called && called.Name == "RunClassConstructor");
            var difference = IlVerification.Against(IlVerification.Read(input), IlVerification.Read(result.OutputPath!));
            Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
            Assert.Empty(difference.Worsened);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData("closed", true)]
    [InlineData("reader", false)]
    [InlineData("address", false)]
    [InlineData("token", false)]
    [InlineData("named", false)]
    [InlineData("external", false)]
    [InlineData("prefix-effect", false)]
    [InlineData("throw", false)]
    [InlineData("unknown", false)]
    [InlineData("foreign-trigger", false)]
    [InlineData("alternate-entry", false)]
    [InlineData("no-provenance", false)]
    [InlineData("disabled", false)]
    [InlineData("string-closed", true)]
    [InlineData("string-empty", true)]
    [InlineData("string-reader", false)]
    [InlineData("string-prefix-effect", false)]
    [InlineData("string-throw", false)]
    public void RetiresOnlyAttributedIsolatedAndClosedInitialization(string scenario, bool expected)
    {
        var stringProvenance = scenario.StartsWith("string-", StringComparison.Ordinal);
        if (stringProvenance) scenario = scenario[7..];
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Shared");
            if (scenario == "external") owner.Attributes = TypeAttributes.Public;
            var app = SyntheticContext.AddType(module, "App");
            var value = new FieldDefUser("Value", new FieldSig(new SZArraySig(module.CorLibTypes.Int32)), FieldAttributes.Static | FieldAttributes.Assembly);
            owner.Fields.Add(value);
            var observed = new FieldDefUser("Observed", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public); app.Fields.Add(observed);
            var init = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            owner.Methods.Add(init);
            if (scenario == "prefix-effect")
            {
                var effect = new MethodDefUser("Effect", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static, Body = new CilBody() };
                app.Methods.Add(effect);
                Add(effect, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(observed), OpCodes.Ret.ToInstruction());
                Add(init, OpCodes.Call.ToInstruction(effect));
            }
            if (scenario == "unknown") Add(init, OpCodes.Call.ToInstruction(new MemberRefUser(module, "Effect", MethodSig.CreateStatic(module.CorLibTypes.Void), new TypeRefUser(module, "External", "Api", new AssemblyRefUser("External")))));
            if (scenario == "empty") Add(init, OpCodes.Ret.ToInstruction());
            else if (scenario == "throw") Add(init, OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
            else Add(init, OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef), OpCodes.Stsfld.ToInstruction(value), OpCodes.Ret.ToInstruction());
            var dead = new MethodDefUser("Unused", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(dead); Add(dead, OpCodes.Ret.ToInstruction());
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static | MethodAttributes.Public, Body = new CilBody() };
            app.Methods.Add(run); module.EntryPoint = run;
            var trigger = OpCodes.Call.ToInstruction(new MemberRefUser(module, "RunClassConstructor", MethodSig.CreateStatic(module.CorLibTypes.Void,
                new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers",
                    scenario == "foreign-trigger" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef)));
            if (scenario == "alternate-entry") Add(run, OpCodes.Ldtoken.ToInstruction(app), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(trigger), OpCodes.Pop.ToInstruction());
            Add(run, OpCodes.Ldtoken.ToInstruction(owner), trigger);
            if (scenario == "reader") Add(run, OpCodes.Ldsfld.ToInstruction(value), OpCodes.Pop.ToInstruction());
            if (scenario == "address") Add(run, OpCodes.Ldsflda.ToInstruction(value), OpCodes.Pop.ToInstruction());
            if (scenario == "token") Add(run, OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Pop.ToInstruction());
            if (scenario == "named") Add(run, OpCodes.Ldstr.ToInstruction(owner.FullName), OpCodes.Pop.ToInstruction());
            Add(run, OpCodes.Ret.ToInstruction());
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "Shared");
        var run = context.Module.EntryPoint;
        var before = MethodBodySnapshot.Capture(run);
        context.SetFact("options.removeRuntime", scenario != "disabled");
        if (scenario != "no-provenance") context.SetFact<IReadOnlySet<TypeDef>>(
            stringProvenance ? StringLookupCompletionPass.SharedTypesFact : NumericInitializationCompletionPass.SharedTypesFact, new HashSet<TypeDef> { owner });
        var result = new SharedInitializationCompletionPass().Run(context);
        Assert.True(result.Changes == (expected ? 1 : 0), string.Join("\n", result.Diagnostics));
        if (!expected) { Assert.True(before.StructurallyEquals(run)); return; }
        Assert.DoesNotContain(run.Body.Instructions, i => i.OpCode.Code is Code.Call or Code.Ldtoken);
        Assert.Equal(0, new SharedInitializationCompletionPass().Run(context).Changes);
        Assert.Equal(Cilantro.Core.PassStatus.Success, new SharedInitializerRuntimeCleanupPass().Run(context).Status);
        Assert.DoesNotContain(owner, context.Module.GetTypes());
        Assert.Same(run, context.Module.EntryPoint);
    }

    [Theory]
    [InlineData("closed", true)]
    [InlineData("foreign-write", false)]
    [InlineData("reader", false)]
    [InlineData("handle", false)]
    [InlineData("named", false)]
    [InlineData("throw", false)]
    public void LiteralRegionsRequireClosedEffectsAndNoExternalConsumers(string scenario, bool retired)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("seed-key", [7], ManifestResourceAttributes.Private));
            var app = SyntheticContext.AddType(module, "App"); app.Attributes |= TypeAttributes.Public;
            var a = SyntheticContext.AddType(module, "First"); var b = SyntheticContext.AddType(module, "Second");
            var stream = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
            var buffer = new FieldDefUser("Input", new FieldSig(stream.ToTypeSig()), FieldAttributes.Static | FieldAttributes.Private); b.Fields.Add(buffer);
            var value = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Private); a.Fields.Add(value);
            var observed = new FieldDefUser("Observed", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public); app.Fields.Add(observed);
            MethodDef Method(TypeDef owner, string name, MethodSig signature)
            {
                var method = new MethodDefUser(name, signature) { Attributes = MethodAttributes.Static | MethodAttributes.Assembly, Body = new CilBody() };
                if (name == ".cctor") method.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
                owner.Methods.Add(method); return method;
            }
            var bInit = Method(b, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void));
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            Add(bInit, OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(assembly.ToTypeSig()), assembly)),
                OpCodes.Ldstr.ToInstruction("seed-key"), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetManifestResourceStream",
                    MethodSig.CreateInstance(stream.ToTypeSig(), module.CorLibTypes.String), assembly)), OpCodes.Stsfld.ToInstruction(buffer));
            if (scenario == "foreign-write") Add(bInit, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(observed));
            if (scenario == "throw") Add(bInit, OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
            Add(bInit, OpCodes.Ret.ToInstruction());
            var read = Method(b, "Read", MethodSig.CreateStatic(module.CorLibTypes.Int32));
            Add(read, OpCodes.Ldsfld.ToInstruction(buffer), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ReadByte", MethodSig.CreateInstance(module.CorLibTypes.Int32), stream)), OpCodes.Ret.ToInstruction());
            var aInit = Method(a, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void));
            Add(aInit, OpCodes.Call.ToInstruction(read), OpCodes.Stsfld.ToInstruction(value), OpCodes.Ret.ToInstruction());
            var run = Method(app, "Run", MethodSig.CreateStatic(module.CorLibTypes.Void)); run.Attributes |= MethodAttributes.Public; module.EntryPoint = run;
            var trigger = new MemberRefUser(module, "RunClassConstructor", MethodSig.CreateStatic(module.CorLibTypes.Void,
                new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers"));
            Add(run, OpCodes.Ldtoken.ToInstruction(a), OpCodes.Call.ToInstruction(trigger), OpCodes.Ldtoken.ToInstruction(b), OpCodes.Call.ToInstruction(trigger));
            if (scenario == "reader") Add(run, OpCodes.Ldsfld.ToInstruction(buffer), OpCodes.Pop.ToInstruction());
            if (scenario == "handle") Add(run, OpCodes.Ldtoken.ToInstruction(b), OpCodes.Pop.ToInstruction());
            if (scenario == "named") Add(run, OpCodes.Ldstr.ToInstruction(b.FullName), OpCodes.Pop.ToInstruction());
            Add(run, OpCodes.Ret.ToInstruction());
        });
        context.SetFact("options.removeRuntime", true);
        var owners = context.Module.GetTypes().Where(t => t.Name.String is "First" or "Second").ToHashSet();
        context.SetFact<IReadOnlySet<TypeDef>>(LiteralStringDecoderPass.InitializersFact, owners);
        var result = new SharedInitializationCompletionPass().Run(context);
        Assert.Equal(retired ? 2 : 0, result.Changes);
        new SharedInitializerRuntimeCleanupPass().Run(context);
        new ProtectorResourceCleanupPass().Run(context);
        Assert.Equal(!retired, context.Module.Resources.Any(r => r.Name == "seed-key"));
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed);
    }

    private static void Add(MethodDef method, params Instruction[] instructions)
    { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }
}
