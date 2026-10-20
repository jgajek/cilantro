using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorRootHelperTests
{
    private static string Input => Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_CHECK_SAMPLES")!,
        CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-root-checks.manifest.json"))
            .Samples.Single(sample => sample.Id == "net10.0-root-method").LocalName);
    private static TypeDef Binding(ModuleDef module) => module.GetTypes().Single(type => type.Name == "GeneratedBindingInterceptors");

    [DotfuscatorCheckCorpusFact]
    public void DetectionAloneDoesNotAttributeDisconnectedHelpers()
    {
        using var context = ArtifactContext.Load(Input);
        new DotfuscatorDetectionPass().Run(context);
        Assert.Empty(RetiredDotfuscatorRootRuntime.UnusedHelpers(context));
        Assert.Empty(RecoveryOrphans.TypesOf(context));
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("body")]
    [InlineData("attribute")]
    [InlineData("scope")]
    [InlineData("initializer")]
    [InlineData("method-flags")]
    public void ChangedInputTemplateIsRetainedWithoutBlockingCheckRecovery(string change)
    {
        Temporary(module =>
        {
            var type = Binding(module);
            if (change == "body") AddEffect(type.Methods[0]);
            if (change == "attribute") type.CustomAttributes.Single().ConstructorArguments[1] = new CAArgument(module.CorLibTypes.String, "unreviewed");
            if (change == "scope") type.Methods[0].MethodSig.Params[1] = new ClassSig(new TypeRefUser(module,
                "Microsoft.Maui.Controls", "BindableProperty", new AssemblyRefUser("Foreign")));
            if (change == "method-flags") type.Methods[0].ImplAttributes |= MethodImplAttributes.NoInlining;
            if (change == "initializer")
            {
                var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                    MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
                initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); type.Methods.Add(initializer);
            }
        }, context =>
        {
            Recover(context);
            var helpers = RetiredDotfuscatorRootRuntime.UnusedHelpers(context).ToArray();
            Assert.Single(helpers);
            Assert.DoesNotContain(Binding(context.Module), helpers);
        });
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("body")]
    [InlineData("metadata")]
    [InlineData("reflection")]
    public void LaterTemplateChangesOrReflectionVetoRetirement(string change)
    {
        using var context = ArtifactContext.Load(Input);
        Recover(context);
        var type = Binding(context.Module);
        Assert.Equal(2, RetiredDotfuscatorRootRuntime.UnusedHelpers(context).Count());
        if (change == "body") AddEffect(type.Methods[0]);
        else if (change == "metadata") type.Attributes ^= TypeAttributes.Sealed;
        else
        {
            context.Module.EntryPoint.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction(type.ReflectionFullName));
            context.Module.EntryPoint.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        Assert.DoesNotContain(type, RetiredDotfuscatorRootRuntime.UnusedHelpers(context));
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("call")]
    [InlineData("handle")]
    [InlineData("field")]
    public void SurvivingConsumersKeepTheReviewedBindingHelper(string use)
    {
        using var context = ArtifactContext.Load(Input);
        Recover(context);
        var type = Binding(context.Module);
        var candidates = RetiredDotfuscatorRootRuntime.UnusedHelpers(context).ToHashSet();
        Assert.Contains(type, candidates);
        if (use == "field") context.Module.EntryPoint.DeclaringType.Fields.Add(new FieldDefUser("ApplicationState",
            new FieldSig(new ClassSig(type)), FieldAttributes.Public | FieldAttributes.Static));
        else
        {
            var body = context.Module.EntryPoint.Body;
            if (use == "handle") body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(type));
            else
            {
                body.Instructions.Insert(0, OpCodes.Ldc_I4_0.ToInstruction());
                body.Instructions.Insert(1, OpCodes.Call.ToInstruction(type.Methods.Single(method => method.MethodSig.Params.Count == 1)));
            }
            body.Instructions.Insert(use == "handle" ? 1 : 2, OpCodes.Pop.ToInstruction());
        }
        Assert.DoesNotContain(type, RuntimeCleanupPass.ComputeUnreferenced(context.Module, candidates));
    }

    [DotfuscatorCheckCorpusFact]
    public void AnEmptyClassWithoutItsVendorIdentityRemainsUnattributed()
    {
        Temporary(module =>
        {
            var type = module.GetTypes().Single(type => type.Name == "PlatformClass1");
            type.Namespace = "Application"; type.Name = "Empty";
        }, context =>
        {
            Recover(context);
            var type = context.Module.GetTypes().Single(type => type.FullName == "Application.Empty");
            Assert.DoesNotContain(type, RetiredDotfuscatorRootRuntime.UnusedHelpers(context));
            Assert.DoesNotContain(type.MDToken.Raw, RecoveryOrphans.TypesOf(context));
        });
    }

    private static void Recover(ArtifactContext context)
    {
        new DotfuscatorDetectionPass().Run(context);
        Assert.Equal(PassStatus.Success, new DotfuscatorCheckPass().Run(context).Status);
    }

    private static void AddEffect(MethodDef method)
    {
        method.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("changed"));
        method.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(new Importer(method.Module).Import(typeof(Console).GetMethod(nameof(Console.WriteLine), [typeof(string)])!)));
    }

    private static void Temporary(Action<ModuleDefMD> rewrite, Action<ArtifactContext> verify)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.RootHelper.").FullName;
        try
        {
            var path = Path.Combine(directory, "RootCheckProbe.dll");
            using (var module = ModuleDefMD.Load(Input)) { rewrite(module); module.Write(path); }
            using var context = ArtifactContext.Load(path); verify(context);
        }
        finally { Directory.Delete(directory, true); }
    }
}
