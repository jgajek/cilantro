using Cilantro.Core;
using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorResourceRetirementTests
{
    private static readonly string[] Manifests = ["dotfuscator-7-resources", "dotfuscator-7-resource-types", "dotfuscator-7-satellite-resources"];
    private static string Samples => Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_RESOURCE_SAMPLES")!;
    private static string Input => Path.Combine(Samples, "dotfuscator-resources", "net48", "protected", "ResourceProbe.exe");

    [DotfuscatorResourceCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void AllNineCapturesRetireBothGeneratedResourceTypes()
    {
        Temporary(directory =>
        {
            var captures = 0;
            foreach (var name in Manifests)
                foreach (var sample in CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", name + ".manifest.json")).Samples.Where(sample => sample.Tier != "oracle"))
                {
                    var input = Path.Combine(Samples, sample.LocalName);
                    using var source = ModuleDefMD.Load(input);
                    var manager = Assert.Single(DotfuscatorResourceShape.Find(source)).Manager;
                    var family = GeneratedRuntimeShape.Read(manager.Methods[0]).Types.Select(type => type.FullName).ToHashSet(StringComparer.Ordinal);
                    Assert.Equal(2, family.Count);
                    var folder = Path.Combine(directory, name, sample.Id);
                    var result = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: Path.Combine(folder, "cleaned.bin"), ReportDirectory: folder));
                    Assert.True(result.Success, string.Join(";", result.Report.VerificationDiagnostics));
                    using var output = ModuleDefMD.Load(result.OutputPath!);
                    Assert.DoesNotContain(output.GetTypes(), type => family.Contains(type.FullName));
                    var changes = JsonSerializer.Deserialize<ChangeRecord[]>(File.ReadAllText(result.ChangesReportPath), CilantroPipeline.ReportJsonOptions)!;
                    Assert.Equal(2, changes.Count(change => change.Kind == "remove-runtime-type" && change.Description.Contains("resource family", StringComparison.Ordinal)));
                    Assert.Contains(changes, change => change.Kind == "rebind-resource-manager");
                    if (sample.Id.StartsWith("net48", StringComparison.Ordinal))
                    {
                        var verification = IlVerification.Against(IlVerification.Read(input), IlVerification.Read(result.OutputPath!));
                        Assert.Empty(verification.Broken.Except(verification.Was.Unreadable));
                        Assert.Empty(verification.Worsened);
                    }
                    captures++;
                }
            Assert.Equal(9, captures);
        });
    }

    [DotfuscatorResourceCorpusTheory]
    [InlineData("reflection")]
    [InlineData("handle")]
    [InlineData("field")]
    [InlineData("subclass")]
    public void ObservableTypeUsesKeepTheManagerAndItsConstructorBinding(string use)
    {
        Temporary(directory =>
        {
            var input = Rewrite(directory, module =>
            {
                var manager = Assert.Single(DotfuscatorResourceShape.Find(module)).Manager;
                if (use == "subclass") module.Types.Add(new TypeDefUser("ApplicationChild", manager));
                else if (use == "field") module.Types.Single(type => type.FullName == "ResourceProbe.Program").Fields.Add(
                    new FieldDefUser("ApplicationState", new FieldSig(new ClassSig(manager)), FieldAttributes.Public | FieldAttributes.Static));
                else
                {
                    var main = module.EntryPoint;
                    main.Body.Instructions.Insert(0, use == "reflection" ? OpCodes.Ldstr.ToInstruction(manager.ReflectionFullName + ", " + module.Assembly.FullName) : OpCodes.Ldtoken.ToInstruction(manager));
                    main.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
                }
            });
            using var context = ArtifactContext.Load(input);
            new DotfuscatorDetectionPass().Run(context);
            Assert.Equal(PassStatus.Success, new DotfuscatorResourcePass().Run(context).Status);
            Assert.Contains(context.Module.GetTypes().Where(type => type.FullName.StartsWith("ResourceProbe.", StringComparison.Ordinal)).SelectMany(type => type.Methods)
                .Where(method => method.HasBody).SelectMany(method => method.Body.Instructions),
                instruction => instruction.OpCode.Code == Code.Newobj && instruction.Operand is IMethod called && called.DeclaringType.FullName.EndsWith(".CRManager", StringComparison.Ordinal));
            Assert.Empty(RetiredDotfuscatorResourceRuntime.Unused(context));
        });
    }

    [DotfuscatorResourceCorpusTheory]
    [InlineData("attribute")]
    [InlineData("scope")]
    public void UnreviewedSourceMetadataLeavesResourcesAndHooksIntact(string change)
    {
        Temporary(directory =>
        {
            var input = Rewrite(directory, module =>
            {
                var manager = Assert.Single(DotfuscatorResourceShape.Find(module)).Manager;
                if (change == "attribute") manager.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void), new TypeRefUser(module, "System", "ObsoleteAttribute", module.CorLibTypes.AssemblyRef))));
                else
                {
                    var field = manager.Fields.First(field => field.FieldType.ElementType == ElementType.String);
                    field.FieldSig = new FieldSig(new ClassSig(new TypeRefUser(module, "System", "String", new AssemblyRefUser("Foreign.Core"))));
                }
            });
            using var context = ArtifactContext.Load(input);
            var resources = context.Module.Resources.OfType<EmbeddedResource>().Select(resource => resource.CreateReader().ToArray()).ToArray();
            var methods = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
                .ToDictionary(method => method, Cilantro.Core.Verification.MethodBodySnapshot.Capture);
            new DotfuscatorDetectionPass().Run(context);
            Assert.Equal(PassStatus.Unsupported, new DotfuscatorResourcePass().Run(context).Status);
            Assert.Equal(resources, context.Module.Resources.OfType<EmbeddedResource>().Select(resource => resource.CreateReader().ToArray()).ToArray());
            Assert.All(methods, item => Assert.True(item.Value.StructurallyEquals(item.Key)));
        });
    }

    [DotfuscatorResourceCorpusTheory]
    [InlineData("body")]
    [InlineData("attribute")]
    [InlineData("reader-body")]
    public void LaterFamilyChangesInvalidateRetirement(string change)
    {
        using var context = ArtifactContext.Load(Input);
        new DotfuscatorDetectionPass().Run(context);
        Assert.Equal(PassStatus.Success, new DotfuscatorResourcePass().Run(context).Status);
        Assert.Equal(2, RetiredDotfuscatorResourceRuntime.Unused(context).Count());
        var type = context.Module.GetTypes().Single(type => type.Name == (change == "reader-body" ? "DRReader" : "CRManager"));
        if (change == "attribute") type.Attributes ^= TypeAttributes.Sealed;
        else
        {
            var method = type.Methods.First(method => method.HasBody && !method.IsConstructor);
            method.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("changed"));
            method.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(new Importer(context.Module).Import(typeof(Console).GetMethod(nameof(Console.WriteLine), [typeof(string)])!)));
        }
        Assert.Empty(RetiredDotfuscatorResourceRuntime.Unused(context));
    }

    [DotfuscatorResourceCorpusFact]
    public void RuntimeProofCopiesExpandedApplicationBranchesWithoutChangingTheirForms()
    {
        using var context = ArtifactContext.Load(Input);
        var main = context.Module.EntryPoint;
        var branch = main.Body.Instructions.First(instruction => instruction.OpCode.OperandType == OperandType.ShortInlineBrTarget);
        var target = Assert.IsType<Instruction>(branch.Operand);
        var insertion = Math.Min(main.Body.Instructions.IndexOf(branch), main.Body.Instructions.IndexOf(target)) + 1;
        for (var index = 0; index < 512; index++) main.Body.Instructions.Insert(insertion, OpCodes.Nop.ToInstruction());
        var before = Cilantro.Core.Verification.MethodBodySnapshot.Capture(main);
        Assert.True(RetiredDotfuscatorResourceRuntime.CanRebind(context, Assert.Single(DotfuscatorResourceShape.Find(context.Module))));
        Assert.True(before.StructurallyEquals(main));
    }

    [DotfuscatorResourceCorpusFact]
    public void ANewSurvivingReferenceVetoesWholeFamilyDeletion()
    {
        using var context = ArtifactContext.Load(Input);
        new DotfuscatorDetectionPass().Run(context);
        Assert.Equal(PassStatus.Success, new DotfuscatorResourcePass().Run(context).Status);
        var family = RetiredDotfuscatorResourceRuntime.Unused(context).ToHashSet();
        Assert.Equal(2, family.Count);
        var manager = family.Single(type => type.Name == "CRManager");
        context.Module.Types.Single(type => type.FullName == "ResourceProbe.Program").Fields.Add(
            new FieldDefUser("LaterReference", new FieldSig(new ClassSig(manager)), FieldAttributes.Public | FieldAttributes.Static));
        Assert.DoesNotContain(manager, RuntimeCleanupPass.ComputeUnreferenced(context.Module, family));
    }

    private static string Rewrite(string directory, Action<ModuleDefMD> change)
    {
        var path = Path.Combine(directory, "ResourceProbe.exe");
        using var module = ModuleDefMD.Load(Input);
        change(module); module.Write(path); return path;
    }
    private static void Temporary(Action<string> action)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.ResourceRetirement.").FullName;
        try { action(directory); } finally { Directory.Delete(directory, true); }
    }
}
