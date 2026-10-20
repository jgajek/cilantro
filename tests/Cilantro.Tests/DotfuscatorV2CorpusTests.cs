using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorV2CorpusTests
{
    private static CorpusManifest Manifest => CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-native.manifest.json"));
    private static string Samples => Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_V2_SAMPLES")!;

    [Fact]
    public void NativeManifestPinsRecoveredSitesAndOriginalProtectorDefect()
    {
        Assert.Equal(13, Manifest.Samples.Count);
        Assert.Equal(9, Manifest.Samples.Count(sample => sample.MinimumRecoveredStringSites == 17));
        Assert.Equal(19, Assert.Single(Manifest.Samples, sample => sample.Id == "net48-native-original").MinimumRecoveredStringSites);
        Assert.All(Manifest.Samples.Where(sample => sample.Tier != "oracle"), sample => Assert.Equal("detected", sample.Tier));
        Assert.All(Manifest.Samples.Where(sample => sample.Tier != "oracle"), sample => Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers));
    }

    [DotfuscatorV2CorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void NativeCorpusRecoversWithoutNewFrameworkVerifierFindings()
    {
        var results = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorV2.").FullName;
        try
        {
            var manifest = Manifest;
            var outcome = CorpusRunner.Run(Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-native.manifest.json"), Samples, results);
            Assert.True(outcome.Passed == 10 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(new { outcome.Passed, outcome.Failed, outcome.Missing,
                    Problems = outcome.Samples.Where(sample => sample.Status != "passed").Select(sample => new { sample.Id, sample.Diagnostics }) }, CilantroPipeline.ReportJsonOptions));
            foreach (var sample in manifest.Samples.Where(sample => sample.Tier != "oracle"))
            {
                var output = Path.Combine(results, sample.Id, "cleaned.bin");
                var originalPath = Path.Combine(Samples, sample.LocalName);
                using var cleaned = ModuleDefMD.Load(output);
                using var oracle = ModuleDefMD.Load(Path.Combine(Samples, manifest.Samples.Single(entry => entry.Sha256 == sample.OracleSha256).LocalName));
                var literals = Literals(cleaned);
                var missing = Literals(oracle).Except(literals).Order(StringComparer.Ordinal).ToArray();
                if (sample.Id == "net48-native-original")
                {
                    Assert.Equal(2, missing.Length);
                    Assert.Equal("PROBE_STR_11 nothing to transform", missing[0]);
                    Assert.Equal("PROBE_STR_12 ", missing[1]);
                }
                else Assert.Empty(missing);
                Assert.DoesNotContain(cleaned.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).SelectMany(method => method.Body.Instructions),
                    i => i.Operand is IMethod called && called.FullName == "System.Reflection.MethodBase System.Reflection.MethodBase::GetCurrentMethod()");
                Assert.DoesNotContain(cleaned.GetTypes(), type => type.FullName == "PreEmptive.Protection.Runtime.Native.NativeCPP");
                Assert.DoesNotContain(cleaned.GetTypes().SelectMany(type => type.Methods), method => method.ImplMap?.Module.Name.String is "Runtime.Extensions" or "Runtime.Extensions.dll");
                Assert.Contains(outcome.Samples.Single(entry => entry.Id == sample.Id).Passes,
                    pass => pass.Pass == "dotfuscator-native-strings" && pass.Status == PassStatus.Success && pass.Changes == sample.MinimumRecoveredStringSites);
                if (sample.Id.StartsWith("net48-", StringComparison.Ordinal))
                {
                    var difference = IlVerification.Against(IlVerification.Read(originalPath), IlVerification.Read(output));
                    Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                    Assert.True(difference.Worsened.Count == 0, sample.Id + ": " + difference.Describe());
                }
            }
        }
        finally { Directory.Delete(results, recursive: true); }
    }

    [DotfuscatorV2CorpusTheory]
    [InlineData("body")]
    [InlineData("attribute")]
    [InlineData("new-method")]
    [InlineData("field-scope")]
    [InlineData("live-call")]
    [InlineData("type-handle")]
    [InlineData("type-name")]
    [InlineData("qualified-name")]
    [InlineData("partial-qualified-name")]
    [InlineData("keep-runtime")]
    public void NativeBridgeRetirementRequiresAnIntactUnusedBridge(string change)
    {
        var directory = CopyOriginal();
        try
        {
            using var context = ArtifactContext.Load(Path.Combine(directory, "Probe.exe"));
            new DotfuscatorDetectionPass().Run(context);
            context.SetFact("options.removeRuntime", change != "keep-runtime");
            var native = Assert.Single(DotfuscatorV2Shape.Find(context.Module)).NativeType;
            Assert.Equal(19, new DotfuscatorV2StringPass().Run(context).Changes);
            switch (change)
            {
                case "body":
                    var body = native.Methods.Single(method => method.Name == "ComputeKey");
                    body.Body = new CilBody(); body.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); body.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); break;
                case "attribute":
                    var attribute = new CustomAttribute((ICustomAttributeType)new Importer(context.Module).Import(typeof(ObsoleteAttribute).GetConstructor([typeof(string)])!));
                    attribute.ConstructorArguments.Add(new CAArgument(context.Module.CorLibTypes.String, "changed")); native.CustomAttributes.Add(attribute); break;
                case "new-method":
                    var extra = new MethodDefUser("Extra", MethodSig.CreateStatic(context.Module.CorLibTypes.Void), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
                    extra.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); native.Methods.Add(extra); break;
                case "field-scope":
                    native.Fields.First(field => field.FieldType.FullName == "System.Byte[]").FieldSig.Type =
                        new SZArraySig(new ClassSig(new TypeRefUser(context.Module, "System", "Byte", new AssemblyRefUser("Forged.Runtime")))); break;
                case "live-call":
                    context.Module.EntryPoint.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(native.Methods.Single(method => method.Name == "GetEnvData")));
                    context.Module.EntryPoint.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction()); break;
                case "type-handle":
                    context.Module.EntryPoint.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(native));
                    context.Module.EntryPoint.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction()); break;
                case "type-name":
                case "qualified-name":
                case "partial-qualified-name":
                    var name = change == "type-name" ? native.FullName : change == "qualified-name" ? native.AssemblyQualifiedName : native.ReflectionFullName + ", " + context.Module.Assembly.Name;
                    context.Module.EntryPoint.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction(name));
                    context.Module.EntryPoint.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction()); break;
            }
            Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
            Assert.Contains(native, context.Module.GetTypes());
            Assert.Contains(native.Methods, method => method.ImplMap?.Name == "__eck");
        }
        finally { Directory.Delete(directory, true); }
    }

    [DotfuscatorV2CorpusTheory]
    [InlineData("net8.0-native-strings")]
    [InlineData("net10.0-native-strings")]
    public void ChangedCoreClrPlatformWrappersDoNotMatchTheReviewedInlining(string id)
    {
        var sample = Manifest.Samples.Single(sample => sample.Id == id);
        using var context = ArtifactContext.Load(Path.Combine(Samples, sample.LocalName));
        new DotfuscatorDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        var native = Assert.Single(DotfuscatorV2Shape.Find(context.Module)).NativeType;
        Assert.Equal(17, new DotfuscatorV2StringPass().Run(context).Changes);
        var wrapper = native.Methods.Single(method => method.Name == "IsAndroid");
        wrapper.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Call).Operand =
            new MemberRefUser(context.Module, "IsWindows", MethodSig.CreateStatic(context.Module.CorLibTypes.Boolean),
                new TypeRefUser(context.Module, "System", "OperatingSystem", context.Module.CorLibTypes.AssemblyRef));
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.Contains(native, context.Module.GetTypes());
    }

    [DotfuscatorV2CorpusTheory]
    [InlineData("missing-environment")]
    [InlineData("tampered-environment")]
    [InlineData("different-environment")]
    [InlineData("unknown-native")]
    [InlineData("modified-decoder")]
    [InlineData("modified-marshalling")]
    [InlineData("modified-import")]
    [InlineData("modified-library")]
    [InlineData("modified-export")]
    public void UnknownOrMismatchedInputsRefuseWithoutRewriting(string failure)
    {
        var directory = CopyOriginal();
        try
        {
            var path = Path.Combine(directory, "Probe.exe");
            using (var original = ModuleDefMD.Load(path))
            {
                var runtime = Assert.Single(DotfuscatorV2Shape.Find(original));
                var environmentPath = Path.Combine(directory, runtime.EnvironmentFile);
                var bytes = File.ReadAllBytes(environmentPath);
                Assert.True(DotfuscatorV2Codec.ValidateEnvironment(bytes, runtime.Seed, out _));
                if (failure == "missing-environment") File.Delete(environmentPath);
                if (failure == "tampered-environment") { bytes[100] ^= 1; File.WriteAllBytes(environmentPath, bytes); }
                if (failure == "different-environment")
                {
                    var other = Manifest.Samples.Single(sample => sample.Id == "net48-native-combined");
                    File.Copy(Path.Combine(Path.GetDirectoryName(Path.Combine(Samples, other.LocalName))!, runtime.EnvironmentFile), environmentPath, true);
                }
                if (failure == "unknown-native") File.WriteAllBytes(Path.Combine(directory, "runtimes", "win-x64", "native", "Runtime.Extensions.dll"), [0]);
                if (failure == "modified-decoder")
                {
                    var state = new FieldDefUser("ApplicationState", new FieldSig(original.CorLibTypes.Int32), FieldAttributes.Static);
                    runtime.Decoder.DeclaringType.Fields.Add(state);
                    runtime.Decoder.Body.Instructions.Insert(0, OpCodes.Ldc_I4_1.ToInstruction());
                    runtime.Decoder.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(state));
                }
                var import = runtime.NativeType.Methods.Single(method => method.ImplMap?.Name == "__eck");
                if (failure == "modified-marshalling") import.ParamDefs.Single(parameter => parameter.Sequence == 5).Attributes = ParamAttributes.In;
                if (failure == "modified-import") import.ImplMap.Attributes = PInvokeAttributes.CallConvStdcall;
                if (failure is "modified-library" or "modified-export")
                {
                    var systemImport = original.GetTypes().SelectMany(type => type.Methods).Single(method => method.ImplMap?.Name == "SetDllDirectoryW");
                    if (failure == "modified-library") systemImport.ImplMap.Module.Name = "unknown-system.dll";
                    else systemImport.ImplMap.Name = "SetDllDirectoryUnknown";
                }
                if (failure.StartsWith("modified-", StringComparison.Ordinal)) original.Write(path + ".changed");
            }
            if (failure.StartsWith("modified-", StringComparison.Ordinal)) File.Move(path + ".changed", path, true);
            using var context = ArtifactContext.Load(path);
            new DotfuscatorDetectionPass().Run(context);
            var before = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
                .ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new DotfuscatorV2StringPass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status);
            Assert.Equal(0, result.Changes);
            Assert.All(before, item => Assert.True(item.Value.StructurallyEquals(item.Key)));
            Assert.Empty(context.Changes);
            var pipeline = new CilantroPipeline().Run(path, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.exe"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.False(pipeline.Success);
            Assert.Null(pipeline.OutputPath);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [DotfuscatorV2CorpusFact]
    public void WindowsSystemLibraryCaseDoesNotChangeTheReviewedDecoderGraph()
    {
        var input = Path.Combine(Samples, Manifest.Samples.Single(sample => sample.Id == "net48-native-strings").LocalName);
        using var module = ModuleDefMD.Load(input);
        var original = Assert.Single(DotfuscatorV2Shape.Find(module));
        Assert.True(DotfuscatorV2Shape.Supported(original));
        var import = module.GetTypes().SelectMany(type => type.Methods).Single(method => method.ImplMap?.Name == "SetDllDirectoryW");
        foreach (var name in new[] { "Kernel32.dll", "KERNEL32.DLL", "kernel32.dll" })
        {
            import.ImplMap.Module.Name = name;
            Assert.Equal(original.Fingerprint, Assert.Single(DotfuscatorV2Shape.Find(module)).Fingerprint);
        }
    }

    [DotfuscatorV2CorpusFact]
    public void PartialRecoveryCannotEmitWithAnUnresolvedKeyArgument()
    {
        var directory = CopyOriginal();
        try
        {
            var path = Path.Combine(directory, "Probe.exe");
            using (var original = ModuleDefMD.Load(path))
            {
                var runtime = Assert.Single(DotfuscatorV2Shape.Find(original));
                var caller = original.EntryPoint;
                var call = caller.Body.Instructions.First(i => i.Operand is IMethod method && method.ResolveMethodDef() == runtime.Decoder);
                var parts = new Local(runtime.Parts.ReturnType);
                caller.Body.Variables.Add(parts);
                var at = caller.Body.Instructions.IndexOf(call);
                caller.Body.Instructions.Insert(at++, OpCodes.Stloc.ToInstruction(parts));
                caller.Body.Instructions.Insert(at, OpCodes.Ldloc.ToInstruction(parts));
                caller.Body.SimplifyBranches();
                original.Write(path + ".changed");
            }
            File.Move(path + ".changed", path, true);
            using var context = ArtifactContext.Load(path);
            new DotfuscatorDetectionPass().Run(context);
            var result = new DotfuscatorV2StringPass().Run(context);
            Assert.Equal(PassStatus.Partial, result.Status);
            Assert.Equal(18, result.Changes);
            var pipeline = new CilantroPipeline().Run(path, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.exe"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.False(pipeline.Success);
            Assert.Null(pipeline.OutputPath);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [DotfuscatorV2CorpusFact]
    public void ApplicationInitializerAndFreshStringsSurviveRecovery()
    {
        var directory = CopyOriginal();
        try
        {
            var path = Path.Combine(directory, "Probe.exe");
            using (var original = ModuleDefMD.Load(path))
            {
                var owner = Assert.Single(DotfuscatorV2Shape.Find(original)).Decoder.DeclaringType;
                var state = new FieldDefUser("Initialized", new FieldSig(original.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public);
                owner.Fields.Add(state);
                var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(original.CorLibTypes.Void),
                    MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
                owner.Methods.Add(initializer);
                foreach (var i in new[] { OpCodes.Ldc_I4.ToInstruction(42), OpCodes.Stsfld.ToInstruction(state), OpCodes.Ret.ToInstruction() }) initializer.Body.Instructions.Add(i);
                original.Write(path + ".changed");
            }
            File.Move(path + ".changed", path, true);
            using var context = ArtifactContext.Load(path);
            new DotfuscatorDetectionPass().Run(context);
            Assert.Equal(19, new DotfuscatorV2StringPass().Run(context).Changes);
            // Only this source-built benign, cleaned fixture is loaded. Recovery
            // itself never loads this assembly or its native runtime.
            using var stream = new MemoryStream(); context.Module.Write(stream); stream.Position = 0;
            var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), true);
            try
            {
                var assembly = loader.LoadFromStream(stream);
                var method = assembly.GetType("Probe.Program")!.GetMethod("DescribeCampaign")!;
                var first = (string)method.Invoke(null, null)!;
                var second = (string)method.Invoke(null, null)!;
                Assert.Equal(first, second);
                Assert.False(ReferenceEquals(first, second));
                Assert.StartsWith("PROBE_STR_04", first, StringComparison.Ordinal);
                Assert.Equal(42, assembly.GetType("Probe.RecoveryGroundTruth")!.GetField("Initialized")!.GetValue(null));
            }
            finally { loader.Unload(); }
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static string CopyOriginal()
    {
        var sample = Manifest.Samples.Single(entry => entry.Id == "net48-native-original");
        var input = Path.Combine(Samples, sample.LocalName);
        var source = Path.GetDirectoryName(input)!;
        var directory = Directory.CreateTempSubdirectory("Cilantro.V2Refusal.").FullName;
        Directory.CreateDirectory(Path.Combine(directory, "runtimes", "win-x64", "native"));
        File.Copy(input, Path.Combine(directory, "Probe.exe"));
        File.Copy(Path.Combine(source, "environment0f617e02.bin"), Path.Combine(directory, "environment0f617e02.bin"));
        File.Copy(Path.Combine(source, "runtimes", "win-x64", "native", "Runtime.Extensions.dll"), Path.Combine(directory, "runtimes", "win-x64", "native", "Runtime.Extensions.dll"));
        return directory;
    }

    private static HashSet<string> Literals(ModuleDef module) => module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
        .SelectMany(method => method.Body.Instructions).Where(i => i.OpCode.Code == Code.Ldstr).Select(i => (string)i.Operand).ToHashSet(StringComparer.Ordinal);
}

public sealed class DotfuscatorV2CorpusFactAttribute : FactAttribute
{
    public DotfuscatorV2CorpusFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_V2_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_DOTFUSCATOR_V2_SAMPLES to the native v2 corpus including signed environment/native companions.";
    }
}

public sealed class DotfuscatorV2CorpusTheoryAttribute : TheoryAttribute
{
    public DotfuscatorV2CorpusTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_V2_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_DOTFUSCATOR_V2_SAMPLES to the native v2 corpus including signed environment/native companions.";
    }
}
