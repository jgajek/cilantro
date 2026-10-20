using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelMethodImageTests
{
    private static string Sample(string id)
    {
        var manifest = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-baseline.manifest.json"));
        return Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!, manifest.Samples.Single(sample => sample.Id == id).LocalName);
    }

    [Babel12CorpusTheory]
    [InlineData("net48-code")]
    [InlineData("net8.0-code")]
    [InlineData("net10.0-code")]
    [InlineData("net48-combined")]
    [InlineData("net8.0-combined")]
    [InlineData("net10.0-combined")]
    public void ActualInvocationRestoresCodeAndExceptionClauses(string id)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new BabelDetectionPass().Run(context);
        Assert.Equal(PassStatus.Success, new BabelCheckPass().Run(context).Status);
        var result = new BabelMethodImagePass().Run(context);
        Assert.True(result.Status == PassStatus.Success, string.Join("; ", result.Diagnostics));
        Assert.Equal(1, result.Changes);
        Assert.True(context.TryGetFact<IReadOnlyList<BabelMethodImageResourceOwnership.Pending>>(BabelMethodImageResourceOwnership.Fact, out var resourceInputs));
        var input = Assert.Single(resourceInputs!);
        Assert.Equal(id.EndsWith("-code", StringComparison.Ordinal), input.Published);
        Assert.Single(input.Readers);
        var method = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Encrypted");
        Assert.Equal(2, method.Body.ExceptionHandlers.Count);
        Assert.Contains(method.Body.ExceptionHandlers, handler => handler.HandlerType == ExceptionHandlerType.Finally);
        Assert.Contains(method.Body.ExceptionHandlers, handler => handler.CatchType?.FullName == "System.ArgumentException");
        Assert.DoesNotContain(method.Body.Instructions, instruction => instruction.Operand is IMethod called && called.MethodSig?.Params.Count == 4 &&
            called.MethodSig.Params[1].FullName == "System.Reflection.MethodBase");
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        if (!id.EndsWith("-code", StringComparison.Ordinal)) return;
        Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out var why), why);
        var expected = new[] { -65, -7, 3, 90, 21928, -7, 139, 5 };
        var inputs = new[] { -4, -1, 0, 1, 2, 3, 8, 17 };
        for (var index = 0; index < inputs.Length; index++)
        {
            var answer = machine!.Execute(method, [StaticValue.FromInt32(inputs[index])]);
            Assert.True(answer.Succeeded, answer.Diagnostic);
            Assert.Equal(expected[index], answer.Value.AsInt32());
        }
        var calls = method.DeclaringType.Fields.Single(field => field.Name == "calls");
        Assert.Equal(8, machine!.State.ReadStaticField(calls).AsInt32());
        context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(1, new ProtectorResourceCleanupPass().Run(context).Changes);
        Assert.DoesNotContain(context.Module.Resources, resource => resource.Name == input.Source.Name);
        Assert.Equal("BabelProbe.Secret.txt", Assert.Single(context.Module.Resources).Name.String);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed);
    }

    [Babel12CorpusTheory]
    [InlineData("net48-checks")]
    [InlineData("net8.0-checks")]
    [InlineData("net10.0-checks")]
    [InlineData("net48-combined")]
    [InlineData("net8.0-combined")]
    [InlineData("net10.0-combined")]
    public void ReviewedChecksAreNeutralizedAndAttributed(string id)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new BabelDetectionPass().Run(context);
        var result = new BabelCheckPass().Run(context);
        Assert.True(result.Status == PassStatus.Success, string.Join("; ", result.Diagnostics));
        Assert.True(result.Changes >= 2);
        Assert.True(context.TryGetFact<HashSet<uint>>(BabelCheckPass.NeutralizedFact, out var neutralized));
        Assert.Equal(2, neutralized!.Count);
        Assert.All(neutralized, token => Assert.Equal(Code.Ret, Assert.Single(((MethodDef)context.Module.ResolveToken(token)).Body.Instructions).OpCode.Code));
        Assert.NotEmpty(RecoveryOrphans.Of(context));
    }

    [Babel12CorpusTheory]
    [InlineData("argument")]
    [InlineData("return")]
    [InlineData("adapter")]
    public void ChangedArgumentOrReturnAdaptationCannotBeRestored(string change)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelImageRefusal.").FullName;
        try
        {
            var path = Path.Combine(directory, "BabelProbe.exe");
            using (var module = ModuleDefMD.Load(Sample("net48-code")))
            {
                var method = module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Encrypted");
                if (change == "argument")
                {
                    var input = method.Body.Instructions.First(instruction => instruction.IsLdarg());
                    input.OpCode = OpCodes.Ldc_I4_1; input.Operand = null;
                }
                if (change == "return")
                {
                    method.Body.Instructions.Insert(method.Body.Instructions.Count - 1, OpCodes.Pop.ToInstruction());
                    method.Body.Instructions.Insert(method.Body.Instructions.Count - 1, OpCodes.Ldc_I4_0.ToInstruction());
                }
                if (change == "adapter")
                {
                    var adapters = module.GetTypes().SelectMany(type => type.Methods).Where(candidate => candidate.HasBody &&
                        candidate.MethodSig is { HasThis: true, Params.Count: 2 } signature &&
                        signature.Params[0].FullName == "System.Object" && signature.Params[1].FullName == "System.Object[]" && candidate.Body.Instructions.Any(instruction =>
                        instruction.Operand is IMethod called && called.FullName == "System.Object System.Delegate::DynamicInvoke(System.Object[])" )).ToArray();
                    Assert.NotEmpty(adapters);
                    Instruction[] prefix = [OpCodes.Ldarg_2.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldarg_2.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(),
                        OpCodes.Ldelem_Ref.ToInstruction(), OpCodes.Unbox_Any.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Add.ToInstruction(),
                        OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef), OpCodes.Stelem_Ref.ToInstruction()];
                    foreach (var adapter in adapters)
                        for (var index = 0; index < prefix.Length; index++) adapter.Body.Instructions.Insert(index, new Instruction(prefix[index].OpCode, prefix[index].Operand));
                }
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            new BabelDetectionPass().Run(context);
            var original = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Encrypted");
            var snapshot = MethodBodySnapshot.Capture(original);
            var result = new BabelMethodImagePass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status);
            Assert.Equal(0, result.Changes);
            Assert.True(snapshot.StructurallyEquals(original));
            Assert.Empty(context.Changes);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EmptyOrUnresolvedRawBodiesCannotBeAssembled(bool unresolved)
    {
        using var module = new ModuleDefUser("capture");
        var capture = new RawDynamicMethodIntrinsic.Capture { Returns = module.CorLibTypes.Void, Parameters = [], Locals = [],
            Code = unresolved ? [0x28, 1, 0, 0, 6, 0x2A] : [] };
        Assert.Throws<InvalidOperationException>(() => RawDynamicMethodIntrinsic.Assemble(module, capture));
    }

    [Babel12CorpusTheory]
    [InlineData("instructions")]
    [InlineData("import")]
    [InlineData("integrity-binding")]
    public void ChangedChecksDeclineAtomicallyAndWithholdEmission(string change)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelCheckRefusal.").FullName;
        try
        {
            var path = Path.Combine(directory, "BabelProbe.exe");
            using (var module = ModuleDefMD.Load(Sample("net48-checks")))
            {
                var checks = BabelCheckShape.Find(module).ToArray();
                var debug = checks.Single(check => check.Kind == "debugging");
                if (change == "instructions") debug.Method.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
                if (change == "import")
                    debug.Graph.Types.SelectMany(type => type.Methods).First(method => method.IsPinvokeImpl).ImplMap.Attributes = PInvokeAttributes.CallConvCdecl;
                // All bytes of this checksum-bound PE change when it is rewritten,
                // while the integer-normalized checker shape remains identical.
                if (change == "integrity-binding")
                {
                    var app = module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Encrypted");
                    app.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
                }
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            new BabelDetectionPass().Run(context);
            var snapshots = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new BabelCheckPass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status);
            Assert.Equal(0, result.Changes);
            Assert.All(snapshots, item => Assert.True(item.Value.StructurallyEquals(item.Key)));
            Assert.Empty(context.Changes);
            var pipeline = new CilantroPipeline().Run(path, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.exe"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.False(pipeline.Success);
            Assert.Null(pipeline.OutputPath);
        }
        finally { Directory.Delete(directory, true); }
    }
}

public sealed class Babel12CorpusTheoryAttribute : TheoryAttribute
{
    public Babel12CorpusTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_BABEL12_SAMPLES to the pinned Babel 12 source-built corpus.";
    }
}
