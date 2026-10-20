using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorResponseRetirementTests
{
    private static string Input(string manifest = "dotfuscator-7-checks", string id = "net48-debug-method") =>
        Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_CHECK_SAMPLES")!,
            CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", manifest + ".manifest.json")).Samples.Single(sample => sample.Id == id).LocalName);
    private static TypeDef ExceptionType(ModuleDef module) => module.GetTypes().Single(type => type.BaseType?.FullName == "System.Exception");
    private static MethodDef Failure(ModuleDef module) => module.GetTypes().SelectMany(type => type.Methods).Single(method => method.HasBody &&
        method.Body.Instructions.Any(instruction => instruction.OpCode.Code == Code.Newobj && instruction.Operand is IMethod called && called.DeclaringType.ResolveTypeDef() == ExceptionType(module)));
    private static MethodDef Empty(ModuleDef module) => Failure(module).DeclaringType.Methods.Single(method => method.IsPrivate && method.IsStatic &&
        method.MethodSig.Params.Count == 0 && method.HasBody && method.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop)
            .Select(instruction => instruction.OpCode.Code).SequenceEqual([Code.Ret]));

    [DotfuscatorCheckCorpusTheory]
    [InlineData("dotfuscator-7-checks", "net48-debug-method")]
    [InlineData("dotfuscator-7-checks", "net8.0-debug-method")]
    [InlineData("dotfuscator-7-checks", "net10.0-debug-method")]
    [InlineData("dotfuscator-7-check-interactions", "net48-combined-renamed")]
    [InlineData("dotfuscator-7-check-interactions", "net8.0-combined-native")]
    [InlineData("dotfuscator-7-check-interactions", "net10.0-combined-renamed")]
    [InlineData("dotfuscator-7-root-checks", "net10.0-root-method")]
    [InlineData("dotfuscator-7-root-checks", "net10.0-root-native")]
    public void ACheckDerivedSelectorAttributesTheCompleteException(string manifest, string id)
    {
        using var context = ArtifactContext.Load(Input(manifest, id));
        Assert.Empty(RetiredDotfuscatorResponseRuntime.Unused(context));
        Recover(context);
        Assert.Same(ExceptionType(context.Module), Assert.Single(RetiredDotfuscatorResponseRuntime.Unused(context)));
    }

    [DotfuscatorCheckCorpusFact]
    public void ALiteralSelectorConfersNoResponseOwnership()
    {
        Temporary(module =>
        {
            var guarded = module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Guarded");
            var load = guarded.Body.Instructions.Last(instruction => instruction.IsLdloc() && instruction.GetLocal(guarded.Body.Variables)?.Index == 0);
            load.OpCode = OpCodes.Ldc_I4; load.Operand = 1483055301;
        }, context =>
        {
            Recover(context);
            Assert.Empty(RetiredDotfuscatorResponseRuntime.Unused(context));
            Assert.DoesNotContain(Failure(context.Module).MDToken.Raw, RecoveryOrphans.Of(context));
        });
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("effect")]
    [InlineData("field")]
    [InlineData("attribute")]
    [InlineData("scope")]
    [InlineData("failure")]
    [InlineData("empty")]
    public void ChangedOriginalTypesOrResponsesRemainUnattributed(string change)
    {
        Temporary(module =>
        {
            var type = ExceptionType(module);
            if (change == "effect") Effect(type.Methods.Single(method => method.IsConstructor));
            if (change == "field") type.Fields.Add(new FieldDefUser("ApplicationState", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public));
            if (change == "attribute") type.CustomAttributes.Add(new CustomAttribute((ICustomAttributeType)new Importer(module).Import(typeof(ObsoleteAttribute).GetConstructor(Type.EmptyTypes)!)));
            if (change == "scope") type.BaseType = new TypeRefUser(module, "System", "Exception", new AssemblyRefUser("Foreign"));
            if (change == "failure") Effect(Failure(module));
            if (change == "empty") Effect(Empty(module));
        }, context =>
        {
            Recover(context);
            Assert.Empty(RetiredDotfuscatorResponseRuntime.Unused(context));
        });
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("body")]
    [InlineData("metadata")]
    [InlineData("message")]
    [InlineData("failure")]
    [InlineData("empty")]
    [InlineData("reflection")]
    public void LaterChangesOrReflectionVetoWholeTypeRetirement(string change)
    {
        using var context = ArtifactContext.Load(Input());
        Recover(context);
        var type = Assert.Single(RetiredDotfuscatorResponseRuntime.Unused(context));
        if (change == "body") Effect(type.Methods.Single(method => method.IsConstructor));
        if (change == "metadata") type.Attributes ^= TypeAttributes.Sealed;
        if (change == "message")
        {
            var message = type.Methods.Single(method => method.IsConstructor).Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Ldstr);
            var display = type.Methods.Single(method => method.Name == "ToString").Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Ldstr);
            display.Operand = ((string)display.Operand).Replace((string)message.Operand, "Changed message", StringComparison.Ordinal);
            message.Operand = "Changed message";
        }
        if (change == "failure") Effect(Failure(context.Module));
        if (change == "empty") Effect(Empty(context.Module));
        if (change == "reflection")
        {
            context.Module.EntryPoint.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction(type.ReflectionFullName + ", " + context.Module.Assembly.FullName));
            context.Module.EntryPoint.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        Assert.Empty(RetiredDotfuscatorResponseRuntime.Unused(context));
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("handle")]
    [InlineData("field")]
    [InlineData("construct")]
    [InlineData("call")]
    [InlineData("method-handle")]
    [InlineData("method-name")]
    public void SurvivingApplicationConsumersKeepTheException(string use)
    {
        using var context = ArtifactContext.Load(Input());
        Recover(context);
        var type = Assert.Single(RetiredDotfuscatorResponseRuntime.Unused(context));
        var main = context.Module.EntryPoint;
        if (use == "field") main.DeclaringType.Fields.Add(new FieldDefUser("ApplicationState", new FieldSig(new ClassSig(type)), FieldAttributes.Public | FieldAttributes.Static));
        else
        {
            if (use == "method-name")
            {
                main.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(main.DeclaringType));
                main.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
                main.Body.Instructions.Insert(2, OpCodes.Ldstr.ToInstruction(Failure(context.Module).Name.String));
                main.Body.Instructions.Insert(3, OpCodes.Pop.ToInstruction());
            }
            else if (use == "call") main.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(Failure(context.Module)));
            else
            {
                main.Body.Instructions.Insert(0, use == "handle" ? OpCodes.Ldtoken.ToInstruction(type) : use == "method-handle" ?
                    OpCodes.Ldtoken.ToInstruction(Failure(context.Module)) : OpCodes.Newobj.ToInstruction(type.Methods.Single(method => method.IsConstructor)));
                main.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
            }
        }
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.Contains(type, context.Module.GetTypes());
    }

    private static void Recover(ArtifactContext context)
    {
        new DotfuscatorDetectionPass().Run(context);
        Assert.Equal(PassStatus.Success, new DotfuscatorCheckPass().Run(context).Status);
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void RepeatedCleanupRequiresRecordedRemovalOfVerifiedResponses(bool validated, bool recorded)
    {
        using var context = ArtifactContext.Load(Input());
        Recover(context);
        var type = ExceptionType(context.Module);
        if (validated) Assert.Same(type, Assert.Single(RetiredDotfuscatorResponseRuntime.Unused(context)));
        var failure = Failure(context.Module); var empty = Empty(context.Module);
        var tokens = new HashSet<uint> { failure.MDToken.Raw, empty.MDToken.Raw };
        foreach (var method in context.Module.GetTypes().SelectMany(owner => owner.Methods).Where(method => method.HasBody))
            foreach (var instruction in method.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Call &&
                         instruction.Operand is IMethod called && (called.ResolveMethodDef() == failure || called.ResolveMethodDef() == empty)))
            { instruction.OpCode = OpCodes.Nop; instruction.Operand = null; }
        failure.DeclaringType.Methods.Remove(failure); empty.DeclaringType.Methods.Remove(empty);
        if (recorded) context.SetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", tokens);
        Assert.Equal(validated && recorded, RetiredDotfuscatorResponseRuntime.Unused(context).Contains(type));
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.Equal(validated && recorded, !context.Module.GetTypes().Contains(type));
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("body", true)]
    [InlineData("call-scope", false)]
    public void NativeDependencyBodiesAndExceptionCallBindingsHaveIndependentProofs(string change, bool retainedProof)
    {
        using var context = ArtifactContext.Load(Input("dotfuscator-7-check-interactions", "net8.0-combined-native"));
        Recover(context);
        var type = Assert.Single(RetiredDotfuscatorResponseRuntime.Unused(context));
        var bridge = Assert.Single(DotfuscatorV2Shape.Find(context.Module)).NativeType;
        if (change == "body") Effect(bridge.Methods.Single(method => method.Name == "ComputeKey"));
        else
        {
            var call = type.Methods.Where(method => method.HasBody).SelectMany(method => method.Body.Instructions)
                .Single(instruction => instruction.Operand is IMethod called && called.DeclaringType.ResolveTypeDef() == bridge);
            var original = (IMethod)call.Operand;
            call.Operand = new MemberRefUser(context.Module, original.Name, original.MethodSig,
                new TypeRefUser(context.Module, bridge.Namespace, bridge.Name, new AssemblyRefUser("Foreign")));
        }
        Assert.Equal(retainedProof, RetiredDotfuscatorResponseRuntime.Unused(context).Contains(type));
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData(true, false, true)]
    [InlineData(false, false, false)]
    [InlineData(true, true, false)]
    public void RetiredDecoderMembersRequireRecordedRemovalAndIntactRemainingDeclarations(bool recorded, bool changed, bool allowed)
    {
        using var context = ArtifactContext.Load(Input("dotfuscator-7-check-interactions", "net8.0-combined-native"));
        Recover(context);
        var type = Assert.Single(RetiredDotfuscatorResponseRuntime.Unused(context));
        Assert.Equal(PassStatus.Success, new DotfuscatorControlFlowPass().Run(context).Status);
        var decoded = new DotfuscatorV2StringPass().Run(context);
        Assert.True(decoded.Status == PassStatus.Success && decoded.Changes > 0, string.Join(";", decoded.Diagnostics));
        var decoders = type.Methods.Where(method => !method.IsConstructor && method.Name != "ToString" && method.Name != "get_StackTrace").ToArray();
        Assert.Equal(9, decoders.Length);
        var removed = decoders.Select(method => method.MDToken.Raw).ToHashSet();
        foreach (var method in decoders) type.Methods.Remove(method);
        if (recorded) context.SetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", removed);
        if (changed) type.Attributes ^= TypeAttributes.Sealed;
        Assert.True(allowed == RetiredDotfuscatorResponseRuntime.Unused(context).Contains(type), System.Text.Json.JsonSerializer.Serialize(context.Evidence));
    }

    private static void Effect(MethodDef method)
    {
        method.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("changed"));
        method.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(new Importer(method.Module).Import(typeof(Console).GetMethod(nameof(Console.WriteLine), [typeof(string)])!)));
    }

    private static void Temporary(Action<ModuleDefMD> rewrite, Action<ArtifactContext> verify)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.Response.").FullName;
        try
        {
            var path = Path.Combine(directory, "CheckProbe.exe");
            using (var module = ModuleDefMD.Load(Input())) { rewrite(module); module.Write(path); }
            using var context = ArtifactContext.Load(path); verify(context);
        }
        finally { Directory.Delete(directory, true); }
    }
}
