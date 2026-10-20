using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class LiteralStringDecoderPassTests
{
    [Theory]
    [InlineData(false, false, 3)]
    [InlineData(true, false, 3)]
    [InlineData(false, true, 0)]
    public void DotfuscatorEntryPointPreservesValuesInitializationAndEffects(bool initialize, bool writes, int changes)
    {
        // Synthetic decoder contract, not a claim about a captured vendor build.
        using var context = Fixture(initialize, writes, dotfuscator: true);
        context.SetFact("dotfuscator.structure", new Cilantro.Core.Analysis.DotfuscatorStructureFacts(true, "synthetic"));
        var before = Invoke(context, interned: true);
        var otherBefore = Invoke(context, "Other", interned: true);
        var result = new LiteralStringDecoderPass(dotfuscatorOnly: true).Run(context);
        Assert.Equal(changes, result.Changes);
        Assert.Equal(before, Invoke(context, interned: true));
        Assert.Equal(otherBefore, Invoke(context, "Other", interned: true));
        Assert.True(context.TryGetFact<int>("strings.constantSites", out var recorded));
        Assert.Equal(changes, recorded);
    }

    [Fact]
    public void DotfuscatorEntryPointDeclinesWithoutAttribution()
    {
        using var context = Fixture(false, false);
        Assert.Equal(0, new LiteralStringDecoderPass(dotfuscatorOnly: true).Run(context).Changes);
    }

    [Fact]
    public void ThreeArgumentDecoderMustNotReadItsDiscardedArgument()
    {
        using var context = Fixture(false, false, dotfuscator: true);
        context.SetFact("dotfuscator.structure", new Cilantro.Core.Analysis.DotfuscatorStructureFacts(true, "synthetic"));
        var decoder = Find(context, "Decode");
        decoder.Body.Instructions.Insert(0, OpCodes.Ldarg_2.ToInstruction());
        decoder.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        Assert.Equal(0, new LiteralStringDecoderPass(dotfuscatorOnly: true).Run(context).Changes);
    }

    [Fact]
    public void AnAlternateEntryIntoTheArgumentsPreservesTheDecoderCall()
    {
        using var context = Fixture(false, false, dotfuscator: true);
        context.SetFact("dotfuscator.structure", new Cilantro.Core.Analysis.DotfuscatorStructureFacts(true, "synthetic"));
        var caller = Find(context, "Run");
        foreach (var call in caller.Body.Instructions.Where(i => i.OpCode.Code == Code.Call).ToArray())
            caller.Body.Instructions.Insert(caller.Body.Instructions.IndexOf(call), OpCodes.Br.ToInstruction(call));
        var before = Invoke(context, interned: true);
        Assert.Equal(1, new LiteralStringDecoderPass(dotfuscatorOnly: true).Run(context).Changes); // Other only.
        Assert.Equal(before, Invoke(context, interned: true));
        Assert.Equal(2, caller.Body.Instructions.Count(i => i.OpCode.Code == Code.Call && i.Operand is IMethod m && m.Name == "Decode"));
    }

    [Fact]
    public void BabelDecoderRunsBeforeUnpackingAndPreservesItsResult()
    {
        using var context = Fixture(false, false);
        context.SetFact("babel.structure", new Cilantro.Core.Analysis.BabelStructureFacts(true, false, 0, false, 0.99));
        var before = Invoke(context);
        var result = new LiteralStringDecoderPass(babelOnly: true).Run(context);
        Assert.Equal(3, result.Changes);
        Assert.Equal(before, Invoke(context));
        var passes = CilantroPipeline.CreateDefaultPasses().Select(pass => pass.Name).ToList();
        Assert.True(passes.IndexOf("babel-literal-strings") < passes.IndexOf("payload-extraction"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NestedDecodersExposeTextAndPreserveInitialization(bool initialize)
    {
        using var context = Fixture(initialize, false);
        var before = Invoke(context);
        var otherBefore = Invoke(context, "Other");
        var result = new LiteralStringDecoderPass().Run(context);
        Assert.Equal(3, result.Changes);
        Assert.Equal(before, Invoke(context));
        Assert.Equal(otherBefore, Invoke(context, "Other"));
        var caller = Find(context, "Run");
        Assert.DoesNotContain(caller.Body.Instructions, i => i.Operand is IMethod m && m.Name == "Decode");
        Assert.Contains(caller.Body.Instructions, i => i.OpCode.Code == Code.Ldstr && (string)i.Operand == "a");
        if (initialize) Assert.Contains(caller.Body.Instructions, i => i.Operand is IMethod m && m.Name == "RunClassConstructor");
    }

    [Fact]
    public void DecoderWithApplicationStateWriteKeepsItsCall()
    {
        using var context = Fixture(false, true);
        var before = Invoke(context);
        Assert.Equal(0, new LiteralStringDecoderPass().Run(context).Changes);
        Assert.Equal(before, Invoke(context));
    }

    [Fact]
    public void DecoderMutatingAnExistingArrayKeepsItsCall()
    {
        using var context = Fixture(false, false, true);
        var before = Invoke(context);
        Assert.Equal(0, new LiteralStringDecoderPass().Run(context).Changes);
        Assert.Equal(before, Invoke(context));
    }

    private static ArtifactContext Fixture(bool initialize, bool writes, bool mutateArray = false, bool dotfuscator = false) => SyntheticContext.Build(module =>
    {
        var host = SyntheticContext.AddType(module, "Host"); host.Attributes = TypeAttributes.Public;
        var counter = new FieldDefUser("Count", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static);
        host.Fields.Add(counter);
        var type = SyntheticContext.AddType(module, "Decoder");
        var state = new FieldDefUser("State", new FieldSig(new SZArraySig(module.CorLibTypes.Byte)), FieldAttributes.Private | FieldAttributes.Static);
        if (mutateArray) type.Fields.Add(state);
        if (initialize || mutateArray)
        {
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
            type.Methods.Add(cctor);
            if (initialize) Add(cctor, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(counter));
            if (mutateArray) Add(cctor, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef), OpCodes.Stsfld.ToInstruction(state));
            Add(cctor, OpCodes.Ret.ToInstruction());
        }
        var decode = new MethodDefUser("Decode", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.String, module.CorLibTypes.Int32),
            MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody { InitLocals = true } };
        type.Methods.Add(decode);
        if (dotfuscator) decode.MethodSig.Params.Add(module.CorLibTypes.String);
        var chars = new Local(new SZArraySig(module.CorLibTypes.Char)); decode.Body.Variables.Add(chars);
        var toChars = new MemberRefUser(module, "ToCharArray", MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Char)), module.CorLibTypes.String.TypeDefOrRef);
        var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.Char)), module.CorLibTypes.String.TypeDefOrRef);
        if (writes) Add(decode, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(counter));
        if (mutateArray) Add(decode, OpCodes.Ldsfld.ToInstruction(state), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stelem_I1.ToInstruction());
        Add(decode, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Callvirt.ToInstruction(toChars), OpCodes.Stloc.ToInstruction(chars),
            OpCodes.Ldloc.ToInstruction(chars), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldloc.ToInstruction(chars), OpCodes.Ldc_I4_0.ToInstruction(),
            OpCodes.Ldelem_U2.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Xor.ToInstruction(), OpCodes.Conv_U2.ToInstruction(),
            OpCodes.Stelem_I2.ToInstruction(), OpCodes.Ldloc.ToInstruction(chars), OpCodes.Newobj.ToInstruction(ctor), OpCodes.Ret.ToInstruction());
        var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.String), MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody() };
        host.Methods.Add(run);
        Add(run, OpCodes.Ldstr.ToInstruction("a"), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Call.ToInstruction(decode),
            OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Call.ToInstruction(decode), OpCodes.Ret.ToInstruction());
        var other = new MethodDefUser("Other", MethodSig.CreateStatic(module.CorLibTypes.String), MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody() };
        host.Methods.Add(other);
        Add(other, OpCodes.Ldstr.ToInstruction("b"), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Call.ToInstruction(decode), OpCodes.Ret.ToInstruction());
        if (dotfuscator)
        {
            var intern = new MemberRefUser(module, "Intern", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.String), module.CorLibTypes.String.TypeDefOrRef);
            decode.Body.Instructions.Insert(decode.Body.Instructions.Count - 1, OpCodes.Call.ToInstruction(intern));
            foreach (var caller in new[] { run, other })
                foreach (var call in caller.Body.Instructions.Where(i => i.OpCode.Code == Code.Call && i.Operand == decode).ToArray())
                    caller.Body.Instructions.Insert(caller.Body.Instructions.IndexOf(call), OpCodes.Ldstr.ToInstruction("unused"));
        }
    });

    private static MethodDef Find(ArtifactContext c, string name) => c.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == name);
    private static (string, int) Invoke(ArtifactContext context, string method = "Run", bool interned = false)
    {
        // Only this source-built benign fixture is executed.
        using var stream = new MemoryStream(); context.Module.Write(stream); stream.Position = 0;
        var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), true);
        try
        {
            var type = loader.LoadFromStream(stream).GetType("Synthetic.Host")!;
            var value = (string)type.GetMethod(method)!.Invoke(null, null)!;
            Assert.Equal(interned, ReferenceEquals(value, type.GetMethod(method)!.Invoke(null, null)));
            return (value, (int)type.GetField("Count")!.GetValue(null)!);
        }
        finally { loader.Unload(); }
    }
    private static void Add(MethodDef m, params Instruction[] il) { foreach (var i in il) m.Body.Instructions.Add(i); }
}
