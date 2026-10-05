using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorGuardCompletionTests
{
    [Fact]
    public void GeneralReflectionRefusalRemainsInForce()
    {
        using var context = Fixture("normal");
        var module = context.Module;
        var reflection = module.CorLibTypes.GetTypeRef("System.Reflection", "FieldInfo");
        var setter = New(Method(context, "Run").DeclaringType, "ReflectiveSetter", module.CorLibTypes.Void,
            reflection.ToTypeSig(), module.CorLibTypes.Object, module.CorLibTypes.Object);
        Add(setter, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Ldarg_2.ToInstruction(),
            OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "SetValue", MethodSig.CreateInstance(module.CorLibTypes.Void,
                module.CorLibTypes.Object, module.CorLibTypes.Object), reflection)), OpCodes.Ret.ToInstruction());
        Assert.NotNull(FieldWriteSafety.Analyze(module).Refusal);
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(3, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.NotNull(FieldWriteSafety.Analyze(module).Refusal);
        Assert.Contains(setter.Body.Instructions, i => i.Operand is IMethod m && m.Name == "SetValue");
    }

    [Theory]
    [InlineData("normal")]
    [InlineData("throw")]
    public void FailedCheckDoesNotSuppressCheckInCatchHandler(string prefix)
    {
        using var context = Fixture(prefix);
        var run = Method(context, "Run");
        var pool = context.Module.GetTypes().Single(t => t.Name == "Pool");
        var root = pool.Fields.Single(f => f.IsStatic);
        var field = pool.Fields.First(f => !f.IsStatic);
        var start = OpCodes.Ldsfld.ToInstruction(root); var handler = OpCodes.Pop.ToInstruction(); var end = Instruction.CreateLdcI4(7);
        run.Body = new CilBody();
        Add(run, start, OpCodes.Ldfld.ToInstruction(field), OpCodes.Pop.ToInstruction(), OpCodes.Leave.ToInstruction(end),
            handler, OpCodes.Ldsfld.ToInstruction(root), OpCodes.Ldfld.ToInstruction(field), OpCodes.Pop.ToInstruction(),
            OpCodes.Leave.ToInstruction(end), end, OpCodes.Ret.ToInstruction());
        run.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = end,
            CatchType = context.Module.CorLibTypes.GetTypeRef("System", "Exception") });
        var before = Invoke(context, 0);
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(2, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.Equal(before, Invoke(context, 0));
        Assert.Equal(2, run.Body.Instructions.Count(i => i.OpCode.Code == Code.Call));
    }

    [Theory]
    [InlineData("normal")]
    [InlineData("throw")]
    [InlineData("reenter")]
    public void RemovesGuardsPreservingInitializationExceptionsAndApplicationSwitch(string prefix)
    {
        using var context = Fixture(prefix);
        var before = new[] { Invoke(context, 0), Invoke(context, 1), Invoke(context, 4) };
        Assert.All(before, r => Assert.EndsWith(":1", r, StringComparison.Ordinal));
        context.SetFact("options.removeRuntime", true);
        var result = new ReactorGuardCompletionPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(3, result.Changes);
        var run = Method(context, "Run");
        Assert.DoesNotContain(run.Body.Instructions, i => i.OpCode.Code == Code.Ldfld);
        Assert.DoesNotContain(run.Body.Instructions, i => i.OpCode.Code is Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S);
        Assert.Single(run.Body.Instructions, i => i.OpCode.Code == Code.Switch);
        Assert.Single(run.Body.Instructions, i => i.OpCode.Code == Code.Call);
        Assert.True(EvaluationStackAnalyzer.Analyze(run).Valid);
        Assert.Equal(before, new[] { Invoke(context, 0), Invoke(context, 1), Invoke(context, 4) });
        Assert.Equal(0, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.True(context.TryGetFact<int>(VirtualizationRebuildPass.AddedMethodsFact, out var added));
        Assert.Equal(1, added);
        Assert.True(context.TryGetFact<int>("cleanup.removedFieldCount", out var removed));
        Assert.Equal(16, removed);
        Assert.Single(context.Module.GetTypes().Single(t => t.Name == "Pool").Fields);
        var verified = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            new RewriteAllowance(AddedMethodCount: added, RemovedFieldCount: removed));
        Assert.True(verified.Passed, string.Join("; ", verified.Diagnostics));
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("unmarked")]
    [InlineData("escape")]
    [InlineData("address")]
    [InlineData("writer")]
    [InlineData("reinitialize")]
    [InlineData("repeat-cctor")]
    [InlineData("function-pointer")]
    [InlineData("type-handle")]
    [InlineData("field-handle")]
    [InlineData("field-name")]
    [InlineData("numeric-token")]
    [InlineData("unknown-initializer")]
    public void RefusesPoolWithoutClosedConstructionAndUses(string refusal)
    {
        using var context = Fixture("normal");
        context.SetFact("options.removeRuntime", refusal != "disabled");
        var owner = context.Module.GetTypes().Single(t => t.Name == "Pool");
        var root = owner.Fields.Single(f => f.IsStatic);
        var field = owner.Fields.First(f => !f.IsStatic);
        var initializer = Method(context, "Initialize");
        var run = Method(context, "Run");
        var injected = new List<Instruction>();
        switch (refusal)
        {
            case "unmarked": initializer.CustomAttributes.Clear(); break;
            case "escape": injected.AddRange([OpCodes.Ldsfld.ToInstruction(root), OpCodes.Call.ToInstruction(
                new MemberRefUser(context.Module, "KeepAlive", MethodSig.CreateStatic(context.Module.CorLibTypes.Void, context.Module.CorLibTypes.Object), context.Module.CorLibTypes.GetTypeRef("System", "GC")))]); break;
            case "address": injected.AddRange([OpCodes.Ldsflda.ToInstruction(root), OpCodes.Pop.ToInstruction()]); break;
            case "writer": injected.AddRange([OpCodes.Ldsfld.ToInstruction(root), Instruction.CreateLdcI4(9), OpCodes.Stfld.ToInstruction(field)]); break;
            case "reinitialize": injected.Add(OpCodes.Call.ToInstruction(initializer)); break;
            case "repeat-cctor": injected.Add(OpCodes.Call.ToInstruction(owner.FindStaticConstructor())); break;
            case "function-pointer": injected.AddRange([OpCodes.Ldftn.ToInstruction(initializer), OpCodes.Pop.ToInstruction()]); break;
            case "type-handle": injected.AddRange([OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Pop.ToInstruction()]); break;
            case "field-handle": injected.AddRange([OpCodes.Ldtoken.ToInstruction(root), OpCodes.Pop.ToInstruction()]); break;
            case "field-name": injected.AddRange([OpCodes.Ldstr.ToInstruction(field.Name.String), OpCodes.Pop.ToInstruction()]); break;
            case "numeric-token":
                injected.AddRange([OpCodes.Ldnull.ToInstruction(), Instruction.CreateLdcI4(unchecked((int)field.MDToken.Raw)),
                    OpCodes.Callvirt.ToInstruction(new MemberRefUser(context.Module, "ResolveField", MethodSig.CreateInstance(
                        context.Module.CorLibTypes.GetTypeRef("System.Reflection", "FieldInfo").ToTypeSig(), context.Module.CorLibTypes.Int32),
                        context.Module.CorLibTypes.GetTypeRef("System.Reflection", "Module"))), OpCodes.Pop.ToInstruction()]); break;
            case "unknown-initializer":
                var value = initializer.Body.Instructions.First(i => i.IsLdcI4());
                value.OpCode = OpCodes.Ldsfld; value.Operand = Method(context, "Prefix").DeclaringType.Fields.Single(); break;
        }
        for (var n = injected.Count - 1; n >= 0; n--) run.Body.Instructions.Insert(0, injected[n]);
        var before = run.Body.Instructions.Select(i => i.ToString()).ToArray();
        Assert.Equal(0, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.Equal(before, run.Body.Instructions.Select(i => i.ToString()));
        Assert.DoesNotContain(owner.Methods, m => m.Name == "EnsureProtectorInitialized");
    }

    private static ArtifactContext Fixture(string prefix) => SyntheticContext.Build(module =>
    {
        var host = SyntheticContext.AddType(module, "Host"); host.Attributes = TypeAttributes.Public;
        var pool = SyntheticContext.AddType(module, "Pool"); pool.Attributes = TypeAttributes.Sealed;
        var root = new FieldDefUser("Root", new FieldSig(pool.ToTypeSig()), FieldAttributes.Assembly | FieldAttributes.Static); pool.Fields.Add(root);
        var fields = Enumerable.Range(0, 16).Select(n => new FieldDefUser("m_" + n.ToString("x32", System.Globalization.CultureInfo.InvariantCulture),
            new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Assembly)).ToArray();
        foreach (var field in fields) pool.Fields.Add(field);
        var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() }; pool.Methods.Add(ctor);
        Add(ctor, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)), OpCodes.Ret.ToInstruction());
        var initialize = New(pool, "Initialize", module.CorLibTypes.Void);
        ReadingMarker.Add(module).Mark(initialize);
        Add(initialize, OpCodes.Newobj.ToInstruction(ctor), OpCodes.Stsfld.ToInstruction(root));
        for (var n = 0; n < fields.Length; n++) Add(initialize, OpCodes.Ldsfld.ToInstruction(root), Instruction.CreateLdcI4(n), OpCodes.Stfld.ToInstruction(fields[n]));
        Add(initialize, OpCodes.Ret.ToInstruction());
        var count = new FieldDefUser("Count", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static); host.Fields.Add(count);
        var run = New(host, "Run", module.CorLibTypes.Int32, module.CorLibTypes.Int32);
        var pre = New(host, "Prefix", module.CorLibTypes.Void);
        Add(pre, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(count));
        if (prefix == "throw") Add(pre, OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
        else
        {
            if (prefix == "reenter") Add(pre, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Call.ToInstruction(run), OpCodes.Pop.ToInstruction());
            Add(pre, OpCodes.Ret.ToInstruction());
        }
        var cctor = New(pool, ".cctor", module.CorLibTypes.Void);
        cctor.Attributes = MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
        Add(cctor, OpCodes.Call.ToInstruction(pre), OpCodes.Call.ToInstruction(initialize), OpCodes.Ret.ToInstruction());
        var app = OpCodes.Ldarg_0.ToInstruction(); var zero = Instruction.CreateLdcI4(17); var one = Instruction.CreateLdcI4(23);
        Add(run, OpCodes.Ldsfld.ToInstruction(root), OpCodes.Ldfld.ToInstruction(fields[2]), OpCodes.Pop.ToInstruction(),
            OpCodes.Ldsfld.ToInstruction(root), OpCodes.Ldfld.ToInstruction(fields[1]), OpCodes.Brtrue.ToInstruction(app),
            Instruction.CreateLdcI4(99), OpCodes.Ret.ToInstruction(), app, OpCodes.Switch.ToInstruction([zero, one]),
            Instruction.CreateLdcI4(29), OpCodes.Ret.ToInstruction(), zero, OpCodes.Ret.ToInstruction(), one,
            OpCodes.Ldsfld.ToInstruction(root), OpCodes.Ldfld.ToInstruction(fields[0]), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
    });

    private static MethodDefUser New(TypeDef type, string name, TypeSig result, params TypeSig[] parameters)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(result, parameters), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
        type.Methods.Add(method); return method;
    }
    private static void Add(MethodDef method, params Instruction[] instructions) { foreach (var i in instructions) method.Body.Instructions.Add(i); }
    private static MethodDef Method(ArtifactContext context, string name) => context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == name);
    private static string Invoke(ArtifactContext context, int argument)
    {
        // Only the source-built benign fixture is executed in the CLR.
        using var stream = new MemoryStream(); context.Module.Write(stream); stream.Position = 0;
        var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        try
        {
            var host = loader.LoadFromStream(stream).GetType("Synthetic.Host")!;
            string result;
            try { result = host.GetMethod("Run")!.Invoke(null, [argument])!.ToString()!; }
            catch (System.Reflection.TargetInvocationException exception) { result = exception.InnerException!.GetType().FullName!; }
            return result + ":" + host.GetField("Count")!.GetValue(null);
        }
        finally { loader.Unload(); }
    }
}
