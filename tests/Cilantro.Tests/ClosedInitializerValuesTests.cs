using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedInitializerValuesTests
{
    [Theory]
    [InlineData("framework", true)] [InlineData("foreign", false)]
    [InlineData("escape", false)] [InlineData("field", false)]
    public void InitializationHandleDoesNotExposePublishedGraph(string scenario, bool expected)
    {
        using var context = Fixture("loop");
        var module = context.Module;
        var owner = module.GetTypes().Single(t => t.Name == "Lookup");
        var caller = new MethodDefUser("InitializeLookup", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
        owner.Methods.Add(caller);
        caller.Body.Instructions.Add(scenario == "field"
            ? OpCodes.Ldtoken.ToInstruction(owner.Fields.Single(f => f.Name == "Data"))
            : OpCodes.Ldtoken.ToInstruction(owner));
        if (scenario is "escape" or "field") caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
        else
        {
            var type = new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers",
                scenario == "foreign" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "RunClassConstructor",
                MethodSig.CreateStatic(module.CorLibTypes.Void,
                    new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), type)));
        }
        caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var original = caller.Body.Instructions.ToArray();
        var result = ClosedInitializerValues.Check(owner);
        Assert.True(result.Passed == expected, result.Detail);
        Assert.Equal(original, caller.Body.Instructions);
    }

    [Theory]
    [InlineData("loop", true)]
    [InlineData("alias", true)]
    [InlineData("foreign-input", false)]
    [InlineData("read-before-store", false)]
    [InlineData("conditional-store", false)]
    [InlineData("prefix-backedge", false)]
    [InlineData("helper-static", false)]
    [InlineData("helper-publication", false)]
    [InlineData("mutation", false)]
    [InlineData("alias-mutation", false)]
    [InlineData("replacement", false)]
    [InlineData("escape", false)]
    [InlineData("token", false)]
    [InlineData("uninitialized-locals", false)]
    public void ClosedLoopConstructionRequiresClosedInputsAndConsumers(string scenario, bool expected)
    {
        using var context = Fixture(scenario);
        var owner = context.Module.GetTypes().Single(t => t.Name == "Lookup");
        var initializer = owner.FindStaticConstructor();
        var body = initializer.Body;
        var instructions = body.Instructions.ToArray();
        var proof = ClosedInitializerValues.Check(owner);
        Assert.True(proof.Passed == expected, proof.Detail);
        Assert.Same(body, initializer.Body);
        Assert.Equal(instructions, body.Instructions);
        if (expected)
        {
            Assert.Contains(owner.Fields.Single(f => f.Name == "Data"), proof.Fields);
            Assert.DoesNotContain(owner.Fields.Single(f => f.Name == "Unwritten"), proof.Fields);
        }
    }

    [Theory]
    [InlineData("loop", true)]
    [InlineData("alias", true)]
    [InlineData("alias-mutation", false)]
    [InlineData("foreign-input", false)]
    [InlineData("escape", false)]
    public void RecoveredConstantsRetainTheOriginalInitializationEffects(string scenario, bool folds)
    {
        using var context = Fixture(scenario);
        var caller = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Caller");
        var before = Run();
        Assert.Equal(0, new NumericTableRecoveryPass().Run(context).Changes);
        var result = new NumericTableCompletionPass().Run(context);
        Assert.True(result.Changes == (folds ? 1 : 0), string.Join("\n", result.Diagnostics));
        Assert.True(AssemblyVerifier.Verify(context.Module).Passed);
        Assert.Equal(before, Run());
        if (folds)
        {
            var trigger = Assert.Single(context.Module.GetTypes().SelectMany(t => t.Methods), m => m.Name == "InitializeNumericTable");
            Assert.Contains(caller.Body.Instructions, i => i.OpCode.Code == Code.Call && i.Operand == trigger);
            Assert.Contains(trigger.Body.Instructions, i => i.OpCode.Code == Code.Ldsfld && i.Operand is IField f && f.Name == "Instance");
        }

        (int Value, int Effect) Run()
        {
            Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out _));
            var result = machine!.Execute(caller);
            Assert.True(result.Succeeded, result.Diagnostic);
            var effect = context.Module.GetTypes().SelectMany(t => t.Fields).Single(f => f.Name == "Effect");
            return (result.Value.AsInt32(), machine.State.ReadStaticField(effect).AsInt32());
        }
    }

    private static ArtifactContext Fixture(string scenario) => SyntheticContext.Build(module =>
    {
        var lookup = SyntheticContext.AddType(module, "Lookup");
        var host = SyntheticContext.AddType(module, "Host");
        var table = SyntheticContext.AddType(module, "Table");
        var ints = new SZArraySig(module.CorLibTypes.Int32);
        var data = new FieldDefUser("Data", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static | FieldAttributes.InitOnly);
        var alias = new FieldDefUser("Alias", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static | FieldAttributes.InitOnly);
        lookup.Fields.Add(data); lookup.Fields.Add(alias);
        lookup.Fields.Add(new FieldDefUser("Unwritten", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static | FieldAttributes.InitOnly));
        var effect = new FieldDefUser("Effect", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static); host.Fields.Add(effect);
        MethodDef Make(TypeDef type, string name, MethodSig signature, params Instruction[] instructions)
        {
            var method = new MethodDefUser(name, signature)
            {
                Attributes = signature.HasThis ? MethodAttributes.Private : MethodAttributes.Static | MethodAttributes.Private,
                Body = new CilBody { InitLocals = true }
            };
            if (name is ".ctor" or ".cctor") method.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
            foreach (var i in instructions) method.Body.Instructions.Add(i);
            type.Methods.Add(method); return method;
        }
        var prefix = Make(host, "Prefix", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Ldsfld.ToInstruction(effect),
            OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Stsfld.ToInstruction(effect), OpCodes.Ret.ToInstruction());
        var compute = Make(lookup, "Compute", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
            OpCodes.Ldarg_0.ToInstruction(), Instruction.CreateLdcI4(100), OpCodes.Add.ToInstruction(), OpCodes.Ret.ToInstruction());
        if (scenario == "helper-static") { compute.Body.Instructions[1].OpCode = OpCodes.Ldsfld; compute.Body.Instructions[1].Operand = effect; }
        if (scenario == "helper-publication")
        {
            compute.Body.Instructions.Insert(0, OpCodes.Ldc_I4_2.ToInstruction()); compute.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(effect));
        }
        var index = new Local(module.CorLibTypes.Int32);
        var loop = OpCodes.Ldsfld.ToInstruction(data);
        var first = OpCodes.Call.ToInstruction(prefix);
        var done = OpCodes.Ret.ToInstruction();
        var init = Make(lookup, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), first,
            OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef), OpCodes.Stsfld.ToInstruction(data),
            OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Stloc.ToInstruction(index), loop, OpCodes.Castclass.ToInstruction(new TypeSpecUser(ints)),
            OpCodes.Ldloc.ToInstruction(index), OpCodes.Ldloc.ToInstruction(index), OpCodes.Call.ToInstruction(compute), OpCodes.Stelem_I4.ToInstruction(),
            OpCodes.Ldloc.ToInstruction(index), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Stloc.ToInstruction(index),
            OpCodes.Ldloc.ToInstruction(index), OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Blt.ToInstruction(loop), done);
        init.Body.Variables.Add(index);
        if (scenario == "uninitialized-locals") init.Body.InitLocals = false;
        if (scenario == "foreign-input")
        { init.Body.Instructions[9].OpCode = OpCodes.Ldsfld; init.Body.Instructions[9].Operand = effect; }
        if (scenario == "prefix-backedge") init.Body.Instructions[^2].Operand = first;
        if (scenario == "conditional-store")
        { init.Body.Instructions.Insert(1, OpCodes.Ldc_I4_0.ToInstruction()); init.Body.Instructions.Insert(2, OpCodes.Brtrue.ToInstruction(done)); }
        if (scenario == "read-before-store")
        { init.Body.Instructions.Insert(1, OpCodes.Ldsfld.ToInstruction(data)); init.Body.Instructions.Insert(2, OpCodes.Pop.ToInstruction()); }
        if (scenario is "alias" or "alias-mutation")
        { init.Body.Instructions.Insert(init.Body.Instructions.Count - 1, OpCodes.Ldsfld.ToInstruction(data)); init.Body.Instructions.Insert(init.Body.Instructions.Count - 1, OpCodes.Stsfld.ToInstruction(alias)); }
        if (scenario is "mutation" or "alias-mutation")
            Make(host, "Mutate", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Ldsfld.ToInstruction(scenario == "mutation" ? data : alias),
                OpCodes.Castclass.ToInstruction(new TypeSpecUser(ints)), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Stelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction());
        if (scenario == "replacement") Make(host, "Replace", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Ldnull.ToInstruction(), OpCodes.Stsfld.ToInstruction(data), OpCodes.Ret.ToInstruction());
        if (scenario == "escape") Make(host, "Escape", MethodSig.CreateStatic(module.CorLibTypes.Object), OpCodes.Ldsfld.ToInstruction(data), OpCodes.Ret.ToInstruction()).Access = MethodAttributes.Public;
        if (scenario == "token") Make(host, "Token", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Ldtoken.ToInstruction(data), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        var holder = new FieldDefUser("Instance", new FieldSig(table.ToTypeSig()), FieldAttributes.Static | FieldAttributes.InitOnly);
        var values = new FieldDefUser("Values", new FieldSig(ints)); table.Fields.Add(holder); table.Fields.Add(values);
        var ctor = Make(table, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
            OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef), OpCodes.Stfld.ToInstruction(values),
            OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(values), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldsfld.ToInstruction(data),
            OpCodes.Castclass.ToInstruction(new TypeSpecUser(ints)), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ldelem_I4.ToInstruction(), OpCodes.Stelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction());
        Make(table, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Newobj.ToInstruction(ctor), OpCodes.Stsfld.ToInstruction(holder), OpCodes.Ret.ToInstruction());
        var read = Make(table, "Read", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
            OpCodes.Ldsfld.ToInstruction(holder), OpCodes.Ldfld.ToInstruction(values), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction());
        Make(host, "Caller", MethodSig.CreateStatic(module.CorLibTypes.Int32), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Call.ToInstruction(read), OpCodes.Ret.ToInstruction());
    });
}
