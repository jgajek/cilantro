using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedTableConstructionTests
{
    [Theory]
    [InlineData("unknown", true)]
    [InlineData("throw", true)]
    [InlineData("helper", true)]
    [InlineData("fips", true)]
    [InlineData("ambient-input", false)]
    [InlineData("static-input", false)]
    [InlineData("conditional", false)]
    [InlineData("bad-index", false)]
    [InlineData("external-prefix", false)]
    [InlineData("reference-prefix", false)]
    [InlineData("called-type-initializer", false)]
    [InlineData("failed-construction", false)]
    [InlineData("constructor-type-initializer", false)]
    [InlineData("budget", false)]
    public void IndependentConstructionKeepsOriginalInitialization(string scenario, bool folds)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Table");
            var host = SyntheticContext.AddType(module, "Host");
            var holder = new FieldDefUser("Instance", new FieldSig(owner.ToTypeSig()), FieldAttributes.Static | FieldAttributes.InitOnly);
            var values = new FieldDefUser("Values", new FieldSig(new SZArraySig(module.CorLibTypes.Int32)));
            var effect = new FieldDefUser("Effect", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            owner.Fields.Add(holder); owner.Fields.Add(values); host.Fields.Add(effect);
            MethodDef Make(TypeDef type, string name, MethodSig sig, params Instruction[] il)
            {
                var method = new MethodDefUser(name, sig) { Attributes = sig.HasThis ? MethodAttributes.Private : MethodAttributes.Static, Body = new CilBody() };
                if (name is ".ctor" or ".cctor") method.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
                foreach (var instruction in il) method.Body.Instructions.Add(instruction);
                type.Methods.Add(method); return method;
            }
            var clock = new MemberRefUser(module, "get_TickCount", MethodSig.CreateStatic(module.CorLibTypes.Int32), module.CorLibTypes.GetTypeRef("System", "Environment"));
            if (scenario == "fips") clock = new MemberRefUser(module, "get_AllowOnlyFipsAlgorithms", MethodSig.CreateStatic(module.CorLibTypes.Boolean), module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "CryptoConfig"));
            var unknown = new MemberRefUser(module, "Unknown", MethodSig.CreateStatic(module.CorLibTypes.Int32), new TypeRefUser(module, "External", "Support", module.CorLibTypes.AssemblyRef));
            if (scenario == "external-prefix") clock = unknown;
            var prefix = Make(host, "Prefix", MethodSig.CreateStatic(module.CorLibTypes.Void),
                OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(effect),
                OpCodes.Call.ToInstruction(clock), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
            if (scenario == "reference-prefix")
            {
                var published = new FieldDefUser("Published", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static);
                host.Fields.Add(published);
                prefix.Body.Instructions.Insert(0, OpCodes.Ldnull.ToInstruction());
                prefix.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(published));
            }
            if (scenario == "called-type-initializer")
            {
                var other = SyntheticContext.AddType(module, "Other");
                Make(other, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Call.ToInstruction(unknown), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
                var helper = Make(other, "Trigger", MethodSig.CreateStatic(module.CorLibTypes.Int32), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ret.ToInstruction());
                prefix.Body.Instructions.Single(i => i.OpCode.Code == Code.Call).Operand = helper;
            }
            if (scenario == "throw")
            {
                prefix.Body.Instructions.Clear(); prefix.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); prefix.Body.Instructions.Add(OpCodes.Throw.ToInstruction());
            }
            var value = Instruction.CreateLdcI4(123);
            if (scenario == "ambient-input") value = OpCodes.Call.ToInstruction(clock);
            if (scenario == "static-input") value = OpCodes.Ldsfld.ToInstruction(effect);
            if (scenario is "helper" or "budget")
            {
                var helper = Make(owner, "Compute", MethodSig.CreateStatic(module.CorLibTypes.Int32), Instruction.CreateLdcI4(120), OpCodes.Ldc_I4_3.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Ret.ToInstruction());
                value = OpCodes.Call.ToInstruction(helper);
            }
            if (scenario == "constructor-type-initializer")
            {
                var other = SyntheticContext.AddType(module, "ConstructorDependency");
                Make(other, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Call.ToInstruction(unknown), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
                var helper = Make(other, "Compute", MethodSig.CreateStatic(module.CorLibTypes.Int32), Instruction.CreateLdcI4(123), OpCodes.Ret.ToInstruction());
                value = OpCodes.Call.ToInstruction(helper);
            }
            var ctor = Make(owner, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
                OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef), OpCodes.Stfld.ToInstruction(values),
                OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(values), OpCodes.Ldc_I4_0.ToInstruction(), value, OpCodes.Stelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction());
            if (scenario == "failed-construction") ctor.Body.Instructions[6].OpCode = OpCodes.Ldc_I4_2;
            var init = Make(owner, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Call.ToInstruction(prefix),
                OpCodes.Newobj.ToInstruction(ctor), OpCodes.Stsfld.ToInstruction(holder), OpCodes.Ret.ToInstruction());
            if (scenario == "conditional")
            {
                init.Body.Instructions.Insert(1, OpCodes.Ldc_I4_0.ToInstruction());
                init.Body.Instructions.Insert(2, OpCodes.Brtrue.ToInstruction(init.Body.Instructions[^1]));
            }
            var getter = Make(owner, "Read", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                OpCodes.Ldsfld.ToInstruction(holder), OpCodes.Ldfld.ToInstruction(values), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction());
            Make(host, "Caller", MethodSig.CreateStatic(module.CorLibTypes.Int32), Instruction.CreateLdcI4(scenario == "bad-index" ? 5 : 0), OpCodes.Call.ToInstruction(getter), OpCodes.Ret.ToInstruction());
        });
        var caller = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Caller");
        var initializer = context.Module.GetTypes().Single(t => t.Name == "Table").FindStaticConstructor();
        var body = initializer.Body;
        var instructions = body.Instructions.ToArray();
        if (scenario == "budget") context.SetFact(BootstrapMachine.RunEnvironmentFact,
            new RunEnvironment(declarations: RunDeclarations.Parse("""{"budgets":{"depth":1}}""", "construction-limit")));
        var before = Run(context, caller);
        Assert.False(before.Succeeded);
        var result = new NumericTableRecoveryPass().Run(context);
        Assert.Equal(folds ? 1 : 0, result.Changes);
        Assert.Same(body, initializer.Body);
        Assert.Equal(instructions, initializer.Body.Instructions);
        Assert.True(AssemblyVerifier.Verify(context.Module).Passed);
        var after = Run(context, caller);
        Assert.Equal(before.Status, after.Status);
        Assert.False(after.Succeeded);
        if (!folds) return;
        Assert.Contains(caller.Body.Instructions, i => i.OpCode.Code == Code.Ldsfld);
        // If the prefix completes on a supported host, its observable write still runs.
        var prefixMethod = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Prefix");
        if (scenario != "throw")
        {
            var ambient = prefixMethod.Body.Instructions.Single(i => i.OpCode.Code == Code.Call);
            ambient.OpCode = OpCodes.Ldc_I4_0; ambient.Operand = null;
            Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out _));
            var completed = machine!.Execute(caller);
            Assert.True(completed.Succeeded, completed.Diagnostic);
            Assert.Equal(123, completed.Value.AsInt32());
            var effect = context.Module.GetTypes().SelectMany(t => t.Fields).Single(f => f.Name == "Effect");
            Assert.Equal(1, machine.State.ReadStaticField(effect).AsInt32());
        }
    }

    private static StaticExecutionResult Run(ArtifactContext context, MethodDef method)
    {
        Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out _));
        machine!.State.RegisterRunEnvironment(new RunEnvironment(new HostEnvironment(HostProfile.Empty)));
        return machine.Execute(method);
    }
}
