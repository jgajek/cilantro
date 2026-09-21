using Cilantro.Core;
using Cilantro.Core.Recovery;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class NumericTableRecoveryTests
{
    [Theory]
    [InlineData(false, false, 0, true, false)]
    [InlineData(true, false, 0, false, false)]
    [InlineData(false, true, 0, true, false)]
    [InlineData(false, false, 3, false, false)]
    [InlineData(false, false, 0, false, true)]
    [InlineData(false, false, 0, false, false, true)]
    [InlineData(false, true, 0, false, false, false, true)]
    [InlineData(false, false, 0, true, false, false, false, true)]
    [InlineData(false, true, 0, false, false, false, true, true)]
    [InlineData(false, false, 0, true, false, false, false, true, true)]
    [InlineData(false, false, 0, true, false, false, false, true, false, true)]
    [InlineData(false, false, 0, true, false, false, false, false, false, false, true)]
    [InlineData(false, false, 0, false, false, false, false, false, false, false, true, true)]
    public void FoldsOnlyClosedInitializedTables(bool mutation, bool outsideWrite, int index, bool expected, bool alias, bool ambient = false, bool mutableInput = false, bool incidentalRead = false, bool beforeFieldInit = false, bool threaded = false, bool literalDependency = false, bool dependencyEscapes = false)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Table");
            if (beforeFieldInit) owner.IsBeforeFieldInit = true;
            var host = SyntheticContext.AddType(module, "Host");
            var holder = new FieldDefUser("Instance", new FieldSig(owner.ToTypeSig()), FieldAttributes.Static | FieldAttributes.Assembly | FieldAttributes.InitOnly);
            var array = new FieldDefUser("Values", new FieldSig(new SZArraySig(module.CorLibTypes.Int32)), FieldAttributes.Assembly);
            owner.Fields.Add(holder); owner.Fields.Add(array);
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            Add(ctor, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef),
                OpCodes.Stfld.ToInstruction(array), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(array), OpCodes.Ldc_I4_0.ToInstruction(), Instruction.CreateLdcI4(123), OpCodes.Stelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction());
            if (ambient)
            {
                var clock = new MemberRefUser(module, "get_TickCount", MethodSig.CreateStatic(module.CorLibTypes.Int32),
                    new TypeRefUser(module, "System", "Environment", module.CorLibTypes.AssemblyRef));
                var constant = ctor.Body.Instructions.Single(i => i.IsLdcI4() && i.GetLdcI4Value() == 123);
                constant.OpCode = OpCodes.Call; constant.Operand = clock;
            }
            if (alias)
            {
                var local = new Local(array.FieldType); ctor.Body.Variables.Add(local);
                var store = ctor.Body.Instructions.Single(i => i.OpCode.Code == Code.Stfld);
                var at = ctor.Body.Instructions.IndexOf(store);
                ctor.Body.Instructions.Insert(at, OpCodes.Dup.ToInstruction());
                ctor.Body.Instructions.Insert(at + 1, OpCodes.Stloc.ToInstruction(local));
            }
            if (literalDependency)
            {
                var lookup = SyntheticContext.AddType(module, "Lookup");
                var data = new FieldDefUser("Data", new FieldSig(new SZArraySig(module.CorLibTypes.Int32)), FieldAttributes.Static | FieldAttributes.InitOnly);
                lookup.Fields.Add(data);
                var mutable = new FieldDefUser("Incidental", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static); host.Fields.Add(mutable);
                var init = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
                    { Attributes = MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
                Add(init, OpCodes.Ldsfld.ToInstruction(mutable), OpCodes.Pop.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(mutable),
                    OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef), OpCodes.Dup.ToInstruction(),
                    OpCodes.Ldc_I4_0.ToInstruction(), Instruction.CreateLdcI4(123), OpCodes.Stelem_I4.ToInstruction(), OpCodes.Stsfld.ToInstruction(data), OpCodes.Ret.ToInstruction()); lookup.Methods.Add(init);
                var constant = ctor.Body.Instructions.Single(i => i.IsLdcI4() && i.GetLdcI4Value() == 123);
                constant.OpCode = OpCodes.Ldsfld; constant.Operand = data;
                var at = ctor.Body.Instructions.IndexOf(constant);
                ctor.Body.Instructions.Insert(at + 1, OpCodes.Ldc_I4_0.ToInstruction()); ctor.Body.Instructions.Insert(at + 2, OpCodes.Ldelem_I4.ToInstruction());
                if (dependencyEscapes)
                {
                    var escape = new MethodDefUser("Escape", MethodSig.CreateStatic(data.FieldType))
                        { Attributes = MethodAttributes.Public | MethodAttributes.Static, Body = new CilBody() };
                    Add(escape, OpCodes.Ldsfld.ToInstruction(data), OpCodes.Ret.ToInstruction()); lookup.Methods.Add(escape);
                }
            }
            owner.Methods.Add(ctor);
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            Add(cctor, OpCodes.Newobj.ToInstruction(ctor), OpCodes.Stsfld.ToInstruction(holder));
            if (outsideWrite)
            {
                var field = new FieldDefUser("Other", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Assembly);
                host.Fields.Add(field); Add(cctor, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(field));
                if (mutableInput)
                {
                    var constant = ctor.Body.Instructions.Single(i => i.IsLdcI4() && i.GetLdcI4Value() == 123);
                    constant.OpCode = OpCodes.Ldsfld; constant.Operand = field;
                }
            }
            if (incidentalRead)
            {
                var state = new FieldDefUser("MutableInput", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public);
                host.Fields.Add(state);
                // Mark mutable with a write outside its own initializer.
                var setter = new MethodDefUser("SetInput", MethodSig.CreateStatic(module.CorLibTypes.Void))
                    { Attributes = MethodAttributes.Public | MethodAttributes.Static, Body = new CilBody() };
                Add(setter, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(state), OpCodes.Ret.ToInstruction()); host.Methods.Add(setter);
                cctor.Body.Instructions.Insert(0, OpCodes.Ldsfld.ToInstruction(state));
                cctor.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
                cctor.Body.Instructions.Insert(2, OpCodes.Ldc_I4_1.ToInstruction());
                cctor.Body.Instructions.Insert(3, OpCodes.Stsfld.ToInstruction(state));
            }
            Add(cctor, OpCodes.Ret.ToInstruction()); owner.Methods.Add(cctor);
            if (threaded)
            {
                var first = cctor.Body.Instructions[0];
                cctor.Body.Instructions.Insert(0, OpCodes.Br.ToInstruction(first));
                cctor.Body.Instructions.Insert(1, OpCodes.Nop.ToInstruction());
            }
            var getter = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Assembly | MethodAttributes.Static, Body = new CilBody() };
            Add(getter, OpCodes.Ldsfld.ToInstruction(holder), OpCodes.Ldfld.ToInstruction(array), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction()); owner.Methods.Add(getter);
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Public | MethodAttributes.Static, Body = new CilBody() };
            Add(caller, Instruction.CreateLdcI4(index), OpCodes.Call.ToInstruction(getter), OpCodes.Ret.ToInstruction()); host.Methods.Add(caller);
            if (mutation)
            {
                var writer = new MethodDefUser("Write", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Public | MethodAttributes.Static, Body = new CilBody() };
                Add(writer, OpCodes.Ldsfld.ToInstruction(holder), OpCodes.Ldfld.ToInstruction(array), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Stelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction()); host.Methods.Add(writer);
            }
        });
        var result = new NumericTableRecoveryPass().Run(context);
        Assert.Equal(expected ? 1 : 0, result.Changes);
        Assert.True(AssemblyVerifier.Verify(context.Module).Passed);
        var caller = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Caller");
        Assert.Equal(!expected, caller.Body.Instructions.Any(i => i.OpCode.Code == Code.Call && i.Operand is IMethod m && m.Name == "Read"));
        if (outsideWrite && expected)
            Assert.Contains(caller.Body.Instructions, i => i.OpCode.Code == Code.Ldsfld && i.Operand is IField f && f.Name == "Instance");
        if (expected)
        {
            Assert.Contains(caller.Body.Instructions, i => i.IsLdcI4() && i.GetLdcI4Value() == 123);
            Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out _));
            var answer = machine!.Execute(caller);
            Assert.True(answer.Succeeded, answer.Diagnostic);
            Assert.Equal(123, answer.Value.AsInt32());
            if (outsideWrite)
                Assert.Equal(1, machine.State.ReadStaticField(context.Module.GetTypes().SelectMany(t => t.Fields).Single(f => f.Name == "Other")).AsInt32());
        }
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true, true)]
    public void PureHelpersFoldWithIntegerOverflowButKeepTypeInitialization(bool hasInitializer, bool expected, bool empty = false)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Arithmetic");
            if (hasInitializer)
            {
                var init = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
                if (!empty)
                {
                    var field = new FieldDefUser("Initialized", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
                    owner.Fields.Add(field);
                    Add(init, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(field));
                }
                Add(init, OpCodes.Ret.ToInstruction()); owner.Methods.Add(init);
            }
            var helper = new MethodDefUser("Increment", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Static | MethodAttributes.Assembly, Body = new CilBody { InitLocals = true } };
            Add(helper, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Ret.ToInstruction()); owner.Methods.Add(helper);
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Static | MethodAttributes.Public, Body = new CilBody() };
            Add(caller, Instruction.CreateLdcI4(int.MaxValue), OpCodes.Call.ToInstruction(helper), OpCodes.Ret.ToInstruction()); owner.Methods.Add(caller);
        });
        var result = new IntegerHelperRecoveryPass().Run(context);
        Assert.Equal(expected ? 1 : 0, result.Changes);
        if (expected)
            Assert.Contains(context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Caller").Body.Instructions,
                i => i.IsLdcI4() && i.GetLdcI4Value() == int.MinValue);
    }

    [Fact]
    public void ExplicitInitializerRunsOnceEvenForBeforeFieldInitType()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Table"); owner.IsBeforeFieldInit = true;
            var host = SyntheticContext.AddType(module, "Host");
            var field = new FieldDefUser("Counter", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static); owner.Fields.Add(field);
            var init = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            Add(init, OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Stsfld.ToInstruction(field), OpCodes.Ret.ToInstruction()); owner.Methods.Add(init);
            var trigger = new MemberRefUser(module, "RunClassConstructor", MethodSig.CreateStatic(module.CorLibTypes.Void,
                new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers"));
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            Add(run, OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Call.ToInstruction(trigger), OpCodes.Ldtoken.ToInstruction(owner),
                OpCodes.Call.ToInstruction(trigger), OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ret.ToInstruction()); host.Methods.Add(run);
        });
        Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out _));
        var result = machine!.Execute(context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Run"));
        Assert.True(result.Succeeded, result.Diagnostic);
        Assert.Equal(1, result.Value.AsInt32());
    }

    private static void Add(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }
}
