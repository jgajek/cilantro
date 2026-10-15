using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DependencyArrayCompletionTests
{
    [Theory]
    [InlineData("direct", true)]
    [InlineData("initializer", true)]
    [InlineData("empty", false)]
    [InlineData("stored", false)]
    [InlineData("pointer", false)]
    [InlineData("alternate-entry", false)]
    [InlineData("changed-helper", false)]
    public void RemovesOnlyClosedGeneratedArrayRoundTrips(string scenario, bool expected)
    {
        var bytes = scenario == "empty" ? [] : Enumerable.Range(0, 4096).Select(i => (byte)i).ToArray();
        using var context = SyntheticContext.Build(module =>
        {
            var shared = SyntheticContext.AddType(module, "Shared");
            var count = new FieldDefUser("Count", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            shared.Fields.Add(count);
            var initialize = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            shared.Methods.Add(initialize);
            initialize.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(count));
            initialize.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
            initialize.Body.Instructions.Add(OpCodes.Add.ToInstruction());
            initialize.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(count));
            initialize.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var holder = DependencyDecoderCompletionPass.BuildHolder(module,
                new ClosedDependencyDecoder.Result(bytes, scenario == "initializer" ? [shared] : [], new HashSet<MethodDef>(), 0));
            module.Types.Add(holder);
            var helper = holder.Methods[0];
            var owner = SyntheticContext.AddType(module, "Caller");
            var caller = new MethodDefUser("Read", MethodSig.CreateStatic(new SZArraySig(module.CorLibTypes.Byte)))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(caller);
            var memory = module.CorLibTypes.GetTypeRef("System.IO", "MemoryStream");
            var cast = OpCodes.Castclass.ToInstruction(memory);
            var il = caller.Body.Instructions;
            if (scenario == "alternate-entry") { il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Br.ToInstruction(cast)); }
            il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(helper));
            if (scenario == "stored")
            {
                var local = new Local(helper.ReturnType); caller.Body.Variables.Add(local);
                il.Add(OpCodes.Stloc.ToInstruction(local)); il.Add(OpCodes.Ldloc.ToInstruction(local));
            }
            il.Add(cast);
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ToArray",
                MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Byte)), memory)));
            il.Add(OpCodes.Ret.ToInstruction());
            if (scenario == "pointer")
            { il.Insert(0, OpCodes.Pop.ToInstruction()); il.Insert(0, OpCodes.Ldftn.ToInstruction(helper)); }
            if (scenario == "changed-helper") helper.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
        });
        var helper = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Open");
        var caller = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read");
        var original = helper.MethodSig;
        Assert.Equal(expected, DependencyArrayCompletion.Apply(context, helper));
        if (!expected) { Assert.Same(original, helper.MethodSig); return; }
        Assert.Equal("System.Byte[]", helper.ReturnType.FullName);
        Assert.DoesNotContain(caller.Body.Instructions, i => i.OpCode.Code is Code.Castclass or Code.Callvirt);
        Assert.DoesNotContain(helper.Body.Instructions, i => i.OpCode.Code == Code.Newobj);
        var machine = new StaticMachine(BootstrapMachine.Limits(10000), StaticIntrinsicRegistry.CreateDefault(), modelTypeInitialization: true);
        var first = machine.Execute(caller, []);
        Assert.True(first.Succeeded, first.Diagnostic);
        var actual = new byte[bytes.Length];
        Assert.True(machine.State.Heap.TryReadBytes(first.Value, 0, actual)); Assert.Equal(bytes, actual);
        Assert.True(machine.State.Heap.TryWriteBytes(first.Value, 0, new byte[] { 255 }));
        var second = machine.Execute(caller, []);
        Assert.True(second.Succeeded, second.Diagnostic); Assert.NotEqual(first.Value, second.Value);
        Assert.True(machine.State.Heap.TryReadBytes(second.Value, 0, actual)); Assert.Equal(bytes, actual);
        if (scenario == "initializer")
            Assert.Equal(1, machine.State.ReadStaticField(context.Module.GetTypes().Single(t => t.Name == "Shared").Fields.Single()).AsInt32());
        using var output = new MemoryStream(); context.Module.Write(output);
        using var reloaded = ModuleDefMD.Load(output.ToArray());
        Assert.True(AssemblyVerifier.Verify(reloaded).Passed);
    }
}
