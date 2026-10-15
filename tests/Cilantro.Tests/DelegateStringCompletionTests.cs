using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DelegateStringCompletionTests
{
    [Theory]
    [InlineData("plain", true)] [InlineData("effect", false)]
    [InlineData("foreign", false)] [InlineData("bypass", false)]
    [InlineData("mutable", false)]
    public void DecodesOnlyClosedBodiesAndKeepsInitialization(string variant, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var callback = SyntheticContext.AddType(module, "Callback");
            callback.BaseType = module.CorLibTypes.GetTypeRef("System", "MulticastDelegate");
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void,
                module.CorLibTypes.Object, module.CorLibTypes.IntPtr))
                { Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                  ImplAttributes = MethodImplAttributes.Runtime };
            var invoke = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.String))
                { Attributes = MethodAttributes.Public | MethodAttributes.Virtual, ImplAttributes = MethodImplAttributes.Runtime };
            callback.Methods.Add(ctor); callback.Methods.Add(invoke);
            var binding = new FieldDefUser("Binding", new FieldSig(callback.ToTypeSig()),
                FieldAttributes.Private | FieldAttributes.Static | FieldAttributes.InitOnly);
            if (variant == "mutable") binding.IsInitOnly = false;
            var observed = new FieldDefUser("Observed", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            owner.Fields.Add(binding); owner.Fields.Add(observed);
            var target = new MethodDefUser("Decode", MethodSig.CreateStatic(module.CorLibTypes.String))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(target);
            var stringType = variant == "foreign" ? new TypeRefUser(module, "System", "String", new AssemblyRefUser("Foreign"))
                : module.CorLibTypes.String.TypeDefOrRef;
            var chars = new MemberRefUser(module, "ToCharArray", MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Char)), stringType);
            var make = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void,
                new SZArraySig(module.CorLibTypes.Char)), module.CorLibTypes.String.TypeDefOrRef);
            var padding = OpCodes.Nop.ToInstruction();
            var il = target.Body.Instructions;
            if (variant == "bypass") { il.Add(OpCodes.Ldstr.ToInstruction("B")); il.Add(OpCodes.Br.ToInstruction(padding)); }
            if (variant == "effect") { il.Add(OpCodes.Ldc_I4_1.ToInstruction()); il.Add(OpCodes.Stsfld.ToInstruction(observed)); }
            foreach (var i in new[] { OpCodes.Ldstr.ToInstruction("@"), OpCodes.Callvirt.ToInstruction(chars),
                OpCodes.Dup.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), Instruction.CreateLdcI4(64),
                OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Xor.ToInstruction(), OpCodes.Conv_U2.ToInstruction(),
                OpCodes.Stelem_I2.ToInstruction(), OpCodes.Newobj.ToInstruction(make), padding, OpCodes.Ret.ToInstruction() }) il.Add(i);
            var init = owner.FindOrCreateStaticConstructor(); init.Body.Instructions.Clear();
            foreach (var i in new[] { OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Stsfld.ToInstruction(observed),
                OpCodes.Ldnull.ToInstruction(), OpCodes.Ldftn.ToInstruction(target), OpCodes.Newobj.ToInstruction(ctor),
                OpCodes.Stsfld.ToInstruction(binding), OpCodes.Ret.ToInstruction() }) init.Body.Instructions.Add(i);
            var caller = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.String))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(caller);
            caller.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(binding));
            caller.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(invoke)); caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var decode = methods.Single(m => m.Name == "Decode");
        var original = decode.Body;
        var result = new DelegateStringCompletionPass().Run(context);
        Assert.Equal(expected ? 1 : 0, result.Changes);
        if (!expected) { Assert.Same(original, decode.Body); return; }
        Assert.Equal(new[] { Code.Ldstr, Code.Callvirt, Code.Newobj, Code.Ret }, decode.Body.Instructions.Select(i => i.OpCode.Code));
        var machine = new StaticMachine(modelTypeInitialization: true);
        machine.State.RegisterModuleMetadata(context.Module);
        var answer = machine.Execute(methods.Single(m => m.Name == "Run"));
        Assert.True(answer.Succeeded, answer.Diagnostic);
        Assert.True(machine.State.Heap.TryGetString(answer.Value, out var text)); Assert.Equal("A", text);
        Assert.Contains(machine.State.StaticFields, p => p.Key.Contains("Observed", StringComparison.Ordinal) && p.Value.AsInt32() == 7);
        Assert.Equal(0, new DelegateStringCompletionPass().Run(context).Changes);
    }
}
