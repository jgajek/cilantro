using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReadonlyDelegateBindingTests
{
    [Theory]
    [InlineData("plain", true)]
    [InlineData("threaded", true)]
    [InlineData("conditional", false)]
    [InlineData("loop", false)]
    [InlineData("rewrite", false)]
    [InlineData("address", false)]
    [InlineData("token", false)]
    [InlineData("mutable", false)]
    [InlineData("instance", false)]
    [InlineData("signature", false)]
    [InlineData("ambiguous", false)]
    public void RequiresOneImmutableStaticTarget(string variation, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Bindings");
            var type = SyntheticContext.AddType(module, "Callback");
            type.BaseType = module.CorLibTypes.GetTypeRef("System", "MulticastDelegate");
            var constructor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void,
                module.CorLibTypes.Object, module.CorLibTypes.IntPtr))
            {
                Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                ImplAttributes = MethodImplAttributes.Runtime
            };
            var invoke = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Public | MethodAttributes.Virtual, ImplAttributes = MethodImplAttributes.Runtime };
            type.Methods.Add(constructor); type.Methods.Add(invoke);
            if (variation == "ambiguous") type.Methods.Add(new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Public | MethodAttributes.Virtual, ImplAttributes = MethodImplAttributes.Runtime });
            var field = new FieldDefUser("Binding", new FieldSig(type.ToTypeSig()), FieldAttributes.Static | FieldAttributes.Private | FieldAttributes.InitOnly);
            if (variation == "mutable") field.IsInitOnly = false;
            owner.Fields.Add(field);
            var target = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Static | MethodAttributes.Private, Body = new CilBody() };
            if (variation == "instance") { target.IsStatic = false; target.MethodSig.HasThis = true; }
            if (variation == "signature") target.MethodSig.Params.Add(module.CorLibTypes.Int32);
            target.Body.Instructions.Add(Instruction.CreateLdcI4(123)); target.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); owner.Methods.Add(target);
            var init = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            var il = init.Body.Instructions;
            il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldftn.ToInstruction(target));
            il.Add(OpCodes.Newobj.ToInstruction(constructor)); il.Add(OpCodes.Stsfld.ToInstruction(field)); il.Add(OpCodes.Ret.ToInstruction());
            if (variation == "threaded") il.Insert(0, OpCodes.Br.ToInstruction(il[0]));
            if (variation == "conditional") { il.Insert(0, OpCodes.Brfalse.ToInstruction(il[^1])); il.Insert(0, OpCodes.Ldc_I4_0.ToInstruction()); }
            if (variation == "loop") il.Insert(0, OpCodes.Br.ToInstruction(il[0]));
            if (variation == "loop") il[0].Operand = il[0];
            owner.Methods.Add(init);
            if (variation is "rewrite" or "address" or "token")
            {
                var other = new MethodDefUser("Other", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
                if (variation == "rewrite") { other.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); other.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field)); }
                else { other.Body.Instructions.Add((variation == "address" ? OpCodes.Ldsflda : OpCodes.Ldtoken).ToInstruction(field)); other.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
                other.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); owner.Methods.Add(other);
            }
        });
        var binding = context.Module.GetTypes().SelectMany(t => t.Fields).Single();
        var actual = ReadonlyDelegateBinding.Target(binding);
        Assert.Equal(expected, actual is not null);
        if (expected) Assert.Equal("Target", actual!.Name.String);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void ReceiverMustBeLoadedInTheSameBasicBlock(bool alternateEntry, bool expected)
    {
        var module = new ModuleDefUser("receiver");
        var type = SyntheticContext.AddType(module, "Callback");
        var field = new FieldDefUser("Binding", new FieldSig(type.ToTypeSig()), FieldAttributes.Static);
        type.Fields.Add(field);
        var invoke = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Int32)); type.Methods.Add(invoke);
        var method = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Int32)) { Body = new CilBody() }; type.Methods.Add(method);
        var call = OpCodes.Callvirt.ToInstruction(invoke);
        method.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field));
        if (alternateEntry) method.Body.Instructions.Add(OpCodes.Br.ToInstruction(call));
        method.Body.Instructions.Add(call); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        Assert.Equal(expected, ReadonlyDelegateBinding.Receiver(method, call) == field);
    }
}
