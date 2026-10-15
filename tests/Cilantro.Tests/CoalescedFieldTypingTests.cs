using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class CoalescedFieldTypingTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("inverted", true)]
    [InlineData("inverted-wrong-branch", false)]
    [InlineData("inverted-alternate-entry", false)]
    [InlineData("alternate-entry", false)]
    [InlineData("wrong-fallback", false)]
    [InlineData("wrong-branch", false)]
    public void RequiresCompatibleArmsAndNoOtherEntry(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var contract = SyntheticContext.AddType(module, "IValue");
            contract.Attributes = TypeAttributes.Interface | TypeAttributes.Abstract;
            contract.BaseType = null;
            var get = new MethodDefUser("Get", MethodSig.CreateInstance(module.CorLibTypes.Int32))
                { Attributes = MethodAttributes.Public | MethodAttributes.Abstract | MethodAttributes.Virtual | MethodAttributes.NewSlot };
            contract.Methods.Add(get);
            var fallback = SyntheticContext.AddType(module, "DefaultValue");
            if (scenario != "wrong-fallback") fallback.Interfaces.Add(new InterfaceImplUser(contract));
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            ctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            ctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)));
            ctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); fallback.Methods.Add(ctor);
            var implementation = new MethodDefUser("Get", get.MethodSig)
                { Attributes = MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot, Body = new CilBody() };
            implementation.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
            implementation.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); fallback.Methods.Add(implementation);
            var owner = SyntheticContext.AddType(module, "Owner");
            var field = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            var write = new MethodDefUser("Write", MethodSig.CreateStatic(module.CorLibTypes.Void, contract.ToTypeSig()))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(write);
            var store = OpCodes.Stsfld.ToInstruction(field);
            if (scenario.EndsWith("alternate-entry", StringComparison.Ordinal))
            {
                write.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                write.Body.Instructions.Add(OpCodes.Br.ToInstruction(store));
            }
            var fallbackPop = OpCodes.Pop.ToInstruction();
            var selection = scenario.StartsWith("inverted", StringComparison.Ordinal)
                ? new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Dup.ToInstruction(),
                    (scenario == "inverted-wrong-branch" ? OpCodes.Brtrue : OpCodes.Brfalse).ToInstruction(fallbackPop),
                    OpCodes.Br.ToInstruction(store), fallbackPop, OpCodes.Newobj.ToInstruction(ctor), store, OpCodes.Ret.ToInstruction() }
                : new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Dup.ToInstruction(),
                (scenario == "wrong-branch" ? OpCodes.Brfalse : OpCodes.Brtrue).ToInstruction(store),
                fallbackPop, OpCodes.Newobj.ToInstruction(ctor), store, OpCodes.Ret.ToInstruction() };
            foreach (var i in selection)
                write.Body.Instructions.Add(i);
            var read = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Int32))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(read);
            read.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field));
            read.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(get));
            read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected ? 1 : 0, new ReferenceFieldTypingPass().Run(context).Changes);
        Assert.Equal(0, new ReferenceFieldTypingPass().Run(context).Changes);
        var field = context.Module.GetTypes().SelectMany(t => t.Fields).Single();
        Assert.Equal(ElementType.Object, field.FieldType.ElementType);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            Assert.Equal(expected ? 0 : 1, IlVerification.Read(path, []).Count);
        }
        finally { File.Delete(path); }
    }
}
