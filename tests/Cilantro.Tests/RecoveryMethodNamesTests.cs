using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class RecoveryMethodNamesTests
{
    [Theory]
    [InlineData("label", true)]
    [InlineData("called-getter", false)]
    [InlineData("reflected", false)]
    [InlineData("public-field", false)]
    [InlineData("mutable-field", false)]
    [InlineData("duplicate", false)]
    [InlineData("argument-escape", false)]
    [InlineData("address", false)]
    [InlineData("duplicate-stack", false)]
    public void IgnoresOnlyLabelsWithoutAnObservedConsumer(string mode, bool recover)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Application"); owner.Attributes = TypeAttributes.Public;
            var target = new MethodDefUser("Label", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(target);
            Emit(target, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ret.ToInstruction());
            var data = SyntheticContext.AddType(module, "Descriptor");
            var field = new FieldDefUser("Text", new FieldSig(module.CorLibTypes.String),
                (mode == "public-field" ? FieldAttributes.Public : FieldAttributes.Private) |
                (mode == "mutable-field" ? 0 : FieldAttributes.InitOnly));
            data.Fields.Add(field);
            var getter = new MethodDefUser("get_Text", MethodSig.CreateInstance(module.CorLibTypes.String), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.SpecialName) { Body = new CilBody() };
            data.Methods.Add(getter);
            Emit(getter, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(field), OpCodes.Ret.ToInstruction());
            var property = new PropertyDefUser("Text", PropertySig.CreateInstance(module.CorLibTypes.String));
            property.GetMethods.Add(getter); data.Properties.Add(property);
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String, module.CorLibTypes.Int32),
                MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
            data.Methods.Add(ctor);
            Emit(ctor, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)),
                OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Stfld.ToInstruction(field));
            if (mode == "argument-escape") Emit(ctor, OpCodes.Ldarg_1.ToInstruction(), OpCodes.Call.ToInstruction(target), OpCodes.Pop.ToInstruction());
            if (mode == "address") Emit(ctor, OpCodes.Ldarga_S.ToInstruction(ctor.Parameters[1]), OpCodes.Pop.ToInstruction());
            Emit(ctor, OpCodes.Ret.ToInstruction());
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(entry);
            Emit(entry, OpCodes.Ldstr.ToInstruction("Label"));
            if (mode == "duplicate-stack") Emit(entry, OpCodes.Dup.ToInstruction(), OpCodes.Pop.ToInstruction());
            Emit(entry, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newobj.ToInstruction(ctor));
            if (mode == "called-getter") Emit(entry, OpCodes.Callvirt.ToInstruction(getter));
            Emit(entry, OpCodes.Pop.ToInstruction(), OpCodes.Ldstr.ToInstruction("value"), OpCodes.Call.ToInstruction(target), OpCodes.Pop.ToInstruction());
            if (mode == "duplicate") Emit(entry, OpCodes.Ldstr.ToInstruction("Label"), OpCodes.Pop.ToInstruction());
            if (mode == "reflected") Emit(entry, OpCodes.Ldtoken.ToInstruction(data), OpCodes.Pop.ToInstruction());
            Emit(entry, OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(recover ? 1 : 0, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
    }
    private static void Emit(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }
}
