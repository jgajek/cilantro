using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ResizedArrayFieldTypingTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("static", true)]
    [InlineData("null-writer", true)]
    [InlineData("foreign", false)]
    [InlineData("escape", false)]
    [InlineData("named", false)]
    [InlineData("reflected", false)]
    [InlineData("public", false)]
    [InlineData("readonly", false)]
    [InlineData("serializable", false)]
    [InlineData("wrong-writer", false)]
    [InlineData("wrong-size", false)]
    [InlineData("wrong-return", false)]
    [InlineData("alternate-entry", false)]
    public void RestoresOnlyClosedPrivateResizeFields(string mode, bool expected)
    {
        FieldDef field = null!;
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Holder");
            if (mode == "serializable") owner.Attributes |= TypeAttributes.Serializable;
            var isStatic = mode == "static";
            field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object),
                (mode == "public" ? FieldAttributes.Public : FieldAttributes.Private) |
                (isStatic ? FieldAttributes.Static : 0) | (mode == "readonly" ? FieldAttributes.InitOnly : 0));
            owner.Fields.Add(field);
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, owner.ToTypeSig()), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(method);
            if (!isStatic) Emit(OpCodes.Ldarg_0.ToInstruction());
            if (mode == "null-writer") Emit(OpCodes.Ldnull.ToInstruction());
            else if (mode == "wrong-writer") Emit(OpCodes.Ldstr.ToInstruction("wrong"));
            else Emit(OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
            Emit((isStatic ? OpCodes.Stsfld : OpCodes.Stfld).ToInstruction(field));
            if (mode == "named") Emit(OpCodes.Ldstr.ToInstruction("Value"), OpCodes.Pop.ToInstruction());
            if (mode == "reflected") Emit(OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Pop.ToInstruction());
            if (!isStatic) Emit(OpCodes.Ldarg_0.ToInstruction());
            Emit((isStatic ? OpCodes.Ldsflda : OpCodes.Ldflda).ToInstruction(field));
            if (mode == "escape") Emit(OpCodes.Dup.ToInstruction(), OpCodes.Pop.ToInstruction());
            var size = mode == "wrong-size" ? OpCodes.Ldstr.ToInstruction("size") : OpCodes.Ldc_I4_4.ToInstruction();
            if (mode == "alternate-entry") Emit(OpCodes.Br.ToInstruction(size));
            Emit(size);
            var signature = MethodSig.CreateStaticGeneric(1, mode == "wrong-return" ? module.CorLibTypes.Int32 : module.CorLibTypes.Void,
                new ByRefSig(new SZArraySig(new GenericMVar(0))), module.CorLibTypes.Int32);
            var resize = new MethodSpecUser(new MemberRefUser(module, "Resize", signature,
                new TypeRefUser(module, "System", "Array", mode == "foreign" ? new AssemblyRefUser("Foreign", new Version(1, 0)) : module.CorLibTypes.AssemblyRef)), new GenericInstMethodSig(module.CorLibTypes.Int32));
            Emit(OpCodes.Call.ToInstruction(resize));
            if (mode == "wrong-return") Emit(OpCodes.Pop.ToInstruction());
            if (!isStatic) Emit(OpCodes.Ldarg_0.ToInstruction());
            Emit((isStatic ? OpCodes.Ldsfld : OpCodes.Ldfld).ToInstruction(field), OpCodes.Ldlen.ToInstruction(), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
            void Emit(params Instruction[] instructions) { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }
        });
        var result = new ArrayFieldTypingPass().Run(context);
        Assert.Equal(expected ? 1 : 0, result.Changes);
        Assert.Equal(expected ? "System.Int32[]" : "System.Object", context.Module.GetTypes().SelectMany(t => t.Fields).Single(f => f.Name == "Value").FieldType.FullName);
        Assert.Equal(0, new ArrayFieldTypingPass().Run(context).Changes);
    }
}
