using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DynamicMethodNameUsesTests
{
    [Theory]
    [InlineData("factory", true)]
    [InlineData("concat", true)]
    [InlineData("escape", false)]
    [InlineData("address", false)]
    [InlineData("foreign", false)]
    [InlineData("branch", false)]
    [InlineData("duplicate", false)]
    [InlineData("return-name", false)]
    public void CreationNamesDoNotNameExistingMethodsUnlessTheyEscape(string mode, bool repaired)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Application"); owner.Attributes = TypeAttributes.Public;
            var target = new MethodDefUser("Label", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(target);
            Emit(target, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ret.ToInstruction());
            var dynamicType = module.CorLibTypes.GetTypeRef("System.Reflection.Emit", "DynamicMethod");
            if (mode == "foreign") dynamicType.ResolutionScope = new AssemblyRefUser("Untrusted", new Version(1, 0));
            var type = module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig();
            var factory = new MethodDefUser("Factory", MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.String),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(factory);
            if (mode == "escape") Emit(factory, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(target), OpCodes.Pop.ToInstruction());
            if (mode == "address") Emit(factory, OpCodes.Ldarga_S.ToInstruction(factory.Parameters[0]), OpCodes.Pop.ToInstruction());
            Emit(factory, OpCodes.Ldarg_0.ToInstruction());
            if (mode == "return-name") Emit(factory, OpCodes.Ret.ToInstruction());
            else
            {
                var next = OpCodes.Ldnull.ToInstruction();
                if (mode == "branch") Emit(factory, OpCodes.Br.ToInstruction(next));
                Emit(factory, next, OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(),
                    OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void,
                        module.CorLibTypes.String, type, new SZArraySig(type), type, module.CorLibTypes.Boolean), dynamicType)), OpCodes.Ret.ToInstruction());
            }
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(entry);
            Emit(entry, OpCodes.Ldstr.ToInstruction("Label"));
            if (mode == "concat") Emit(entry, OpCodes.Ldstr.ToInstruction("Suffix"), OpCodes.Call.ToInstruction(new MemberRefUser(module, "Concat",
                MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.String, module.CorLibTypes.String), module.CorLibTypes.String.TypeDefOrRef)));
            Emit(entry, OpCodes.Call.ToInstruction(factory), OpCodes.Pop.ToInstruction());
            if (mode == "duplicate") Emit(entry, OpCodes.Ldstr.ToInstruction("Label"), OpCodes.Pop.ToInstruction());
            Emit(entry, OpCodes.Ldstr.ToInstruction("value"), OpCodes.Call.ToInstruction(target), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(repaired ? 1 : 0, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
    }
    private static void Emit(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }
}
