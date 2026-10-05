using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class NumericTokenUsesTests
{
    [Theory]
    [InlineData(false, false, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, true)]
    public void OnlyTheSameLiveMemberCanSupplyModuleAndToken(bool differentMember, bool spill, bool expected)
    {
        using var module = new ModuleDefUser("tokens");
        var method = Make(module);
        var il = method.Body.Instructions;
        il.Add(OpCodes.Ldarg_0.ToInstruction());
        il.Add(OpCodes.Callvirt.ToInstruction(Getter(module, "Module")));
        il.Add((differentMember ? OpCodes.Ldarg_1 : OpCodes.Ldarg_0).ToInstruction());
        il.Add(OpCodes.Castclass.ToInstruction(module.CorLibTypes.GetTypeRef("System.Reflection", "MemberInfo")));
        il.Add(OpCodes.Callvirt.ToInstruction(Getter(module, "MetadataToken")));
        if (spill)
        {
            var local = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(local);
            il.Add(OpCodes.Stloc.ToInstruction(local));
            il.Add(OpCodes.Nop.ToInstruction());
            il.Add(OpCodes.Ldloc.ToInstruction(local));
        }
        var resolve = OpCodes.Callvirt.ToInstruction(Resolve(module));
        il.Add(resolve); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        Assert.Equal(expected, NumericTokenUses.MemberRoundTrips(method).Contains(resolve));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ConstantsAndControlFlowEntriesDoNotBorrowProvenance(bool branchIntoSequence)
    {
        using var module = new ModuleDefUser("tokens");
        var method = Make(module);
        var il = method.Body.Instructions;
        il.Add(OpCodes.Ldarg_0.ToInstruction());
        il.Add(OpCodes.Callvirt.ToInstruction(Getter(module, "Module")));
        il.Add(OpCodes.Ldc_I4.ToInstruction(0x06000001));
        var resolve = OpCodes.Callvirt.ToInstruction(Resolve(module));
        il.Add(resolve); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        if (branchIntoSequence) il.Insert(0, OpCodes.Br.ToInstruction(resolve));
        Assert.Empty(NumericTokenUses.MemberRoundTrips(method));
    }

    [Fact]
    public void ReplacingTheArgumentInvalidatesItsOldIdentity()
    {
        using var module = new ModuleDefUser("tokens");
        var method = Make(module);
        var il = method.Body.Instructions;
        il.Add(OpCodes.Ldarg_0.ToInstruction());
        il.Add(OpCodes.Callvirt.ToInstruction(Getter(module, "Module")));
        il.Add(OpCodes.Ldarg_1.ToInstruction());
        il.Add(OpCodes.Starg.ToInstruction(method.Parameters[0]));
        il.Add(OpCodes.Ldarg_0.ToInstruction());
        il.Add(OpCodes.Callvirt.ToInstruction(Getter(module, "MetadataToken")));
        il.Add(OpCodes.Callvirt.ToInstruction(Resolve(module)));
        il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        Assert.Empty(NumericTokenUses.MemberRoundTrips(method));
    }

    private static MethodDefUser Make(ModuleDef module)
    {
        var owner = new TypeDefUser("", "Reader", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(owner);
        var member = new ClassSig(module.CorLibTypes.GetTypeRef("System.Reflection", "MemberInfo"));
        var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Void, member, member),
            MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
        owner.Methods.Add(method); return method;
    }
    private static MemberRefUser Getter(ModuleDef module, string name) => new MemberRefUser(module, "get_" + name,
        MethodSig.CreateInstance(name == "Module" ? new ClassSig(module.CorLibTypes.GetTypeRef("System.Reflection", "Module")) : module.CorLibTypes.Int32),
        module.CorLibTypes.GetTypeRef("System.Reflection", "MemberInfo"));
    private static MemberRefUser Resolve(ModuleDef module) => new MemberRefUser(module, "ResolveMethod",
        MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Int32),
        module.CorLibTypes.GetTypeRef("System.Reflection", "Module"));
}
