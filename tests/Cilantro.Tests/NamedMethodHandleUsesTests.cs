using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class NamedMethodHandleUsesTests
{
    [Theory]
    [InlineData("other", true)]
    [InlineData("local-name", true)]
    [InlineData("candidate", false)]
    [InlineData("unknown-name", false)]
    [InlineData("metadata-escape", false)]
    [InlineData("method-escape", false)]
    [InlineData("foreign", false)]
    public void AllowsOnlyClosedInvocationOfAnotherName(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var candidate = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.Private)
                { Body = new CilBody() }; owner.Methods.Add(candidate); candidate.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var source = new MethodDefUser("Source", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String), MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.Private)
                { Body = new CilBody() }; owner.Methods.Add(source);
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var info = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo");
            var il = source.Body.Instructions;
            il.Add(OpCodes.Ldtoken.ToInstruction(owner));
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(type.ToTypeSig(), module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()),
                mode == "foreign" ? new TypeRefUser(module, "System", "Type", new AssemblyRefUser("Foreign")) : type)));
            if (mode == "unknown-name") il.Add(OpCodes.Ldarg_0.ToInstruction());
            else il.Add(OpCodes.Ldstr.ToInstruction(mode == "candidate" ? "Target" : "Other"));
            if (mode == "local-name")
            {
                var local = new Local(module.CorLibTypes.String); source.Body.Variables.Add(local);
                il.Add(OpCodes.Stloc.ToInstruction(local)); il.Add(OpCodes.Castclass.ToInstruction(type)); il.Add(OpCodes.Ldloc.ToInstruction(local));
            }
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetMethod", MethodSig.CreateInstance(info.ToTypeSig(), module.CorLibTypes.String), type)));
            if (mode == "method-escape") il.Add(OpCodes.Pop.ToInstruction());
            else if (mode == "metadata-escape")
            {
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_DeclaringType", MethodSig.CreateInstance(type.ToTypeSig()), module.CorLibTypes.GetTypeRef("System.Reflection", "MemberInfo"))));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            else
            {
                il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Invoke", MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Object)), module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase"))));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            il.Add(OpCodes.Ret.ToInstruction());
        });
        var candidate = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Target");
        Assert.Equal(expected, NamedMethodHandleUses.Excludes(context.Module, candidate));
    }
}
