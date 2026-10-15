using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ExactReflectionTypesTests
{
    [Theory]
    [InlineData("direct", true)]
    [InlineData("cast", true)]
    [InlineData("same-join", true)]
    [InlineData("different-join", false)]
    [InlineData("unknown", false)]
    [InlineData("foreign", false)]
    public void ResolvesOnlyExactFrameworkTypeTokens(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var runtimeType = module.CorLibTypes.GetTypeRef("System", "Type");
            var method = new MethodDefUser("Lookup", MethodSig.CreateStatic(module.CorLibTypes.Void, runtimeType.ToTypeSig(), module.CorLibTypes.Boolean))
                { Body = new CilBody() }; owner.Methods.Add(method);
            var il = method.Body.Instructions;
            var declaring = mode == "foreign" ? new TypeRefUser(module, "System", "Type", new AssemblyRefUser("Foreign")) : runtimeType;
            var fromHandle = new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(runtimeType.ToTypeSig(), module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()), declaring);
            var name = OpCodes.Ldstr.ToInstruction("Target");
            if (mode.Contains("join"))
            {
                var alternate = OpCodes.Ldtoken.ToInstruction(mode == "same-join" ? owner : module.GlobalType);
                il.Add(OpCodes.Ldarg_1.ToInstruction()); il.Add(OpCodes.Brtrue.ToInstruction(alternate));
                il.Add(OpCodes.Ldtoken.ToInstruction(owner)); il.Add(OpCodes.Call.ToInstruction(fromHandle)); il.Add(OpCodes.Br.ToInstruction(name));
                il.Add(alternate); il.Add(OpCodes.Call.ToInstruction(fromHandle));
            }
            else if (mode == "unknown") il.Add(OpCodes.Ldarg_0.ToInstruction());
            else { il.Add(OpCodes.Ldtoken.ToInstruction(owner)); il.Add(OpCodes.Call.ToInstruction(fromHandle)); }
            if (mode == "cast") il.Add(OpCodes.Castclass.ToInstruction(runtimeType));
            il.Add(name);
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetMethod", MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo").ToTypeSig(), module.CorLibTypes.String), runtimeType)));
            il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Lookup");
        var call = method.Body.Instructions.Single(i => i.Operand is IMethod m && m.Name == "GetMethod");
        var target = ExactReflectionTypes.Receiver(method, call);
        Assert.Equal(expected, target is not null);
        if (expected) Assert.Equal("Synthetic.Owner", target!.FullName);
    }
}
