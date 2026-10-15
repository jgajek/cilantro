using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DecliningDynamicInvocationTests
{
    [Theory]
    [InlineData("false", true)]
    [InlineData("nop", true)]
    [InlineData("true", false)]
    [InlineData("wrong-result", false)]
    [InlineData("extra-effect", false)]
    [InlineData("foreign", false)]
    public void RequiresExactNullResultAndRefusal(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var binder = new TypeRefUser(module, "System.Dynamic", "InvokeMemberBinder",
                new AssemblyRefUser(mode == "foreign" ? "Foreign" : "System.Core", new Version(4, 0, 0, 0), new PublicKeyToken("b77a5c561934e089")));
            var method = new MethodDefUser("TryInvokeMember", MethodSig.CreateInstance(module.CorLibTypes.Boolean,
                module.CorLibTypes.Object, binder.ToTypeSig(), new SZArraySig(module.CorLibTypes.Object), new ByRefSig(module.CorLibTypes.Object)))
                { Body = new CilBody() }; owner.Methods.Add(method);
            var il = method.Body.Instructions;
            if (mode == "nop") il.Add(OpCodes.Nop.ToInstruction());
            if (mode == "extra-effect") { il.Add(OpCodes.Ldstr.ToInstruction("extra")); il.Add(OpCodes.Pop.ToInstruction()); }
            il.Add(OpCodes.Ldarg.ToInstruction(method.Parameters[^1]));
            il.Add(mode == "wrong-result" ? OpCodes.Ldstr.ToInstruction("result") : OpCodes.Ldnull.ToInstruction());
            il.Add(OpCodes.Stind_Ref.ToInstruction());
            il.Add(mode == "true" ? OpCodes.Ldc_I4_1.ToInstruction() : OpCodes.Ldc_I4_0.ToInstruction());
            il.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "TryInvokeMember");
        Assert.Equal(expected, DecliningDynamicInvocation.IsClosed(method));
    }
}
