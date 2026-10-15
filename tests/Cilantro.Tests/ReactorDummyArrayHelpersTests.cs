using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorDummyArrayHelpersTests
{
    [SampleTheory]
    [InlineData("original", true)]
    [InlineData("simplified", true)]
    [InlineData("literal", true)]
    [InlineData("array-size", false)]
    [InlineData("element", false)]
    [InlineData("operation", false)]
    [InlineData("effect", false)]
    [InlineData("foreign", false)]
    public void RequiresCompleteDecoyBody(string scenario, bool expected)
    {
        using var module = ModuleDefMD.Load(Checkout.Sample("reactor7-probe-net48.full.exe"));
        var methods = module.GetTypes().SelectMany(t => t.Methods).Where(ReactorDummyArrayHelpers.Recognize).ToArray();
        Assert.Equal(2, methods.Length);
        foreach (var method in methods)
        {
            var il = method.Body.Instructions;
            if (scenario == "simplified") { il.RemoveAt(2); il.RemoveAt(2); }
            if (scenario == "literal") il[0].Operand = "different decoy text";
            if (scenario == "array-size") il[il.IndexOf(il.Single(i => i.OpCode.Code == Code.Newarr)) - 1].OpCode = OpCodes.Ldc_I4_3;
            if (scenario == "element") il[^3].OpCode = OpCodes.Ldc_I4_3;
            if (scenario == "operation") ((MemberRef)il[1].Operand).Name = "DifferentOperation";
            if (scenario == "effect") { il.Insert(0, OpCodes.Ldstr.ToInstruction("extra")); il.Insert(1, OpCodes.Pop.ToInstruction()); }
            if (scenario == "foreign") ((MemberRef)il[1].Operand).Class = new TypeRefUser(module, "System", "String", new AssemblyRefUser("Foreign"));
            Assert.Equal(expected, ReactorDummyArrayHelpers.Recognize(method));
        }
    }
}
