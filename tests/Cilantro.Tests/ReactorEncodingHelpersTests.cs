using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorEncodingHelpersTests
{
    [SampleTheory]
    [InlineData("original", true)]
    [InlineData("new-literal", true)]
    [InlineData("typed-argument", true)]
    [InlineData("encoding", false)]
    [InlineData("length", false)]
    [InlineData("local", false)]
    [InlineData("extra-effect", false)]
    [InlineData("foreign", false)]
    public void RequiresCompleteUtilityAndIgnoresOnlyDiscardedLiteralContents(string scenario, bool expected)
    {
        using var module = ModuleDefMD.Load(Checkout.Sample("reactor7-probe-net48.full.exe"));
        var method = Assert.Single(module.GetTypes().SelectMany(t => t.Methods), ReactorEncodingHelpers.Recognize);
        if (scenario == "new-literal") method.Body.Instructions[0].Operand = "a different protector build";
        if (scenario == "typed-argument") method.MethodSig.Params[0] = module.CorLibTypes.String;
        if (scenario == "encoding") ((MemberRef)method.Body.Instructions[6].Operand).Name = "get_UTF8";
        if (scenario == "length") method.Body.Instructions[8].OpCode = OpCodes.Ldc_I4_1;
        if (scenario == "local") method.Body.Variables[0].Type = module.CorLibTypes.Object;
        if (scenario == "extra-effect")
        {
            method.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("extra"));
            method.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        if (scenario == "foreign")
        {
            var member = (MemberRef)method.Body.Instructions[4].Operand;
            member.Class = new TypeRefUser(module, "System", "Convert", new AssemblyRefUser("Foreign"));
        }
        Assert.Equal(expected, ReactorEncodingHelpers.Recognize(method));
    }
}
