using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorFileHelpersTests
{
    [SampleTheory]
    [InlineData("original", true)]
    [InlineData("branch", false)]
    [InlineData("handler", false)]
    [InlineData("local", false)]
    [InlineData("extra-effect", false)]
    [InlineData("framework", false)]
    [InlineData("operation", false)]
    public void CompleteBenignRuntimeBodiesAreRequired(string scenario, bool expected)
    {
        using var module = ModuleDefMD.Load(Checkout.Sample("reactor7-probe-net48.full.exe"));
        var methods = module.GetTypes().SelectMany(t => t.Methods).Where(ReactorFileHelpers.Recognize).ToArray();
        Assert.Equal(2, methods.Length);
        foreach (var method in methods)
        {
            if (scenario == "branch")
                method.Body.Instructions.First(i => i.OpCode.FlowControl == FlowControl.Cond_Branch).Operand = method.Body.Instructions[^1];
            if (scenario == "handler") method.Body.ExceptionHandlers[0].TryEnd = method.Body.ExceptionHandlers[0].HandlerEnd;
            if (scenario == "local") method.Body.Variables[0].Type = module.CorLibTypes.Int64;
            if (scenario == "extra-effect")
            {
                method.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("unexpected"));
                method.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
            }
            var member = (MemberRef)method.Body.Instructions.First(i => i.Operand is MemberRef).Operand;
            if (scenario == "framework")
                member.Class = new TypeRefUser(module, member.DeclaringType.Namespace, member.DeclaringType.Name,
                    new AssemblyRefUser("Foreign"));
            if (scenario == "operation") member.Name = "DifferentOperation";
            Assert.Equal(expected, ReactorFileHelpers.Recognize(method));
        }
    }
}
