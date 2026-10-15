using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DiscardedStackValuesTests
{
    [Theory]
    [InlineData("native", true)]
    [InlineData("duplicate", true)]
    [InlineData("null-store", true)]
    [InlineData("live-copy", false)]
    [InlineData("checked", false)]
    [InlineData("unknown-reference", false)]
    [InlineData("field", true)]
    public void RemovesOnlyUnusedLiteralOrStackCopies(string scenario, bool changes)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Object))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(method);
            var local = new Local(scenario == "live-copy" ? module.CorLibTypes.Int32 : module.CorLibTypes.Object);
            method.Body.Variables.Add(local);
            var il = method.Body.Instructions;
            switch (scenario)
            {
                case "native":
                    il.Add(OpCodes.Ldc_I4_1.ToInstruction()); il.Add(OpCodes.Conv_U.ToInstruction());
                    il.Add(OpCodes.Conv_I4.ToInstruction()); il.Add(OpCodes.Pop.ToInstruction()); break;
                case "duplicate":
                    il.Add(OpCodes.Ldc_I4_7.ToInstruction()); il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Pop.ToInstruction());
                    il.Add(OpCodes.Ret.ToInstruction()); return;
                case "null-store":
                    il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Dup.ToInstruction());
                    il.Add(OpCodes.Stloc.ToInstruction(local)); il.Add(OpCodes.Pop.ToInstruction()); break;
                case "live-copy":
                    il.Add(OpCodes.Ldc_I4_7.ToInstruction()); il.Add(OpCodes.Dup.ToInstruction());
                    il.Add(OpCodes.Stloc.ToInstruction(local)); il.Add(OpCodes.Pop.ToInstruction());
                    il.Add(OpCodes.Ldloc.ToInstruction(local)); il.Add(OpCodes.Ret.ToInstruction()); return;
                case "checked":
                    il.Add(OpCodes.Ldc_I8.ToInstruction(long.MaxValue)); il.Add(OpCodes.Conv_Ovf_I4.ToInstruction()); il.Add(OpCodes.Pop.ToInstruction()); break;
                case "unknown-reference":
                    il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Stloc.ToInstruction(local)); break;
                case "field":
                    var field = new FieldDefUser("Field", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
                    owner.Fields.Add(field); il.Add(OpCodes.Ldsfld.ToInstruction(field));
                    il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Pop.ToInstruction()); break;
            }
            il.Add(OpCodes.Ldc_I4_7.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Run");
        var count = 0;
        for (var n = 0; n < 4; n++) count += DiscardedStackValues.Remove(method);
        Assert.Equal(changes, count != 0);
        if (scenario == "field") Assert.Contains(method.Body.Instructions, i => i.OpCode.Code == Code.Ldsfld);
        if (scenario == "checked") { Assert.Contains(method.Body.Instructions, i => i.OpCode.Code == Code.Conv_Ovf_I4); return; }
        var machine = new StaticMachine(BootstrapMachine.Limits(10000), StaticIntrinsicRegistry.CreateDefault(), modelTypeInitialization: true);
        var result = machine.Execute(method, [StaticValue.Null]);
        Assert.True(result.Succeeded, result.Diagnostic); Assert.Equal(7, result.Value.AsInt32());
    }
}
