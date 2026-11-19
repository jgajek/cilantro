using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class UnreadLocalDataflowTests
{
    [Fact]
    public void FoldingIgnoresUnusedLocalsButStoreQueriesKeepTheirFacts()
    {
        using var module = new ModuleDefUser("unused-local-dataflow");
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Boolean),
            MethodAttributes.Static) { Body = new CilBody { InitLocals = true } };
        module.GlobalType.Methods.Add(method);
        var il = method.Body.Instructions;
        var writes = new List<Instruction>();
        for (var index = 0; index < 2048; index++)
        {
            var unused = new Local(module.CorLibTypes.Int32); method.Body.Variables.Add(unused);
            il.Add(Instruction.CreateLdcI4(index));
            var store = OpCodes.Stloc.ToInstruction(unused); writes.Add(store); il.Add(store);
        }
        var live = new Local(module.CorLibTypes.Int32); method.Body.Variables.Add(live);
        var taken = OpCodes.Ldc_I4_7.ToInstruction(); var join = OpCodes.Ldloc.ToInstruction(live);
        var success = OpCodes.Ldc_I4_1.ToInstruction();
        il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Brtrue.ToInstruction(taken));
        il.Add(OpCodes.Ldc_I4_7.ToInstruction()); il.Add(OpCodes.Stloc.ToInstruction(live)); il.Add(OpCodes.Br.ToInstruction(join));
        il.Add(taken); il.Add(OpCodes.Stloc.ToInstruction(live)); il.Add(join);
        il.Add(OpCodes.Ldc_I4_7.ToInstruction()); il.Add(OpCodes.Beq.ToInstruction(success));
        il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        il.Add(success); il.Add(OpCodes.Ret.ToInstruction());
        var expected = new[] { Run(0), Run(1) };
        var stores = LocalConstantPropagation.KnownStores(method);
        for (var index = 0; index < writes.Count; index++) Assert.Equal(index, stores[writes[index]]);
        Assert.True(LocalConstantPropagation.Fold(method) > 0);
        Assert.Equal(expected, new[] { Run(0), Run(1) });
        var after = LocalConstantPropagation.KnownStores(method);
        for (var index = 0; index < writes.Count; index++) Assert.Equal(index, after[writes[index]]);

        int Run(int argument)
        {
            var result = new StaticMachine().Execute(method, [StaticValue.FromInt32(argument)]);
            Assert.True(result.Succeeded, result.Diagnostic);
            return result.Value.AsInt32();
        }
    }
}
