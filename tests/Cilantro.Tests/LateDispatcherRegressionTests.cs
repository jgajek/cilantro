using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class LateDispatcherRegressionTests
{
    [Fact]
    public void MergedBooleanSelectorsSpecializeEdgesWithoutRemovingApplicationChoice()
    {
        using var module = Module();
        var method = Method(module);
        var yes = OpCodes.Ldc_I4_1.ToInstruction();
        var value = Instruction.CreateLdcI4(17);
        var join = OpCodes.Brtrue.ToInstruction(value);
        Add(method, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(yes),
            OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Br.ToInstruction(join), yes, join,
            Instruction.CreateLdcI4(23), OpCodes.Ret.ToInstruction(), value, OpCodes.Ret.ToInstruction());
        var before = new[] { Execute(module, 0), Execute(module, 1) };
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.Equal(before, new[] { Execute(module, 0), Execute(module, 1) });
        Assert.Equal(23, before[0]); Assert.Equal(17, before[1]);
        Assert.Single(method.Body.Instructions, i => i.OpCode.FlowControl == FlowControl.Cond_Branch);
    }

    [Fact]
    public void PureMultiLocalPathRetainsWritesAndUnknownApplicationSwitch()
    {
        using var module = Module();
        var method = Method(module);
        var a = new Local(module.CorLibTypes.Int32); var b = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(a); method.Body.Variables.Add(b);
        var dispatch = OpCodes.Ldloc.ToInstruction(a);
        var selected = OpCodes.Ldloc.ToInstruction(b);
        var app = OpCodes.Ldarg_0.ToInstruction();
        var answer = OpCodes.Ldloc.ToInstruction(b);
        var source = OpCodes.Br.ToInstruction(dispatch);
        Add(method, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Stloc.ToInstruction(a), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stloc.ToInstruction(b), source,
            dispatch, OpCodes.Switch.ToInstruction([selected]), OpCodes.Ldc_I4_M1.ToInstruction(), OpCodes.Ret.ToInstruction(),
            selected, OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Xor.ToInstruction(), OpCodes.Stloc.ToInstruction(b), OpCodes.Br.ToInstruction(app),
            app, OpCodes.Switch.ToInstruction([answer]), Instruction.CreateLdcI4(19), OpCodes.Ret.ToInstruction(), answer, OpCodes.Ret.ToInstruction());
        var before = new[] { Execute(module, 0), Execute(module, 1) };
        var graph = ControlFlowGraph.Build(method);
        Assert.Equal(1, EffectfulDispatcherPath.Rewrite(method, graph,
            new Dictionary<Instruction, IReadOnlyDictionary<Local, int>> { [source] = new Dictionary<Local, int> { [a] = 0, [b] = 1 } }));
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.Equal(before, new[] { Execute(module, 0), Execute(module, 1) });
        Assert.Equal(3, before[0]); Assert.Equal(19, before[1]);
        Assert.Single(method.Body.Instructions, i => i.OpCode.Code == Code.Switch);
    }

    private static ModuleDefUser Module()
    {
        var module = new ModuleDefUser("late-dispatch.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser("LateDispatch", new Version(1, 0)).Modules.Add(module);
        return module;
    }
    private static MethodDefUser Method(ModuleDefUser module)
    {
        var host = new TypeDefUser("Host", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
        module.Types.Add(host);
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
            MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { InitLocals = true } };
        host.Methods.Add(method); return method;
    }
    private static int Execute(ModuleDef module, int arg)
    {
        // Execute only the benign source-built fixture.
        using var stream = new MemoryStream(); module.Write(stream); stream.Position = 0;
        var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), true);
        try { return (int)loader.LoadFromStream(stream).GetType("Host")!.GetMethod("Run")!.Invoke(null, [arg])!; }
        finally { loader.Unload(); }
    }
    private static void Add(MethodDef method, params Instruction[] il) { foreach (var i in il) method.Body.Instructions.Add(i); }
}
