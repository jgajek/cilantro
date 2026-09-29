using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class EffectfulDispatcherChainTests
{
    [Theory]
    [InlineData("known")]
    [InlineData("throws")]
    [InlineData("unknown")]
    [InlineData("unsupported")]
    [InlineData("limit")]
    public void ContinuesThroughProvenBranchesAndFallsBackBeforeAnUnprovenSuffix(string scenario)
    {
        using var module = new ModuleDefUser("dispatcher-chain.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser("DispatcherChain", new Version(1, 0)).Modules.Add(module);
        var host = new TypeDefUser("Host", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
        module.Types.Add(host);
        var trace = new FieldDefUser("Trace", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public);
        host.Fields.Add(trace);
        var observe = new MethodDefUser("Observe", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32), MethodAttributes.Static)
        { Body = new CilBody() };
        host.Methods.Add(observe);
        Add(observe, OpCodes.Ldsfld.ToInstruction(trace), Instruction.CreateLdcI4(10), OpCodes.Mul.ToInstruction(),
            OpCodes.Ldarg_0.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Stsfld.ToInstruction(trace));
        var done = OpCodes.Ret.ToInstruction();
        if (scenario == "throws") Add(observe, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldc_I4_2.ToInstruction(),
            OpCodes.Bne_Un.ToInstruction(done), OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
        Add(observe, done);
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static)
        { Body = new CilBody { InitLocals = true } };
        host.Methods.Add(method);
        var state = new Local(module.CorLibTypes.Int32); var result = new Local(module.CorLibTypes.Int32);
        var scratch = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(state); method.Body.Variables.Add(result); method.Body.Variables.Add(scratch);
        var start = OpCodes.Ldc_I4_0.ToInstruction(); var first = OpCodes.Ldc_I4_1.ToInstruction();
        var second = OpCodes.Ldc_I4_1.ToInstruction(); var zero = Instruction.CreateLdcI4(42); var one = Instruction.CreateLdcI4(43);
        var handler = OpCodes.Pop.ToInstruction(); var finish = OpCodes.Ldloc.ToInstruction(result);
        var source = OpCodes.Br.ToInstruction(first);
        Add(method, start, OpCodes.Stloc.ToInstruction(state), source, first, OpCodes.Call.ToInstruction(observe),
            OpCodes.Ldloc.ToInstruction(state), OpCodes.Switch.ToInstruction([second]), OpCodes.Br.ToInstruction(zero),
            second, OpCodes.Stloc.ToInstruction(state));
        if (scenario == "unsupported") Add(method, OpCodes.Ldloca.ToInstruction(scratch), OpCodes.Pop.ToInstruction());
        if (scenario == "limit") for (var n = 0; n < 40; n++) Add(method, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Pop.ToInstruction());
        Add(method, OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Call.ToInstruction(observe),
            scenario == "unknown" ? OpCodes.Ldarg_0.ToInstruction() : OpCodes.Ldloc.ToInstruction(state),
            OpCodes.Switch.ToInstruction([zero, one]), OpCodes.Br.ToInstruction(zero),
            zero, OpCodes.Stloc.ToInstruction(result), OpCodes.Leave.ToInstruction(finish),
            one, OpCodes.Stloc.ToInstruction(result), OpCodes.Leave.ToInstruction(finish),
            handler, OpCodes.Ldloc.ToInstruction(state), OpCodes.Stloc.ToInstruction(result), OpCodes.Leave.ToInstruction(finish),
            finish, OpCodes.Ret.ToInstruction());
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = finish, CatchType = module.CorLibTypes.GetTypeRef("System", "Exception") });
        var before = new[] { Execute(0), Execute(1) };
        var expected = scenario == "throws" ? new[] { 1, 1 } : scenario == "unknown" ? new[] { 42, 43 } : new[] { 43, 43 };
        Assert.Equal(expected, before.Select(r => r.Result));
        Assert.All(before, r => Assert.Equal(12, r.Trace));
        Assert.Equal(1, DispatcherPathPass.Rewrite(method, preserveEffects: true));
        Assert.Same(scenario is "known" or "throws" ? one : second, source.Operand);
        Assert.Equal(before, new[] { Execute(0), Execute(1) });
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.Equal(before, new[] { Execute(0), Execute(1) });
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);

        (int Result, int Trace) Execute(int argument)
        {
            // Execute only this benign generated fixture; actual samples use static analysis.
            using var stream = new MemoryStream(); module.Write(stream); stream.Position = 0;
            var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
            try
            {
                var type = loader.LoadFromStream(stream).GetType("Host")!;
                return ((int)type.GetMethod("Run")!.Invoke(null, [argument])!, (int)type.GetField("Trace")!.GetValue(null)!);
            }
            finally { loader.Unload(); }
        }
    }

    private static void Add(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }
}
