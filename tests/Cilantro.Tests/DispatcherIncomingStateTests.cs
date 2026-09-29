using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DispatcherIncomingStateTests
{
    [Theory]
    [InlineData("same-join", true)]
    [InlineData("different-join", false)]
    [InlineData("inherited", true)]
    [InlineData("loop-stable", true)]
    [InlineData("loop-changes", false)]
    [InlineData("overwritten", false)]
    [InlineData("address", false)]
    [InlineData("finally", false)]
    public void UsesOnlyConvergedUnaliasedIncomingState(string scenario, bool known)
    {
        using var module = new ModuleDefUser("incoming-state.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser("IncomingState", new Version(1, 0)).Modules.Add(module);
        var host = new TypeDefUser("Host", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
        module.Types.Add(host);
        var trace = new FieldDefUser("Trace", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static);
        host.Fields.Add(trace);
        var observe = Method("Observe", module.CorLibTypes.Void, module.CorLibTypes.Int32);
        Add(observe, OpCodes.Ldsfld.ToInstruction(trace), Instruction.CreateLdcI4(10), OpCodes.Mul.ToInstruction(),
            OpCodes.Ldarg_0.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Stsfld.ToInstruction(trace), OpCodes.Ret.ToInstruction());
        var method = Method("Run", module.CorLibTypes.Int32, module.CorLibTypes.Int32);
        var state = new Local(module.CorLibTypes.Int32); var counter = new Local(module.CorLibTypes.Int32);
        var result = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(state); method.Body.Variables.Add(counter); method.Body.Variables.Add(result);
        var join = Instruction.CreateLdcI4(3); var dispatch = Instruction.CreateLdcI4(4);
        var zero = Instruction.CreateLdcI4(42); var one = Instruction.CreateLdcI4(43);
        var source = OpCodes.Br.ToInstruction(dispatch);
        Add(method, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stloc.ToInstruction(state));
        if (scenario is "same-join" or "different-join")
        {
            var alternate = OpCodes.Ldc_I4_1.ToInstruction();
            Add(method, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(alternate),
                Instruction.CreateLdcI4(scenario == "same-join" ? 1 : 0), OpCodes.Stloc.ToInstruction(state),
                OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Call.ToInstruction(observe), OpCodes.Br.ToInstruction(join),
                alternate, OpCodes.Stloc.ToInstruction(state), OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Call.ToInstruction(observe), OpCodes.Br.ToInstruction(join));
        }
        else if (scenario.StartsWith("loop-", StringComparison.Ordinal))
        {
            var body = OpCodes.Ldc_I4_1.ToInstruction(); var check = OpCodes.Ldloc.ToInstruction(counter);
            Add(method, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Stloc.ToInstruction(counter), OpCodes.Br.ToInstruction(check),
                body, OpCodes.Call.ToInstruction(observe));
            if (scenario == "loop-changes") Add(method, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Stloc.ToInstruction(state));
            Add(method, OpCodes.Ldloc.ToInstruction(counter), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Sub.ToInstruction(), OpCodes.Stloc.ToInstruction(counter),
                check, OpCodes.Brtrue.ToInstruction(body));
        }
        else if (scenario == "finally")
        {
            var start = OpCodes.Nop.ToInstruction(); var handler = OpCodes.Ldc_I4_0.ToInstruction();
            Add(method, start, OpCodes.Leave.ToInstruction(join), handler, OpCodes.Stloc.ToInstruction(state), OpCodes.Endfinally.ToInstruction());
            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
            { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = join });
        }
        else if (scenario == "address")
        {
            var mutate = Method("Mutate", module.CorLibTypes.Void, new ByRefSig(module.CorLibTypes.Int32), module.CorLibTypes.Int32);
            Add(mutate, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Stind_I4.ToInstruction(), OpCodes.Ret.ToInstruction());
            Add(method, OpCodes.Ldloca.ToInstruction(state), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(mutate));
        }
        else if (scenario == "overwritten") Add(method, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Stloc.ToInstruction(state));
        // The inherited case splits after the defining store with a conditional edge,
        // so no unconditional source block defines state locally.
        else Add(method, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(join));
        Add(method, join, OpCodes.Call.ToInstruction(observe), source,
            dispatch, OpCodes.Call.ToInstruction(observe), OpCodes.Ldloc.ToInstruction(state), OpCodes.Switch.ToInstruction([zero, one]),
            Instruction.CreateLdcI4(-1), OpCodes.Ret.ToInstruction(), zero, OpCodes.Ret.ToInstruction(), one, OpCodes.Ret.ToInstruction());

        var inputs = new Dictionary<Instruction, IReadOnlyDictionary<Local, int>>();
        LocalConstantPropagation.KnownStores(method, inputs);
        Assert.Equal(known, inputs.TryGetValue(source, out var incoming) && incoming.ContainsKey(state));
        if (known) Assert.Equal(1, incoming![state]);
        var arguments = scenario.StartsWith("loop-", StringComparison.Ordinal) ? new[] { 0, 1, 3 } : new[] { 0, 1 };
        var before = arguments.Select(Execute).ToArray();
        var expected = scenario switch
        {
            "different-join" or "overwritten" or "address" => new[] { 42, 43 },
            "finally" => [42, 42],
            "loop-changes" => [43, 42, 42],
            _ => arguments.Select(_ => 43).ToArray()
        };
        Assert.Equal(expected, before.Select(r => r.Result));
        var changes = 0;
        for (var round = 0; round < 16; round++)
        {
            var changed = DispatcherPathPass.Rewrite(method, preserveEffects: true);
            changes += changed;
            Assert.Equal(before, arguments.Select(Execute).ToArray());
            if (changed == 0) break;
            Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
            Assert.Equal(before, arguments.Select(Execute).ToArray());
        }
        if (known || scenario == "different-join")
        {
            Assert.True(changes > 0);
            Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.Code == Code.Switch);
        }
        else Assert.Equal(0, changes);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);

        MethodDefUser Method(string name, TypeSig returns, params TypeSig[] parameters)
        {
            var created = new MethodDefUser(name, MethodSig.CreateStatic(returns, parameters), MethodAttributes.Public | MethodAttributes.Static)
            { Body = new CilBody { InitLocals = true } };
            host.Methods.Add(created); return created;
        }
        (int Result, int Trace) Execute(int argument)
        {
            // Only this generated benign fixture runs in the CLR.
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
