using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class EffectfulDispatcherTests
{
    [Fact]
    public void AFilteredCatchInTheDestinationKeepsItsIncomingLocalValue()
    {
        using var module = new ModuleDefUser("future-filter.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser("FilterFixture", new Version(1, 0)).Modules.Add(module);
        var host = new TypeDefUser("Host", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public }; module.Types.Add(host);
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Static | MethodAttributes.Public)
        { Body = new CilBody { InitLocals = true } }; host.Methods.Add(method);
        var helper = new MethodDefUser("Observe", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static)
        { Body = new CilBody() }; host.Methods.Add(helper); Add(helper, OpCodes.Ret.ToInstruction());
        var state = new Local(module.CorLibTypes.Int32); var scratch = new Local(module.CorLibTypes.Int32); var result = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(state); method.Body.Variables.Add(scratch); method.Body.Variables.Add(result);
        var dispatch = Instruction.CreateLdcI4(7); var target = OpCodes.Nop.ToInstruction();
        var tryStart = OpCodes.Ldnull.ToInstruction(); var filter = OpCodes.Pop.ToInstruction();
        var handler = OpCodes.Pop.ToInstruction(); var finish = OpCodes.Ldloc.ToInstruction(result);
        Add(method, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(dispatch),
            dispatch, OpCodes.Stloc.ToInstruction(scratch), OpCodes.Call.ToInstruction(helper), OpCodes.Ldloc.ToInstruction(state),
            OpCodes.Switch.ToInstruction([target]), OpCodes.Br.ToInstruction(target), target, tryStart, OpCodes.Throw.ToInstruction(),
            filter, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Endfilter.ToInstruction(), handler, OpCodes.Ldloc.ToInstruction(scratch),
            OpCodes.Stloc.ToInstruction(result), OpCodes.Leave.ToInstruction(finish), finish, OpCodes.Ret.ToInstruction());
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Filter)
        { TryStart = tryStart, TryEnd = filter, FilterStart = filter, HandlerStart = handler, HandlerEnd = finish });
        Assert.Equal(7, Execute());
        Assert.Equal(1, DispatcherPathPass.Rewrite(method, preserveEffects: true));
        Assert.Equal(2, method.Body.Instructions.Count(i => i.IsStloc() && i.GetLocal(method.Body.Variables) == scratch));
        Assert.Equal(7, Execute());
        int Execute()
        {
            // Filter execution is not modeled by StaticMachine; use only this benign fixture.
            using var stream = new MemoryStream(); module.Write(stream); stream.Position = 0;
            var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
            try { return (int)loader.LoadFromStream(stream).GetType("Host")!.GetMethod("Run")!.Invoke(null, null)!; }
            finally { loader.Unload(); }
        }
    }

    [Fact]
    public void EffectfulSpecializationRunsAfterShapeAndConstantRecovery()
    {
        var passes = Cilantro.Core.CilantroPipeline.CreateDefaultPasses().Select(p => p.Name).ToList();
        var at = passes.IndexOf("dispatcher-effects-completion");
        Assert.True(at > passes.IndexOf("dispatcher-paths-completion"));
        Assert.True(at > passes.IndexOf("control-flow-table-finalization"));
        Assert.True(at < passes.IndexOf("symbol-renaming"));
    }

    [Theory]
    [InlineData("call", true)]
    [InlineData("two-calls", true)]
    [InlineData("call-throws", true)]
    [InlineData("field-initializer", true)]
    [InlineData("field-initializer-throws", true)]
    [InlineData("finally-throws", true)]
    [InlineData("null-field", true)]
    [InlineData("shared-store", true)]
    [InlineData("computed-store", true)]
    [InlineData("virtual-call", true)]
    [InlineData("call-result", false)]
    [InlineData("unknown-condition", false)]
    [InlineData("address", false)]
    [InlineData("volatile", false)]
    [InlineData("long-prefix", true)]
    [InlineData("dead-temporary", true)]
    [InlineData("live-temporary", true)]
    [InlineData("handler-temporary", true)]
    public void OrderedEffectsAndExceptionVisibleLocalsSurviveSpecialization(string scenario, bool rewrites)
    {
        using var module = new ModuleDefUser("effects.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser("EffectsFixture", new Version(1, 0)).Modules.Add(module);
        var host = new TypeDefUser("Host", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
        module.Types.Add(host);
        var trace = new FieldDefUser("Trace", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public);
        host.Fields.Add(trace);
        var observe = Method("Observe", module.CorLibTypes.Int32, module.CorLibTypes.Int32);
        Add(observe, OpCodes.Ldsfld.ToInstruction(trace), Instruction.CreateLdcI4(100), OpCodes.Mul.ToInstruction(),
            OpCodes.Ldarg_0.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Stsfld.ToInstruction(trace));
        if (scenario is "call-throws" or "finally-throws" or "handler-temporary")
        {
            var ok = OpCodes.Ldc_I4_0.ToInstruction();
            Add(observe, OpCodes.Ldarg_0.ToInstruction(), Instruction.CreateLdcI4(11), OpCodes.Bne_Un.ToInstruction(ok),
                OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction(), ok, OpCodes.Ret.ToInstruction());
        }
        else Add(observe, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ret.ToInstruction());
        var gate = new TypeDefUser("Gate", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(gate);
        var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32),
            scenario == "null-field" ? FieldAttributes.Public : FieldAttributes.Public | FieldAttributes.Static);
        gate.Fields.Add(field);
        var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
        { Body = new CilBody() };
        gate.Methods.Add(initializer);
        Add(initializer, Instruction.CreateLdcI4(77), OpCodes.Stsfld.ToInstruction(trace), OpCodes.Ret.ToInstruction());
        if (scenario == "field-initializer-throws")
        {
            initializer.Body.Instructions.RemoveAt(initializer.Body.Instructions.Count - 1);
            Add(initializer, OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
        }
        var constructor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
        { Body = new CilBody() };
        gate.Methods.Add(constructor);
        Add(constructor, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)), OpCodes.Ret.ToInstruction());
        var read = new MethodDefUser("Read", MethodSig.CreateInstance(module.CorLibTypes.Int32),
            MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot)
        { Body = new CilBody() };
        gate.Methods.Add(read); Add(read, OpCodes.Ldsfld.ToInstruction(trace), OpCodes.Ret.ToInstruction());

        var method = Method("Run", module.CorLibTypes.Int32, module.CorLibTypes.Int32);
        var state = new Local(module.CorLibTypes.Int32); var temporary = new Local(module.CorLibTypes.Int32); var result = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(state); method.Body.Variables.Add(temporary); method.Body.Variables.Add(result);
        var scratch = new Local(module.CorLibTypes.Int32); method.Body.Variables.Add(scratch);
        var alternate = OpCodes.Ldc_I4_1.ToInstruction();
        var dispatch = OpCodes.Ldloc.ToInstruction(state);
        var shared = OpCodes.Stloc.ToInstruction(state);
        var entry = scenario == "shared-store" ? shared : dispatch;
        var zero = OpCodes.Ldloc.ToInstruction(state); var one = OpCodes.Ldloc.ToInstruction(state);
        var handler = OpCodes.Pop.ToInstruction(); var finish = OpCodes.Ldloc.ToInstruction(result);
        var start = OpCodes.Ldarg_0.ToInstruction();
        if (scenario == "address") Add(method, OpCodes.Ldloca.ToInstruction(state), OpCodes.Pop.ToInstruction());
        Add(method, start, OpCodes.Brtrue.ToInstruction(alternate), OpCodes.Ldc_I4_0.ToInstruction());
        Source(); Add(method, alternate); Source();
        if (scenario == "shared-store") Add(method, shared);
        Add(method, dispatch, Instruction.CreateLdcI4(10), OpCodes.Add.ToInstruction(), OpCodes.Stloc.ToInstruction(state),
            OpCodes.Ldloc.ToInstruction(state), OpCodes.Stloc.ToInstruction(temporary));
        if (scenario.EndsWith("-temporary", StringComparison.Ordinal)) Add(method, Instruction.CreateLdcI4(7), OpCodes.Stloc.ToInstruction(scratch));
        if (scenario == "virtual-call") Add(method, OpCodes.Newobj.ToInstruction(constructor), OpCodes.Callvirt.ToInstruction(read), OpCodes.Pop.ToInstruction());
        else if (scenario == "null-field") Add(method, OpCodes.Ldnull.ToInstruction(), OpCodes.Ldfld.ToInstruction(field), OpCodes.Pop.ToInstruction());
        else if (scenario is "field-initializer" or "field-initializer-throws" or "volatile")
        {
            if (scenario == "volatile") Add(method, OpCodes.Volatile.ToInstruction());
            Add(method, OpCodes.Ldsfld.ToInstruction(field), OpCodes.Pop.ToInstruction());
        }
        else
        {
            Add(method, OpCodes.Ldloc.ToInstruction(state), OpCodes.Call.ToInstruction(observe), OpCodes.Pop.ToInstruction());
            if (scenario == "two-calls") Add(method, Instruction.CreateLdcI4(23), OpCodes.Call.ToInstruction(observe), OpCodes.Pop.ToInstruction());
            if (scenario == "long-prefix")
                for (var n = 0; n < 30; n++) Add(method, OpCodes.Ldloc.ToInstruction(state), OpCodes.Call.ToInstruction(observe), OpCodes.Pop.ToInstruction());
        }
        Add(method, Instruction.CreateLdcI4(99), OpCodes.Stloc.ToInstruction(temporary));
        if (scenario == "call-result") Add(method, OpCodes.Ldloc.ToInstruction(state), OpCodes.Call.ToInstruction(observe));
        else if (scenario == "unknown-condition") Add(method, OpCodes.Ldarg_0.ToInstruction());
        else Add(method, OpCodes.Ldloc.ToInstruction(state), Instruction.CreateLdcI4(10), OpCodes.Sub.ToInstruction());
        Add(method, OpCodes.Switch.ToInstruction([zero, one]), OpCodes.Ldc_I4_M1.ToInstruction(), OpCodes.Stloc.ToInstruction(result), OpCodes.Leave.ToInstruction(finish));
        Destination(zero, 1000); Destination(one, 2000);
        Add(method, handler, OpCodes.Ldloc.ToInstruction(state), Instruction.CreateLdcI4(100), OpCodes.Mul.ToInstruction(),
            OpCodes.Ldloc.ToInstruction(scenario == "handler-temporary" ? scratch : temporary), OpCodes.Add.ToInstruction(), OpCodes.Stloc.ToInstruction(result), OpCodes.Leave.ToInstruction(finish));
        var catchEnd = finish;
        if (scenario == "finally-throws")
        {
            catchEnd = OpCodes.Ldsfld.ToInstruction(trace);
            Add(method, catchEnd, Instruction.CreateLdcI4(1000), OpCodes.Mul.ToInstruction(), OpCodes.Ldloc.ToInstruction(temporary),
                OpCodes.Add.ToInstruction(), OpCodes.Stsfld.ToInstruction(trace), OpCodes.Endfinally.ToInstruction());
            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
            { TryStart = start, TryEnd = catchEnd, HandlerStart = catchEnd, HandlerEnd = finish });
        }
        Add(method, finish, OpCodes.Ret.ToInstruction());
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = catchEnd, CatchType = module.CorLibTypes.GetTypeRef("System", "Exception") });
        // The CLR requires the inner catch clause before its enclosing finally.
        if (scenario == "finally-throws")
        {
            var outer = method.Body.ExceptionHandlers[0];
            method.Body.ExceptionHandlers.RemoveAt(0); method.Body.ExceptionHandlers.Add(outer);
        }
        var before = new[] { Execute(0), Execute(1) };
        var runtimeBefore = new[] { ExecuteRuntime(0), ExecuteRuntime(1) };
        Assert.All(before, r => Assert.Equal(StaticExecutionStatus.Completed, r.Status));
        var expected = scenario switch
        {
            "null-field" or "field-initializer-throws" => new[] { 1010, 1111 },
            "call-throws" or "finally-throws" => new[] { 1109, 1111 },
            "call-result" => new[] { 1109, 1110 },
            "live-temporary" => new[] { 1017, 2018 },
            "handler-temporary" => new[] { 1109, 1107 },
            _ => new[] { 1109, 2110 }
        };
        Assert.Equal(expected, before.Select(r => r.Result));
        Assert.Equal(expected, runtimeBefore.Select(r => r.Result));
        Assert.Equal(before.Select(r => r.Trace.AsInt32()), runtimeBefore.Select(r => r.Trace));
        Assert.Equal(rewrites ? 1 : 0, DispatcherPathPass.Rewrite(method, preserveEffects: true));
        if (scenario.EndsWith("-temporary", StringComparison.Ordinal))
            Assert.Equal(scenario == "dead-temporary" ? 1 : 2, method.Body.Instructions.Count(i => i.IsStloc() && i.GetLocal(method.Body.Variables) == scratch));
        Assert.Equal(before, new[] { Execute(0), Execute(1) });
        Assert.Equal(runtimeBefore, new[] { ExecuteRuntime(0), ExecuteRuntime(1) });
        if (rewrites)
        {
            for (var round = 0; round < 8; round++)
            {
                var changed = DispatcherPathPass.Rewrite(method, preserveEffects: true);
                ControlFlowCompletionPass.TryComplete(method);
                if (changed == 0) break;
            }
            Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.Code == Code.Switch);
            Assert.Equal(before, new[] { Execute(0), Execute(1) });
            Assert.Equal(runtimeBefore, new[] { ExecuteRuntime(0), ExecuteRuntime(1) });
            Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        }

        MethodDefUser Method(string name, TypeSig returns, params TypeSig[] args)
        {
            var m = new MethodDefUser(name, MethodSig.CreateStatic(returns, args), MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody { InitLocals = true } };
            host.Methods.Add(m); return m;
        }
        void Source()
        {
            if (scenario == "computed-store") Add(method, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Add.ToInstruction());
            if (scenario != "shared-store") Add(method, OpCodes.Stloc.ToInstruction(state));
            Add(method, OpCodes.Br.ToInstruction(entry));
        }
        void Destination(Instruction first, int offset) => Add(method, first, Instruction.CreateLdcI4(offset), OpCodes.Add.ToInstruction(),
            OpCodes.Ldloc.ToInstruction(scenario == "live-temporary" ? scratch : temporary), OpCodes.Add.ToInstruction(), OpCodes.Stloc.ToInstruction(result), OpCodes.Leave.ToInstruction(finish));
        (StaticExecutionStatus Status, int Result, StaticValue Trace) Execute(int input)
        {
            // The interpreter currently refuses a null field receiver rather than
            // delivering a catchable NRE. Use the benign CLR fixture for that case.
            if (scenario is "null-field" or "field-initializer-throws")
            {
                var actual = ExecuteRuntime(input);
                return (StaticExecutionStatus.Completed, actual.Result, StaticValue.FromInt32(actual.Trace));
            }
            var machine = new StaticMachine(modelTypeInitialization: true); var r = machine.Execute(method, [StaticValue.FromInt32(input)]);
            return (r.Status, r.Value.IsKnown ? r.Value.AsInt32() : -9999, machine.State.ReadStaticField(trace));
        }
        (int Result, int Trace) ExecuteRuntime(int input)
        {
            // Only this source-built synthetic assembly is executed, never a corpus sample.
            using var stream = new MemoryStream(); module.Write(stream); stream.Position = 0;
            var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
            try
            {
                var type = loader.LoadFromStream(stream).GetType("Host")!;
                return ((int)type.GetMethod("Run")!.Invoke(null, [input])!, (int)type.GetField("Trace")!.GetValue(null)!);
            }
            finally { loader.Unload(); }
        }
    }

    private static void Add(MethodDef method, params Instruction[] instructions)
    { foreach (var i in instructions) method.Body.Instructions.Add(i); }
}
