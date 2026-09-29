using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DispatcherArithmeticEffectsTests
{
    [Theory]
    [InlineData(Code.Add, int.MaxValue, 1, false)]
    [InlineData(Code.Sub, int.MinValue, 1, false)]
    [InlineData(Code.Mul, int.MaxValue, 2, false)]
    [InlineData(Code.Xor, -30, 52, false)]
    [InlineData(Code.And, -1, 52, false)]
    [InlineData(Code.Or, -30, 52, false)]
    [InlineData(Code.Shl, 1, 33, false)]
    [InlineData(Code.Shr, -4, 33, false)]
    [InlineData(Code.Shr_Un, -4, 33, false)]
    [InlineData(Code.Ceq, -1, -1, false)]
    [InlineData(Code.Clt, -1, 1, false)]
    [InlineData(Code.Clt_Un, -1, 1, false)]
    [InlineData(Code.Cgt, -1, 1, false)]
    [InlineData(Code.Cgt_Un, -1, 1, false)]
    [InlineData(Code.Neg, int.MinValue, 0, false)]
    [InlineData(Code.Not, 5, 0, false)]
    [InlineData(Code.Div, -13, 5, false)]
    [InlineData(Code.Div_Un, -13, 5, false)]
    [InlineData(Code.Rem, -13, 5, false)]
    [InlineData(Code.Rem_Un, -13, 5, false)]
    [InlineData(Code.Div, 12, 0, true)]
    [InlineData(Code.Div_Un, 12, 0, true)]
    [InlineData(Code.Rem, 12, 0, true)]
    [InlineData(Code.Rem_Un, 12, 0, true)]
    [InlineData(Code.Div, int.MinValue, -1, true)]
    [InlineData(Code.Rem, int.MinValue, -1, true)]
    public void FoldingAcrossACallPreservesItsOrderAndArithmeticExceptions(Code code, int left, int right, bool retainsOperation)
    {
        foreach (var discard in new[] { false, true })
        {
            // Only this generated benign fixture runs in the CLR. The call sits between
            // arithmetic operands, and a second call distinguishes throwing from completion.
            using var module = new ModuleDefUser("arithmetic-effects.dll") { Kind = ModuleKind.Dll };
            new AssemblyDefUser("ArithmeticEffects", new Version(1, 0)).Modules.Add(module);
            var host = new TypeDefUser("Host", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
            module.Types.Add(host);
            var trace = new FieldDefUser("Trace", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static);
            host.Fields.Add(trace);
            var observe = new MethodDefUser("Observe", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static)
            { Body = new CilBody() };
            host.Methods.Add(observe);
            foreach (var i in new[] { OpCodes.Ldsfld.ToInstruction(trace), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Stsfld.ToInstruction(trace), OpCodes.Ret.ToInstruction() })
                observe.Body.Instructions.Add(i);
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static)
            { Body = new CilBody { InitLocals = true } };
            host.Methods.Add(method);
            var state = new Local(module.CorLibTypes.Int32); method.Body.Variables.Add(state);
            var computed = new Local(module.CorLibTypes.Int32); method.Body.Variables.Add(computed);
            var dispatch = Instruction.CreateLdcI4(left); var target = discard ? Instruction.CreateLdcI4(42) : OpCodes.Ldloc.ToInstruction(computed);
            Add(OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(dispatch), dispatch, OpCodes.Call.ToInstruction(observe));
            if (code is not (Code.Neg or Code.Not)) Add(Instruction.CreateLdcI4(right));
            var operation = (OpCode)typeof(OpCodes).GetField(code.ToString())!.GetValue(null)!;
            Add(operation.ToInstruction(), discard ? OpCodes.Pop.ToInstruction() : OpCodes.Stloc.ToInstruction(computed), OpCodes.Call.ToInstruction(observe),
                OpCodes.Ldloc.ToInstruction(state), OpCodes.Switch.ToInstruction([target]), OpCodes.Ldc_I4_M1.ToInstruction(), OpCodes.Ret.ToInstruction(), target, OpCodes.Ret.ToInstruction());
            var before = Execute();
            Assert.Equal(1, DispatcherPathPass.Rewrite(method, preserveEffects: true));
            Assert.Equal(before, Execute());
            Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
            Assert.Equal(before, Execute());
            Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.Code == Code.Switch);
            Assert.Equal(retainsOperation, method.Body.Instructions.Any(i => i.OpCode.Code == code));
            Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
            if (!retainsOperation) { Assert.Equal(2, before.Trace); Assert.Null(before.Exception); if (discard) Assert.Equal(42, before.Result); }
            else Assert.Equal(1, before.Trace);

            void Add(params Instruction[] instructions)
            {
                foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
            }
            (int? Result, int Trace, string? Exception) Execute()
            {
                using var stream = new MemoryStream(); module.Write(stream); stream.Position = 0;
                var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
                try
                {
                    var type = loader.LoadFromStream(stream).GetType("Host")!;
                    int? result = null; string? exception = null;
                    try { result = (int)type.GetMethod("Run")!.Invoke(null, null)!; }
                    catch (System.Reflection.TargetInvocationException error) { exception = error.InnerException!.GetType().FullName; }
                    return (result, (int)type.GetField("Trace")!.GetValue(null)!, exception);
                }
                finally { loader.Unload(); }
            }
        }
    }

}
