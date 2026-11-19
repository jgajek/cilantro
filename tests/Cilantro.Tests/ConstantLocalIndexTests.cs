using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ConstantLocalIndexTests
{
    [Theory]
    [InlineData(128)]
    [InlineData(512)]
    public void FoldsManySpillsButPreservesAlternateEntryAndEscapedLocal(int count)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodAttributes.Static) { Body = new CilBody { InitLocals = true } };
            module.GlobalType.Methods.Add(method);
            var gate = new Local(module.CorLibTypes.Int32);
            var escaped = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(gate); method.Body.Variables.Add(escaped);
            var bypass = OpCodes.Nop.ToInstruction(); var il = method.Body.Instructions;
            Add(OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(bypass),
                OpCodes.Ldc_I4_5.ToInstruction(), OpCodes.Stloc.ToInstruction(gate), bypass,
                OpCodes.Ldloca.ToInstruction(escaped), OpCodes.Pop.ToInstruction(),
                OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Stloc.ToInstruction(escaped));
            var locals = new List<Local>();
            for (var index = 0; index < count; index++)
            {
                var local = new Local(module.CorLibTypes.Int32); locals.Add(local); method.Body.Variables.Add(local);
                Add(Instruction.CreateLdcI4(index), OpCodes.Stloc.ToInstruction(local));
            }
            Add(OpCodes.Ldloc.ToInstruction(gate), OpCodes.Ldloc.ToInstruction(escaped), OpCodes.Add.ToInstruction());
            foreach (var local in locals) Add(OpCodes.Ldloc.ToInstruction(local), OpCodes.Add.ToInstruction());
            Add(OpCodes.Ret.ToInstruction());
            void Add(params Instruction[] instructions) { foreach (var instruction in instructions) il.Add(instruction); }
        });
        var method = context.Module.GlobalType.Methods.Single(m => m.Name == "Run");
        var expected = new[] { Run(0), Run(1) };
        Assert.Equal(count, ControlFlowCompletionPass.FoldConstantLocals(method));
        var reads = method.Body.Instructions.Where(i => i.IsLdloc()).Select(i => i.GetLocal(method.Body.Variables)).ToArray();
        Assert.Equal(new[] { method.Body.Variables[0], method.Body.Variables[1] }, reads);
        Assert.Equal(expected, new[] { Run(0), Run(1) });
        Assert.Equal(0, ControlFlowCompletionPass.FoldConstantLocals(method));

        int Run(int argument)
        {
            var result = new StaticMachine().Execute(method, [StaticValue.FromInt32(argument)]);
            Assert.True(result.Succeeded, result.Diagnostic);
            return result.Value.AsInt32();
        }
    }

    [Fact]
    public void HandlerEntryAfterStoreCannotInheritItsValue()
    {
        using var module = new ModuleDefUser("handler-local");
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static)
            { Body = new CilBody { InitLocals = true } };
        module.GlobalType.Methods.Add(method);
        var local = new Local(module.CorLibTypes.Int32); method.Body.Variables.Add(local);
        var handler = OpCodes.Pop.ToInstruction(); var end = OpCodes.Ret.ToInstruction();
        var read = OpCodes.Ldloc.ToInstruction(local);
        var il = method.Body.Instructions;
        il.Add(OpCodes.Ldc_I4_7.ToInstruction()); il.Add(OpCodes.Stloc.ToInstruction(local));
        il.Add(OpCodes.Leave.ToInstruction(end)); il.Add(handler); il.Add(read);
        il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Leave.ToInstruction(end)); il.Add(end);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        { TryStart = il[0], TryEnd = handler, HandlerStart = handler, HandlerEnd = end, CatchType = module.CorLibTypes.Object.TypeDefOrRef });
        Assert.Equal(0, ControlFlowCompletionPass.FoldConstantLocals(method));
        Assert.True(read.IsLdloc());
    }
}
