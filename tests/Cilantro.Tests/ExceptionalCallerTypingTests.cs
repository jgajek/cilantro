using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ExceptionalCallerTypingTests
{
    [Theory]
    [InlineData("typed", true)]
    [InlineData("unknown", false)]
    [InlineData("boundary", false)]
    [InlineData("loop-before", true)]
    public void StackEvidenceStaysInsideItsExceptionRegion(string shape, bool repaired)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "ProtectedCaller");
            var target = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(target);
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void,
                shape == "unknown" ? module.CorLibTypes.Object : new SZArraySig(module.CorLibTypes.Byte)),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(caller);
            var load = OpCodes.Ldarg_0.ToInstruction();
            var call = OpCodes.Call.ToInstruction(target);
            var handler = OpCodes.Pop.ToInstruction();
            var done = OpCodes.Ret.ToInstruction();
            var il = caller.Body.Instructions;
            if (shape == "loop-before")
            {
                var loop = OpCodes.Ldc_I4_0.ToInstruction();
                il.Add(loop); il.Add(OpCodes.Brtrue.ToInstruction(loop));
            }
            il.Add(load); il.Add(OpCodes.Br.ToInstruction(call)); il.Add(call);
            il.Add(OpCodes.Leave.ToInstruction(done));
            il.Add(handler); il.Add(OpCodes.Leave.ToInstruction(done)); il.Add(done);
            caller.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = load, TryEnd = handler,
                HandlerStart = handler, HandlerEnd = done,
                CatchType = module.CorLibTypes.GetTypeRef("System", "Exception")
            });
        });
        if (shape == "boundary")
        {
            // Inject an invalid cross-region stack after serialization; recovery must refuse it.
            var caller = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Run");
            caller.Body.ExceptionHandlers[0].TryStart = caller.Body.Instructions.Single(i => i.OpCode.Code == Code.Call);
        }
        Assert.Equal(repaired ? 1 : 0, new ArrayParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ArrayParameterTypingPass().Run(context).Changes);
        if (repaired)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void UnknownOtherArgumentDoesNotEraseIndependentArrayEvidence(bool known)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "IndependentSlots");
            var target = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.Void,
                module.CorLibTypes.Object, module.CorLibTypes.Object), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(target);
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void,
                known ? new SZArraySig(module.CorLibTypes.Byte) : module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(caller);
            var load = OpCodes.Ldarg_0.ToInstruction();
            var call = OpCodes.Call.ToInstruction(target);
            var handler = OpCodes.Pop.ToInstruction();
            var done = OpCodes.Ret.ToInstruction();
            var il = caller.Body.Instructions;
            il.Add(load); il.Add(OpCodes.Ldc_I4_0.ToInstruction());
            il.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
            il.Add(OpCodes.Br.ToInstruction(call)); il.Add(call); il.Add(OpCodes.Leave.ToInstruction(done));
            il.Add(handler); il.Add(OpCodes.Leave.ToInstruction(done)); il.Add(done);
            caller.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = load, TryEnd = handler, HandlerStart = handler, HandlerEnd = done,
                CatchType = module.CorLibTypes.GetTypeRef("System", "Exception")
            });
        });
        Assert.Equal(known ? 1 : 0, new ArrayParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ArrayParameterTypingPass().Run(context).Changes);
        var target = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Use");
        Assert.Equal(known ? 1 : 0, target.Body.Instructions.Count(i => i.OpCode.Code == Code.Castclass));
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try { context.Module.Write(path); Assert.Equal(known ? 0 : 1, IlVerification.Read(path, []).Count); }
        finally { File.Delete(path); }
    }}
