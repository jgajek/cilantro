using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class GenericCallerReturnTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OnlyClosedMethodReturnTypesCertifyArrayArguments(bool open)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Consumers");
            var factory = new MethodDefUser("Create", MethodSig.CreateStatic(new SZArraySig(new GenericMVar(0))),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            factory.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            factory.MethodSig.GenParamCount = 1;
            factory.MethodSig.Generic = true;
            owner.Methods.Add(factory);
            factory.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
            factory.Body.Instructions.Add(OpCodes.Newarr.ToInstruction(new TypeSpecUser(new GenericMVar(0))));
            factory.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var consumer = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(consumer);
            consumer.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Conv_I4.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            if (open)
            {
                caller.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "U"));
                caller.MethodSig.GenParamCount = 1; caller.MethodSig.Generic = true;
            }
            owner.Methods.Add(caller);
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MethodSpecUser(factory,
                new GenericInstMethodSig(open ? new GenericMVar(0) : module.CorLibTypes.Int32))));
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(consumer));
            caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            Assert.Equal(1, IlVerification.Read(path, []).Count);
            Assert.Equal(open ? 0 : 1, new ArrayParameterTypingPass().Run(context).Changes);
            Assert.Equal(0, new ArrayParameterTypingPass().Run(context).Changes);
            context.Module.Write(path);
            Assert.Equal(open ? 1 : 0, IlVerification.Read(path, []).Count);
        }
        finally { File.Delete(path); }
    }
}
