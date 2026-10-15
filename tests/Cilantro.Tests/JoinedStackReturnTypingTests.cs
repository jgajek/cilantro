using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class JoinedStackReturnTypingTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void DeclaredReturnSurvivesAnUnknownIncomingReceiver(bool typedReturn)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Factory");
            var factory = new MethodDefUser("Get", MethodSig.CreateInstance(typedReturn ? module.CorLibTypes.String : module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Public, Body = new CilBody() };
            owner.Methods.Add(factory);
            factory.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("value")); factory.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var consumer = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(consumer);
            consumer.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); consumer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.String, owner.ToTypeSig()))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(caller);
            var invoke = OpCodes.Callvirt.ToInstruction(factory);
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Br.ToInstruction(invoke));
            caller.Body.Instructions.Add(invoke);
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(consumer)); caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(typedReturn ? 1 : 0, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            var reading = IlVerification.Read(path, []);
            Assert.Empty(reading.Unreadable);
            Assert.Equal(typedReturn ? 0 : 1, reading.Count);
        }
        finally { File.Delete(path); }
    }
}
