using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class OpenGenericConcreteParameterTests
{
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(false, true)]
    public void OpenMethodArgumentDoesNotCertifyOrInvalidateIndependentConcreteSlot(bool known, bool genericInput)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Consumers");
            var target = new MethodDefUser("Use", MethodSig.CreateStaticGeneric(1, module.CorLibTypes.String, module.CorLibTypes.Object, new GenericMVar(0)))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(target); target.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStaticGeneric(1, module.CorLibTypes.String,
                genericInput ? new GenericMVar(0) : known ? module.CorLibTypes.String : module.CorLibTypes.Object, new GenericMVar(0)))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(caller); caller.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "U"));
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            if (genericInput) caller.Body.Instructions.Add(OpCodes.Box.ToInstruction(new TypeSpecUser(new GenericMVar(0, caller))));
            caller.Body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MethodSpecUser(target, new GenericInstMethodSig(new GenericMVar(0, caller)))));
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(known ? 1 : 0, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            var reading = IlVerification.Read(path, []);
            Assert.Empty(reading.Unreadable);
            Assert.Equal(known ? 0 : 1, reading.Count);
        }
        finally { File.Delete(path); }
    }
}
