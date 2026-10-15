using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class IndirectReferenceTypingTests
{
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void IndirectReadRequiresAKnownTypedManagedAddress(bool typed, bool incomingAcrossBranch)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Reader");
            var consumer = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(consumer);
            consumer.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.String,
                new ByRefSig(typed ? module.CorLibTypes.String : module.CorLibTypes.Object)))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(caller);
            var read = OpCodes.Ldind_Ref.ToInstruction();
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            if (incomingAcrossBranch) caller.Body.Instructions.Add(OpCodes.Br.ToInstruction(read));
            caller.Body.Instructions.Add(read);
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(consumer));
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var repaired = typed;
        Assert.Equal(repaired ? 1 : 0, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            var result = IlVerification.Read(path, []);
            Assert.Empty(result.Unreadable);
            Assert.Equal(repaired ? 0 : 1, result.Count);
        }
        finally { File.Delete(path); }
    }
}
