using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class GenericBodyArrayTypingTests
{
    [Theory]
    [InlineData(false, false, "none")]
    [InlineData(true, false, "none")]
    [InlineData(false, true, "none")]
    [InlineData(true, true, "none")]
    [InlineData(true, false, "exact")]
    [InlineData(true, false, "unknown")]
    [InlineData(true, false, "wrong")]
    public void GenericTemplateRequiresAgreementWithEveryClosedCall(bool existingCast, bool conflictingCall, string forwarding)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "GenericArray");
            var target = new MethodDefUser("Use", MethodSig.CreateStaticGeneric(1, module.CorLibTypes.Void, module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(target);
            target.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var local = new Local(new SZArraySig(new GenericMVar(0, target)));
            target.Body.Variables.Add(local);
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            if (existingCast) target.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(new TypeSpecUser(new SZArraySig(module.CorLibTypes.Byte))));
            target.Body.Instructions.Add(OpCodes.Stloc.ToInstruction(local));
            target.Body.Instructions.Add(OpCodes.Ldloc.ToInstruction(local));
            target.Body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.Byte)))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(caller);
            foreach (var argument in conflictingCall ? new TypeSig[] { module.CorLibTypes.Byte, module.CorLibTypes.Int32 } : [module.CorLibTypes.Byte])
            {
                caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MethodSpecUser(target, new GenericInstMethodSig(argument))));
            }
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (forwarding != "none")
            {
                var forward = new MethodDefUser("Forward", MethodSig.CreateStaticGeneric(1, module.CorLibTypes.Void, module.CorLibTypes.Object))
                    { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
                owner.Methods.Add(forward);
                forward.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "U"));
                forward.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                if (forwarding != "unknown") forward.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(new TypeSpecUser(new SZArraySig(
                    forwarding == "exact" ? new GenericMVar(0, forward) : module.CorLibTypes.String))));
                forward.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MethodSpecUser(target, new GenericInstMethodSig(new GenericMVar(0, forward)))));
                forward.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
        });
        new ArrayParameterTypingPass().Run(context);
        var target = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Use");
        var cast = Assert.Single(target.Body.Instructions, i => i.OpCode.Code == Code.Castclass);
        var accepted = !conflictingCall && forwarding is "none" or "exact";
        Assert.Equal(accepted, ((ITypeDefOrRef)cast.Operand).ToTypeSig().ContainsGenericParameter);
        Assert.Equal(0, new ArrayParameterTypingPass().Run(context).Changes);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            var result = IlVerification.Read(path, []);
            Assert.Empty(result.Unreadable);
            Assert.Equal(accepted ? 0 : 1, result.Count);
        }
        finally { File.Delete(path); }
    }
}
