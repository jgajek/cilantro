using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReferenceReceiverTypingTests
{
    [Theory]
    [InlineData("call", false, false, true)]
    [InlineData("field-read", false, false, true)]
    [InlineData("field-write", false, false, true)]
    [InlineData("call", true, false, true)]
    [InlineData("call", false, true, false)]
    [InlineData("field-read", false, true, false)]
    [InlineData("field-write", false, true, false)]
    public void UsesClosedCallerEvidenceForReceiverOnlyConsumers(string kind, bool constructed, bool unknown, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var value = SyntheticContext.AddType(module, "Value");
            var field = new FieldDefUser("Number", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public);
            value.Fields.Add(field);
            var operation = new MethodDefUser("Operation", MethodSig.CreateInstance(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Public, Body = new CilBody() };
            value.Methods.Add(operation); operation.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var constructor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            value.Methods.Add(constructor);
            constructor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            constructor.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module,".ctor",MethodSig.CreateInstance(module.CorLibTypes.Void),module.CorLibTypes.Object.TypeDefOrRef)));
            constructor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var owner = SyntheticContext.AddType(module, "Consumer");
            var use = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object))
            { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(use);
            use.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            if (kind == "call") use.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(operation));
            else if (kind == "field-read") { use.Body.Instructions.Add(OpCodes.Ldfld.ToInstruction(field)); use.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            else { use.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); use.Body.Instructions.Add(OpCodes.Stfld.ToInstruction(field)); }
            use.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void, unknown ? module.CorLibTypes.Object : value.ToTypeSig()))
            { Attributes = MethodAttributes.Static | MethodAttributes.Private, Body = new CilBody() };
            owner.Methods.Add(caller);
            caller.Body.Instructions.Add(constructed ? OpCodes.Newobj.ToInstruction(constructor) : OpCodes.Ldarg_0.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(use)); caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid()+".dll");
        try
        {
            context.Module.Write(path);
            Assert.Equal(1, IlVerification.Read(path, []).Count);
            var result = new ReferenceParameterTypingPass().Run(context);
            Assert.Equal(PassStatus.Success, result.Status);
            Assert.Equal(expected ? 1 : 0, result.Changes);
            Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
            context.Module.Write(path);
            Assert.Equal(expected ? 0 : 1, IlVerification.Read(path, []).Count);
        }
        finally { File.Delete(path); }
    }
}
