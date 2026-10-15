using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class CommonInterfaceTypingTests
{
    [Theory]
    [InlineData("plain", 1)]
    [InlineData("existing-cast", 1)]
    [InlineData("missing-interface", 0)]
    [InlineData("mixed-consumers", 0)]
    [InlineData("base-implements", 0)]
    public void SharedBaseDoesNotHideProvenConsumerInterface(string variant, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var contract = SyntheticContext.AddType(module, "IWorker");
            contract.Attributes = TypeAttributes.Interface | TypeAttributes.Abstract | TypeAttributes.NotPublic;
            contract.BaseType = null;
            var operation = new MethodDefUser("Run", MethodSig.CreateInstance(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.Abstract };
            contract.Methods.Add(operation);
            var parent = SyntheticContext.AddType(module, "Parent");
            if (variant == "base-implements")
            {
                parent.Interfaces.Add(new InterfaceImplUser(contract));
                var run = new MethodDefUser("Run", MethodSig.CreateInstance(module.CorLibTypes.Void))
                    { Attributes = MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot, Body = new CilBody() };
                parent.Methods.Add(run); run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            var keep = new MethodDefUser("Keep", MethodSig.CreateInstance(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Public, Body = new CilBody() };
            parent.Methods.Add(keep); keep.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            TypeDef Child(string name, bool implements)
            {
                var child = SyntheticContext.AddType(module, name); child.BaseType = parent;
                if (implements)
                {
                    child.Interfaces.Add(new InterfaceImplUser(contract));
                    var run = new MethodDefUser("Run", MethodSig.CreateInstance(module.CorLibTypes.Void))
                        { Attributes = MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot, Body = new CilBody() };
                    child.Methods.Add(run); run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                }
                return child;
            }
            var first = Child("First", true); var second = Child("Second", variant != "missing-interface");
            var owner = SyntheticContext.AddType(module, "Consumers");
            var use = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(use);
            use.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            if (variant != "plain") use.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(parent));
            use.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(operation));
            if (variant == "mixed-consumers")
            {
                use.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                use.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(parent));
                use.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(keep));
            }
            use.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void, first.ToTypeSig(), second.ToTypeSig()))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(caller);
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(use));
            caller.Body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction()); caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(use));
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            var result = IlVerification.Read(path, []);
            Assert.Empty(result.Unreadable);
            Assert.Equal(expected == 1 || variant == "base-implements" ? 0 : 1, result.Count);
        }
        finally { File.Delete(path); }
    }
}
