using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class GenericOwnerInliningTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ConstructorOwnerUsesTheCallersGenericArgument(bool methodParameter)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var box = SyntheticContext.AddType(module, "Box`1");
            box.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var constructor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, new SZArraySig(new GenericVar(0))))
            {
                Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                Body = new CilBody()
            };
            constructor.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); box.Methods.Add(constructor);
            var wrapper = SyntheticContext.AddType(module, "Wrapper`1");
            wrapper.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var boxOfT = new GenericInstSig(new ClassSig(box), new GenericVar(0));
            var forwarder = new MethodDefUser("Make", MethodSig.CreateStatic(boxOfT, new SZArraySig(new GenericVar(0))))
                { Attributes = MethodAttributes.Public | MethodAttributes.Static, Body = new CilBody() };
            wrapper.Methods.Add(forwarder);
            forwarder.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            forwarder.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", constructor.MethodSig, new TypeSpecUser(boxOfT))));
            forwarder.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var app = SyntheticContext.AddType(module, "App");
            TypeSig argument = methodParameter ? new GenericMVar(0) : module.CorLibTypes.Int32;
            var caller = new MethodDefUser("Create", MethodSig.CreateStatic(new GenericInstSig(new ClassSig(box), argument), new SZArraySig(argument)))
                { Attributes = MethodAttributes.Public | MethodAttributes.Static, Body = new CilBody() };
            if (methodParameter)
            {
                caller.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "U"));
                caller.MethodSig.GenParamCount = 1;
                caller.MethodSig.Generic = true;
            }
            app.Methods.Add(caller);
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Make", forwarder.MethodSig,
                new TypeSpecUser(new GenericInstSig(new ClassSig(wrapper), argument)))));
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var result = new MethodInliningPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        using var bytes = new MemoryStream(); context.Module.Write(bytes);
        using var reloaded = ModuleDefMD.Load(bytes.ToArray(), new ModuleCreationOptions { TryToLoadPdbFromDisk = false });
        var caller = reloaded.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Create");
        var instruction = Assert.Single(caller.Body.Instructions, i => i.OpCode == OpCodes.Newobj);
        var target = Assert.IsAssignableFrom<IMethod>(instruction.Operand);
        var owner = Assert.IsType<GenericInstSig>(Assert.IsAssignableFrom<TypeSpec>(target.DeclaringType).TypeSig);
        Assert.Equal(methodParameter ? ElementType.MVar : ElementType.I4, Assert.Single(owner.GenericArguments).ElementType);
        // The member signature still belongs to Box<T>, not to the caller.
        Assert.Equal(ElementType.Var, target.MethodSig.Params[0].Next.ElementType);
        Assert.Equal(0, new MethodInliningPass().Run(context).Changes);
    }
}
