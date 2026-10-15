using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedDelegateFrameworkConsumerTests
{
    [Theory]
    [InlineData(false, "valid", 1)]
    [InlineData(true, "valid", 2)]
    [InlineData(false, "foreign", 0)]
    [InlineData(true, "foreign", 0)]
    [InlineData(false, "wrong-key", 0)]
    [InlineData(true, "wrong-element", 0)]
    [InlineData(false, "wrong-return", 0)]
    [InlineData(true, "wrong-return", 0)]
    [InlineData(false, "unknown-name", 0)]
    [InlineData(true, "unknown-name", 0)]
    public void OnlyExactFrameworkConsumerContractsProveTypes(bool sort, string mode, int changes)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Callbacks");
            var target = new MethodDefUser("Callback", sort ? MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Object, module.CorLibTypes.Object)
                : MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Object), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(target);
            Emit(target, OpCodes.Ldarg_0.ToInstruction());
            if (sort)
            {
                var length = new MemberRefUser(module, "get_Length", MethodSig.CreateInstance(module.CorLibTypes.Int32), module.CorLibTypes.String.TypeDefOrRef);
                Emit(target, OpCodes.Callvirt.ToInstruction(length), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Callvirt.ToInstruction(length), OpCodes.Sub.ToInstruction());
            }
            Emit(target, OpCodes.Ret.ToInstruction());
            var delegateType = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System", sort ? "Comparison`1" : "Func`2")),
                sort ? [module.CorLibTypes.String] : [module.CorLibTypes.String, module.CorLibTypes.String]);
            var receiverType = new GenericInstSig(new ClassSig(new TypeRefUser(module,
                sort ? "System.Collections.Generic" : "System.Collections.Concurrent", sort ? "List`1" : "ConcurrentDictionary`2",
                mode == "foreign" ? new AssemblyRefUser("Foreign", new Version(1, 0)) : module.CorLibTypes.AssemblyRef)),
                sort ? [mode == "wrong-element" ? module.CorLibTypes.Object : module.CorLibTypes.String] : [module.CorLibTypes.String, module.CorLibTypes.String]);
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void, receiverType), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(entry);
            Emit(entry, OpCodes.Ldarg_0.ToInstruction());
            if (!sort) Emit(entry, OpCodes.Ldstr.ToInstruction("key"));
            Emit(entry, OpCodes.Ldnull.ToInstruction(), OpCodes.Ldftn.ToInstruction(target), OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr), new TypeSpecUser(delegateType))));
            var returns = mode == "wrong-return" ? module.CorLibTypes.Object : sort ? module.CorLibTypes.Void : module.CorLibTypes.String;
            var signature = sort ? MethodSig.CreateInstance(returns, delegateType) : MethodSig.CreateInstance(returns, mode == "wrong-key" ? module.CorLibTypes.Object : module.CorLibTypes.String, delegateType);
            Emit(entry, OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, mode == "unknown-name" ? "StoreForLater" : sort ? "Sort" : "GetOrAdd", signature, new TypeSpecUser(receiverType))));
            if (returns.ElementType != ElementType.Void) Emit(entry, OpCodes.Pop.ToInstruction());
            Emit(entry, OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(changes, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
    }

    private static void Emit(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }
}
