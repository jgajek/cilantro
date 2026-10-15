using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedDelegateClosureTests
{
    [Theory]
    [InlineData("private-type", true)]
    [InlineData("private-field", true)]
    [InlineData("internal-field", true)]
    [InlineData("friend-field", true)]
    [InlineData("friend-reflected", false)]
    [InlineData("friend-wrong-generic", false)]
    [InlineData("public-type", false)]
    [InlineData("reflected", false)]
    [InlineData("wrong-generic", false)]
    public void GenericClosureStorageRequiresPrivateBoundaryAndMatchingArguments(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var api = SyntheticContext.AddType(module, "Api"); api.Attributes = TypeAttributes.Public;
            var owner = SyntheticContext.AddType(module, "Callbacks");
            if (mode.StartsWith("friend-", StringComparison.Ordinal))
            {
                var attribute = new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String), module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "InternalsVisibleToAttribute")));
                attribute.ConstructorArguments.Add(new CAArgument(module.CorLibTypes.String, "Friend"));
                module.Assembly.CustomAttributes.Add(attribute);
            }
            var target = new MethodDefUser("Decode", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(target);
            Emit(target, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Length", MethodSig.CreateInstance(module.CorLibTypes.Int32), module.CorLibTypes.String.TypeDefOrRef)), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
            var holder = new TypeDefUser("", "Holder`1", module.CorLibTypes.Object.TypeDefOrRef)
                { Attributes = (mode is "public-type" or "internal-field" or "friend-field" or "friend-reflected" or "friend-wrong-generic" ? TypeAttributes.NestedPublic : TypeAttributes.NestedPrivate) | TypeAttributes.Sealed };
            api.NestedTypes.Add(holder); holder.GenericParameters.Add(new GenericParamUser(0));
            var action = new ClassSig(module.CorLibTypes.GetTypeRef("System", "Action`1"));
            var openAction = new GenericInstSig(action, new GenericVar(0));
            var field = new FieldDefUser("Callback", new FieldSig(openAction), mode == "private-field" ? FieldAttributes.Private : mode is "internal-field" or "friend-field" or "friend-reflected" or "friend-wrong-generic" ? FieldAttributes.Assembly : FieldAttributes.Public); holder.Fields.Add(field);
            var constructor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, openAction),
                MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() }; holder.Methods.Add(constructor);
            Emit(constructor, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Stfld.ToInstruction(field), OpCodes.Ret.ToInstruction());
            var read = new MethodDefUser("Run", MethodSig.CreateInstance(module.CorLibTypes.Void, new GenericVar(0)), MethodImplAttributes.IL, MethodAttributes.Public) { Body = new CilBody() }; holder.Methods.Add(read);
            Emit(read, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(field), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void, new GenericVar(0)), new TypeSpecUser(openAction))), OpCodes.Ret.ToInstruction());
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() }; api.Methods.Add(entry);
            var concrete = new GenericInstSig(action, module.CorLibTypes.String);
            var closedHolder = new TypeSpecUser(new GenericInstSig(new ClassSig(holder), mode is "wrong-generic" or "friend-wrong-generic" ? module.CorLibTypes.Object : module.CorLibTypes.String));
            Emit(entry, OpCodes.Ldnull.ToInstruction(), OpCodes.Ldftn.ToInstruction(target), OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr), new TypeSpecUser(concrete))), OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", constructor.MethodSig, closedHolder)), OpCodes.Pop.ToInstruction());
            if (mode is "reflected" or "friend-reflected") Emit(entry, OpCodes.Ldtoken.ToInstruction(holder), OpCodes.Pop.ToInstruction());
            Emit(entry, OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Decode");
        var exposed = ModuleReachability.Compute(context.Module).ReflectivelyExposedTypes.ToHashSet();
        var proof = ClosedDelegateParameterTypes.Find(context.Module, new HashSet<MethodDef> { method }, exposed);
        Assert.Equal(expected, proof.ContainsKey(method));
        Assert.Equal(expected ? 1 : 0, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
    }

    private static void Emit(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }
}
