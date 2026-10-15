using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedDelegateParameterTypesTests
{
    [Theory]
    [InlineData("field", true)]
    [InlineData("local", true)]
    [InlineData("parameter", true)]
    [InlineData("generic", true)]
    [InlineData("wrong-generic", false)]
    [InlineData("escape", false)]
    [InlineData("address", false)]
    [InlineData("reflection", false)]
    [InlineData("public", false)]
    [InlineData("unknown-call", false)]
    [InlineData("direct-call", false)]
    [InlineData("foreign", false)]
    [InlineData("loose-binding", false)]
    [InlineData("bad-invoke", false)]
    [InlineData("stack-edge", false)]
    public void OnlyClosedInvocationPathsCertifyCallbackInputs(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Callbacks");
            if (mode == "public") owner.Attributes = TypeAttributes.Public;
            var target = Add(owner, "Decode", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object));
            var length = new MemberRefUser(module, "get_Length", MethodSig.CreateInstance(module.CorLibTypes.Int32), module.CorLibTypes.String.TypeDefOrRef);
            Emit(target, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Callvirt.ToInstruction(length), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
            var action = new TypeRefUser(module, "System", "Action`1", mode == "foreign" ? new AssemblyRefUser("PretendCore", new Version(1, 0)) : module.CorLibTypes.AssemblyRef);
            var closed = new GenericInstSig(new ClassSig(action), module.CorLibTypes.String);
            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr), new TypeSpecUser(closed));
            var invoke = new MemberRefUser(module, "Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void, mode == "bad-invoke" ? module.CorLibTypes.Object : new GenericVar(0)), new TypeSpecUser(closed));
            var api = SyntheticContext.AddType(module, "Api"); api.Attributes = TypeAttributes.Public;
            var entry = Add(api, "Entry", MethodSig.CreateStatic(module.CorLibTypes.Void));
            entry.Attributes = MethodAttributes.Public | MethodAttributes.Static;
            Emit(entry, OpCodes.Ldnull.ToInstruction(), OpCodes.Ldftn.ToInstruction(target), OpCodes.Newobj.ToInstruction(ctor));
            if (mode == "stack-edge")
            {
                var discard = OpCodes.Pop.ToInstruction();
                Emit(entry, OpCodes.Br.ToInstruction(discard), discard);
            }
            else if (mode == "local")
            {
                var local = new Local(closed); entry.Body.Variables.Add(local);
                var read = OpCodes.Ldloc.ToInstruction(local);
                Emit(entry, OpCodes.Stloc.ToInstruction(local), OpCodes.Br.ToInstruction(read), read,
                    OpCodes.Ldstr.ToInstruction("value"), OpCodes.Callvirt.ToInstruction(invoke));
            }
            else if (mode is "parameter" or "generic" or "wrong-generic" or "unknown-call")
            {
                var parameterType = mode is "generic" or "wrong-generic" ? new GenericInstSig(new ClassSig(action), new GenericMVar(0)) : closed;
                var helper = Add(owner, "Use", MethodSig.CreateStatic(module.CorLibTypes.Void, parameterType));
                if (mode is "generic" or "wrong-generic") { helper.GenericParameters.Add(new GenericParamUser(0)); helper.MethodSig.GenParamCount = 1; helper.MethodSig.Generic = true; }
                var member = mode is "generic" or "wrong-generic" ? new MemberRefUser(module, "Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void, new GenericVar(0)), new TypeSpecUser(parameterType)) : invoke;
                if (mode == "unknown-call")
                {
                    var inspect = new MemberRefUser(module, "Inspect", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object), new TypeRefUser(module, "External", "Api", module.CorLibTypes.AssemblyRef));
                    Emit(helper, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(inspect), OpCodes.Ret.ToInstruction());
                }
                else if (mode is "generic" or "wrong-generic")
                {
                    var value = new Local(new GenericMVar(0)); helper.Body.Variables.Add(value); helper.Body.InitLocals = true;
                    Emit(helper, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldloc.ToInstruction(value), OpCodes.Callvirt.ToInstruction(member), OpCodes.Ret.ToInstruction());
                }
                else Emit(helper, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldstr.ToInstruction("value"), OpCodes.Callvirt.ToInstruction(member), OpCodes.Ret.ToInstruction());
                IMethod call = mode is "generic" or "wrong-generic" ? new MethodSpecUser(helper, new GenericInstMethodSig(mode == "wrong-generic" ? module.CorLibTypes.Object : module.CorLibTypes.String)) : helper;
                Emit(entry, OpCodes.Call.ToInstruction(call));
            }
            else
            {
                var field = new FieldDefUser("Callback", new FieldSig(closed), FieldAttributes.Static | (mode == "public" ? FieldAttributes.Public : FieldAttributes.Private)); owner.Fields.Add(field);
                Emit(entry, OpCodes.Stsfld.ToInstruction(field));
                var reader = Add(owner, "Read", MethodSig.CreateStatic(mode == "escape" ? closed : module.CorLibTypes.Void));
                if (mode == "address") Emit(reader, OpCodes.Ldsflda.ToInstruction(field), OpCodes.Pop.ToInstruction());
                else if (mode == "escape") Emit(reader, OpCodes.Ldsfld.ToInstruction(field));
                else Emit(reader, OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ldstr.ToInstruction("value"), OpCodes.Callvirt.ToInstruction(invoke));
                Emit(reader, OpCodes.Ret.ToInstruction());
                if (mode == "reflection") Emit(entry, OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Pop.ToInstruction());
            }
            if (mode == "direct-call") Emit(entry, OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(target));
            if (mode == "loose-binding")
            {
                var loose = new TypeSpecUser(new GenericInstSig(new ClassSig(action), module.CorLibTypes.Object));
                Emit(entry, OpCodes.Ldnull.ToInstruction(), OpCodes.Ldftn.ToInstruction(target), OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", ctor.MethodSig, loose)), OpCodes.Pop.ToInstruction());
            }
            Emit(entry, OpCodes.Ret.ToInstruction());
        });
        var target = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Decode");
        var exposed = ModuleReachability.Compute(context.Module).ReflectivelyExposedTypes.ToHashSet();
        var proof = ClosedDelegateParameterTypes.Find(context.Module, new HashSet<MethodDef> { target }, exposed);
        Assert.Equal(expected, proof.ContainsKey(target));
        var result = new ReferenceParameterTypingPass().Run(context);
        Assert.Equal(expected ? 1 : 0, result.Changes);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Equal(expected, target.Body.Instructions.Any(i => i.OpCode.Code == Code.Castclass));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void LocalDelegateConstructionMustBeRuntimeImplemented(bool runtime)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var target = Add(owner, "Callback", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object));
            Emit(target, OpCodes.Ret.ToInstruction());
            var type = new TypeDefUser("Synthetic", "CallbackDelegate", module.CorLibTypes.GetTypeRef("System", "MulticastDelegate"))
                { Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed };
            module.Types.Add(type);
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                runtime ? MethodImplAttributes.Runtime : MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
            if (!runtime) { ctor.Body = new CilBody(); Emit(ctor, OpCodes.Ret.ToInstruction()); }
            type.Methods.Add(ctor);
            type.Methods.Add(new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                MethodImplAttributes.Runtime, MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot));
            var entry = Add(owner, "Create", MethodSig.CreateStatic(module.CorLibTypes.Void));
            Emit(entry, OpCodes.Ldnull.ToInstruction(), OpCodes.Ldftn.ToInstruction(target), OpCodes.Newobj.ToInstruction(ctor), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Callback");
        var proof = ClosedDelegateParameterTypes.Find(context.Module, new HashSet<MethodDef> { method }, new HashSet<TypeDef>());
        Assert.Equal(runtime, proof.ContainsKey(method));
    }
    private static MethodDefUser Add(TypeDef owner, string name, MethodSig signature)
    {
        var method = new MethodDefUser(name, signature, MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static)
            { Body = new CilBody() };
        owner.Methods.Add(method);
        return method;
    }

    private static void Emit(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }
}
