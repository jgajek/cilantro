using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorDelegateFallbackTests
{
    [Theory]
    [InlineData("unused", true, true)]
    [InlineData("called", true, false)]
    [InlineData("handle", true, false)]
    [InlineData("public", true, false)]
    [InlineData("no-proof", false, false)]
    [InlineData("foreign", false, false)]
    [InlineData("other-api", false, false)]
    [InlineData("wrong-argument", false, false)]
    [InlineData("extra-call", false, false)]
    public void ExactBridgeStillRequiresOwnershipAndUnreachability(string scenario, bool recognized, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            TypeRef T(string space, string name) => new TypeRefUser(module, space, name, module.CorLibTypes.AssemblyRef);
            var type = T("System", "Type"); var pointer = T("System", "IntPtr"); var @delegate = T("System", "Delegate");
            var marshal = T("System.Runtime.InteropServices", "Marshal");
            if (scenario == "foreign") marshal.ResolutionScope = new AssemblyRefUser("Foreign");
            var owner = SyntheticContext.AddType(module, "Owner");
            if (scenario == "public") owner.Attributes = TypeAttributes.Public;
            var bridge = Add(owner, "Bridge", MethodSig.CreateStatic(@delegate.ToTypeSig(), new ValueTypeSig(pointer), type.ToTypeSig()));
            if (scenario == "public") bridge.Attributes = MethodAttributes.Static | MethodAttributes.Public;
            var il = bridge.Body.Instructions;
            var getType = new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(type.ToTypeSig(), new ValueTypeSig(T("System", "RuntimeTypeHandle"))), type);
            var getMethod = new MemberRefUser(module, "GetMethod", MethodSig.CreateInstance(T("System.Reflection", "MethodInfo").ToTypeSig(), module.CorLibTypes.String, new SZArraySig(type.ToTypeSig())), type);
            var invoke = new MemberRefUser(module, "Invoke", MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Object)), T("System.Reflection", "MethodBase"));
            void Emit(params Instruction[] instructions) { foreach (var i in instructions) il.Add(i); }
            Emit(OpCodes.Ldtoken.ToInstruction(marshal), OpCodes.Call.ToInstruction(getType),
                OpCodes.Ldstr.ToInstruction(scenario == "other-api" ? "GetFunctionPointerForDelegate" : "GetDelegateForFunctionPointer"),
                OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Newarr.ToInstruction(type),
                OpCodes.Dup.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldtoken.ToInstruction(pointer), OpCodes.Call.ToInstruction(getType), OpCodes.Stelem_Ref.ToInstruction(),
                OpCodes.Dup.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ldtoken.ToInstruction(type), OpCodes.Call.ToInstruction(getType), OpCodes.Stelem_Ref.ToInstruction(),
                OpCodes.Call.ToInstruction(getMethod), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef),
                OpCodes.Dup.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), (scenario == "wrong-argument" ? OpCodes.Ldarg_1 : OpCodes.Ldarg_0).ToInstruction(), OpCodes.Box.ToInstruction(pointer), OpCodes.Stelem_Ref.ToInstruction(),
                OpCodes.Dup.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Stelem_Ref.ToInstruction(),
                OpCodes.Callvirt.ToInstruction(invoke), OpCodes.Castclass.ToInstruction(@delegate), OpCodes.Ret.ToInstruction());
            var setup = Add(owner, "Setup", MethodSig.CreateStatic(module.CorLibTypes.Void)); setup.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var gate = Add(owner, "Gate", MethodSig.CreateStatic(module.CorLibTypes.Void)); gate.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (scenario == "extra-call") il.Insert(0, OpCodes.Call.ToInstruction(gate));
            var entry = Add(module.GlobalType, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void));
            entry.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
            if (scenario == "called")
            {
                foreach (var i in new[] { OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Conv_I.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(bridge), OpCodes.Pop.ToInstruction() }) entry.Body.Instructions.Add(i);
            }
            if (scenario == "handle") { entry.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(bridge)); entry.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        if (scenario != "no-proof") context.SetFact("antitamper.memoryLoadEntryPoint", methods.Single(m => m.Name == "Gate").MDToken.Raw);
        var helpers = ReactorRuntimeFallbacks.Find(context, methods.Single(m => m.Name == "Setup")).ToArray();
        var bridge = methods.Single(m => m.Name == "Bridge");
        Assert.Equal(recognized, helpers.Contains(bridge));
        RecoveryOrphans.Declare(context, helpers); context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(!removed, context.Module.GetTypes().SelectMany(t => t.Methods).Contains(bridge));
    }

    private static MethodDefUser Add(TypeDef owner, string name, MethodSig signature)
    {
        var method = new MethodDefUser(name, signature, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
        owner.Methods.Add(method); return method;
    }
}
