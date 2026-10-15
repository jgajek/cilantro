using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class TypeIdentityHandleUseTests
{
    [Theory]
    [InlineData("mscorlib")]
    [InlineData("System.Runtime")]
    [InlineData("System.Private.CoreLib")]
    public void UnsignedFrameworkNamesCannotCertifyTypeIdentity(string assemblyName)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var fake = new TypeRefUser(module, "System", "Type", new AssemblyRefUser(assemblyName));
            var handle = module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle");
            var method = new MethodDefUser("Compare", MethodSig.CreateStatic(module.CorLibTypes.Boolean, fake.ToTypeSig()),
                MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(method);
            method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(owner));
            method.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module,"GetTypeFromHandle",
                MethodSig.CreateStatic(fake.ToTypeSig(),handle.ToTypeSig()),fake)));
            method.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module,"op_Equality",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean,fake.ToTypeSig(),fake.ToTypeSig()),fake)));
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().Single(t => t.Name == "Owner").Methods.Single();
        Assert.False(TypeIdentityHandleUse.IsClosed(method, 1));
    }

    [Theory]
    [InlineData("op_Equality", false, false)]
    [InlineData("op_Inequality", false, false)]
    [InlineData("Equals", false, true)]
    [InlineData("op_Equality", true, true)]
    public void RuntimeRightOperandDoesNotExposeMembersThroughEquality(string name, bool foreign, bool exposed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var hidden = SyntheticContext.AddType(module, "Hidden");
            var api = SyntheticContext.AddType(module, "Api");
            api.Attributes = TypeAttributes.Public;
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Boolean, type.ToTypeSig()),
                MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            api.Methods.Add(run);
            var il = run.Body.Instructions;
            il.Add(OpCodes.Ldarg_0.ToInstruction());
            il.Add(OpCodes.Ldtoken.ToInstruction(hidden));
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(type.ToTypeSig(), module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()), type)));
            var owner = foreign ? new TypeRefUser(module, "System", "Type", new AssemblyRefUser("Foreign")) : type;
            var signature = name == "Equals" ? MethodSig.CreateInstance(module.CorLibTypes.Boolean, type.ToTypeSig())
                : MethodSig.CreateStatic(module.CorLibTypes.Boolean, type.ToTypeSig(), type.ToTypeSig());
            il.Add((name == "Equals" ? OpCodes.Callvirt : OpCodes.Call).ToInstruction(new MemberRefUser(module, name, signature, owner)));
            il.Add(OpCodes.Ret.ToInstruction());
        });
        var target = context.Module.GetTypes().Single(t => t.Name == "Hidden");
        Assert.Equal(exposed, ModuleReachability.Compute(context.Module).IsReflectivelyExposed(target));
    }
    [Theory]
    [InlineData("static", false)]
    [InlineData("instance", false)]
    [InlineData("inspection", true)]
    [InlineData("address", true)]
    [InlineData("assignment", true)]
    [InlineData("foreign", true)]
    [InlineData("alternate-entry", true)]
    public void OnlyIdentityComparisonAvoidsReflectiveExposure(string scenario, bool exposed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var hidden = SyntheticContext.AddType(module, "Hidden");
            var owner = SyntheticContext.AddType(module, "Comparer");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var instance = scenario == "instance";
            var compare = new MethodDefUser("Compare", instance
                ? MethodSig.CreateInstance(module.CorLibTypes.Boolean, module.CorLibTypes.Object, type.ToTypeSig())
                : MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.Object, type.ToTypeSig()),
                MethodImplAttributes.IL, MethodAttributes.Private | (instance ? 0 : MethodAttributes.Static)) { Body = new CilBody() };
            owner.Methods.Add(compare);
            var parameter = compare.Parameters[^1];
            var body = compare.Body.Instructions;
            if (scenario == "inspection")
            {
                body.Add(OpCodes.Ldarg.ToInstruction(parameter));
                body.Add(OpCodes.Callvirt.ToInstruction(module.Import(typeof(Type).GetMethod("GetMethods", Type.EmptyTypes)!)));
                body.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario == "address") { body.Add(OpCodes.Ldarga.ToInstruction(parameter)); body.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "assignment") { body.Add(OpCodes.Ldnull.ToInstruction()); body.Add(OpCodes.Starg.ToInstruction(parameter)); }
            body.Add(OpCodes.Ldarg.ToInstruction(compare.Parameters[instance ? 1 : 0]));
            body.Add(OpCodes.Callvirt.ToInstruction(module.Import(typeof(object).GetMethod("GetType")!)));
            body.Add(OpCodes.Ldarg.ToInstruction(parameter));
            body.Add(OpCodes.Ceq.ToInstruction());
            body.Add(OpCodes.Ret.ToInstruction());
            var api = SyntheticContext.AddType(module, "Api"); api.Attributes = TypeAttributes.Public;
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() }; api.Methods.Add(run);
            var call = OpCodes.Call.ToInstruction(compare);
            var il = run.Body.Instructions;
            if (scenario == "alternate-entry")
            {
                il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Br.ToInstruction(call));
            }
            if (instance) il.Add(OpCodes.Ldnull.ToInstruction());
            il.Add(OpCodes.Ldnull.ToInstruction());
            il.Add(OpCodes.Ldtoken.ToInstruction(hidden));
            var conversion = new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(type.ToTypeSig(),
                module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()),
                scenario == "foreign" ? new TypeRefUser(module, "System", "Type", new AssemblyRefUser("Foreign")) : type);
            il.Add(OpCodes.Call.ToInstruction(conversion)); il.Add(call); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        var target = context.Module.GetTypes().Single(t => t.Name == "Hidden");
        Assert.Equal(exposed, ModuleReachability.Compute(context.Module).IsReflectivelyExposed(target));
    }
}
