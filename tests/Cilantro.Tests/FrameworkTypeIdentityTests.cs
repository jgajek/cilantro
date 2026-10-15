using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class FrameworkTypeIdentityTests
{
    [Theory]
    [InlineData("op_Equality", false)]
    [InlineData("op_Inequality", false)]
    [InlineData("foreign", true)]
    [InlineData("wrong-argument", true)]
    [InlineData("instance", true)]
    [InlineData("escape", true)]
    [InlineData("alternate", true)]
    [InlineData("custom-left", false)]
    [InlineData("runtime-left", false)]
    [InlineData("runtime-direct", false)]
    [InlineData("runtime-handle", false)]
    [InlineData("alternate-token", false)]
    public void FrameworkIdentityDoesNotExposeMembers(string shape, bool exposed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var hidden = SyntheticContext.AddType(module, "Hidden");
            var api = SyntheticContext.AddType(module, "Api"); api.Attributes = TypeAttributes.Public;
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            api.Methods.Add(run);
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var conversion = new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(type.ToTypeSig(),
                module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()), type);
            var signature = MethodSig.CreateStatic(module.CorLibTypes.Boolean, type.ToTypeSig(),
                shape == "wrong-argument" ? module.CorLibTypes.Object : type.ToTypeSig());
            if (shape == "instance") signature.HasThis = true;
            var equality = new MemberRefUser(module, shape == "op_Inequality" ? "op_Inequality" : "op_Equality", signature,
                shape == "foreign" ? new TypeRefUser(module, "System", "Type", new AssemblyRefUser("Foreign")) : type);
            var call = OpCodes.Call.ToInstruction(equality);
            var il = run.Body.Instructions;
            var token = OpCodes.Ldtoken.ToInstruction(hidden);
            if (shape == "alternate-token")
            {
                il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Br.ToInstruction(token));
            }
            if (shape == "alternate")
            {
                il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Br.ToInstruction(call));
            }
            if (shape == "instance") il.Add(OpCodes.Ldnull.ToInstruction());
            if (shape == "custom-left") il.Add(OpCodes.Ldarg_0.ToInstruction());
            else if (shape == "runtime-handle")
            {
                il.Add(OpCodes.Ldtoken.ToInstruction(module.CorLibTypes.String.TypeDefOrRef));
                il.Add(OpCodes.Call.ToInstruction(conversion));
            }
            else if (shape is "runtime-left" or "runtime-direct")
            {
                il.Add(OpCodes.Ldarg_0.ToInstruction());
                il.Add((shape == "runtime-direct" ? OpCodes.Call : OpCodes.Callvirt).ToInstruction(new MemberRefUser(module, "GetType", MethodSig.CreateInstance(type.ToTypeSig()), module.CorLibTypes.Object.TypeDefOrRef)));
            }
            else il.Add(OpCodes.Ldnull.ToInstruction());
            il.Add(token);
            il.Add(OpCodes.Call.ToInstruction(conversion));
            if (shape == "escape")
            {
                il.Add(OpCodes.Dup.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(module.Import(typeof(Type).GetMethod("GetMethods", Type.EmptyTypes)!)));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            il.Add(call); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        var hidden = context.Module.GetTypes().Single(t => t.Name == "Hidden");
        Assert.Equal(exposed, ModuleReachability.Compute(context.Module).IsReflectivelyExposed(hidden));
    }
}
