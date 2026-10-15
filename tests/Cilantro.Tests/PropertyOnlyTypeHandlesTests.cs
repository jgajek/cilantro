using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class PropertyOnlyTypeHandlesTests
{
    [Theory]
    [InlineData("properties", true)]
    [InlineData("methods", false)]
    [InlineData("foreign", false)]
    [InlineData("escape", false)]
    [InlineData("accessor", false)]
    [InlineData("public", false)]
    [InlineData("alternate-entry", false)]
    public void PermitsOnlyClosedPropertyHandlesForPrivateNonAccessors(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var candidate = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Static | (mode == "public" ? MethodAttributes.Public : MethodAttributes.Private)) { Body = new CilBody() };
            owner.Methods.Add(candidate); candidate.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (mode == "accessor") { var p = new PropertyDefUser("P", PropertySig.CreateStatic(module.CorLibTypes.Void)); p.GetMethods.Add(candidate); owner.Properties.Add(p); }
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(run);
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var property = module.CorLibTypes.GetTypeRef("System.Reflection", "PropertyInfo");
            var lookup = OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, mode == "methods" ? "GetMethods" : "GetProperties",
                MethodSig.CreateInstance(new SZArraySig(property.ToTypeSig())), type));
            var il = run.Body.Instructions;
            if (mode == "alternate-entry") { il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Br.ToInstruction(lookup)); }
            il.Add(OpCodes.Ldtoken.ToInstruction(owner));
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(type.ToTypeSig(), module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()),
                mode == "foreign" ? new TypeRefUser(module, "System", "Type", new AssemblyRefUser("Foreign")) : type)));
            il.Add(lookup);
            if (mode == "escape") il.Add(OpCodes.Pop.ToInstruction());
            else
            {
                il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ldelem_Ref.ToInstruction());
                il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetValue", MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Object)), property)));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            il.Add(OpCodes.Ret.ToInstruction());
        });
        var candidate = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Target");
        Assert.Equal(expected, new PropertyOnlyTypeHandles(context.Module).IsClosed(candidate));
    }
}
