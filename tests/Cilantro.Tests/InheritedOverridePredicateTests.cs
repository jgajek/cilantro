using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace Cilantro.Tests;
public sealed class InheritedOverridePredicateTests
{
    [Theory]
    [InlineData("inherited", true)]
    [InlineData("name-branch", true)]
    [InlineData("name-accepts", false)]
    [InlineData("loop", false)]
    [InlineData("inverted", false)]
    [InlineData("side-effect", false)]
    [InlineData("foreign", false)]
    [InlineData("other-field", false)]
    public void RequiresFalseForKnownDeclaringType(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Closure");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var member = module.CorLibTypes.GetTypeRef("System.Reflection", "MemberInfo");
            var info = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo");
            var field = new FieldDefUser("baseType", new FieldSig(type.ToTypeSig()), FieldAttributes.Public); owner.Fields.Add(field);
            var other = new FieldDefUser("other", new FieldSig(type.ToTypeSig()), FieldAttributes.Public); owner.Fields.Add(other);
            var method = new MethodDefUser("Predicate", MethodSig.CreateInstance(module.CorLibTypes.Boolean, info.ToTypeSig()),
                MethodImplAttributes.IL, MethodAttributes.Public) { Body = new CilBody() }; owner.Methods.Add(method);
            var il = method.Body.Instructions;
            if (mode == "side-effect") { il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Stfld.ToInstruction(field)); }
            il.Add(OpCodes.Ldarg_1.ToInstruction());
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_DeclaringType", MethodSig.CreateInstance(type.ToTypeSig()), member)));
            il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Ldfld.ToInstruction(mode == "other-field" ? other : field));
            var declaring = mode == "foreign" ? new TypeRefUser(module, "System", "Type", new AssemblyRefUser("Foreign")) : type;
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, mode == "inverted" ? "op_Equality" : "op_Inequality",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean, type.ToTypeSig(), type.ToTypeSig()), declaring)));
            il.Add(OpCodes.Ret.ToInstruction());
            if (mode is "name-branch" or "name-accepts")
            {
                var name = new FieldDefUser("name", new FieldSig(module.CorLibTypes.String), FieldAttributes.Public); owner.Fields.Add(name);
                var fallback = mode == "name-accepts" ? OpCodes.Ldc_I4_1.ToInstruction() : OpCodes.Ldc_I4_0.ToInstruction();
                var prefix = new[] {
                    OpCodes.Ldarg_1.ToInstruction(),
                    OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Name", MethodSig.CreateInstance(module.CorLibTypes.String), member)),
                    OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(name),
                    OpCodes.Call.ToInstruction(new MemberRefUser(module, "op_Equality", MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                        module.CorLibTypes.String, module.CorLibTypes.String), module.CorLibTypes.String.TypeDefOrRef)),
                    OpCodes.Brfalse.ToInstruction(fallback)
                };
                for (var i = prefix.Length - 1; i >= 0; i--) il.Insert(0, prefix[i]);
                il.Add(fallback); il.Add(OpCodes.Ret.ToInstruction());
            }
            if (mode == "loop") { var loop = OpCodes.Nop.ToInstruction(); il.Insert(0, loop); il.Insert(1, OpCodes.Br.ToInstruction(loop)); }
        });
        var type = context.Module.GetTypes().Single(t => t.Name == "Closure");
        Assert.Equal(expected, InheritedOverridePredicate.RefusesInherited(type.Methods.Single(), type.Fields.Single(f => f.Name == "baseType")));
        if (mode is "name-branch" or "name-accepts")
            Assert.Equal(mode == "name-branch", InheritedOverridePredicate.RefusesOtherNames(type.Methods.Single(),
                type.Fields.Single(f => f.Name == "baseType"), type.Fields.Single(f => f.Name == "name")));
    }
}
