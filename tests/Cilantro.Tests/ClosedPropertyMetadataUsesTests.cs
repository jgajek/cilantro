using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedPropertyMetadataUsesTests
{
    [Theory]
    [InlineData("get", true)]
    [InlineData("dictionary", true)]
    [InlineData("custom-dictionary", false)]
    [InlineData("set", true)]
    [InlineData("local", true)]
    [InlineData("cast", true)]
    [InlineData("legacy-cast", true)]
    [InlineData("fake-core-cast", false)]
    [InlineData("foreign", false)]
    [InlineData("declaring-type", false)]
    [InlineData("address", false)]
    [InlineData("escape", false)]
    [InlineData("duplicate-escape", false)]
    public void RequiresEveryMetadataUseToEndInPropertyAccess(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var property = module.CorLibTypes.GetTypeRef("System.Reflection", "PropertyInfo");
            var method = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.Void, property.ToTypeSig()))
                { Body = new CilBody() }; owner.Methods.Add(method);
            var il = method.Body.Instructions;
            il.Add(OpCodes.Ldarg_0.ToInstruction());
            if (mode is "dictionary" or "custom-dictionary")
            {
                var saved = new Local(property.ToTypeSig()); method.Body.Variables.Add(saved); il.Add(OpCodes.Stloc.ToInstruction(saved));
                var dictionary = new TypeSpecUser(new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "Dictionary`2")), property.ToTypeSig(), module.CorLibTypes.String));
                if (mode == "custom-dictionary") il.Add(OpCodes.Ldnull.ToInstruction());
                il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", mode == "custom-dictionary"
                    ? MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object)
                    : MethodSig.CreateInstance(module.CorLibTypes.Void), dictionary)));
                il.Add(OpCodes.Ldloc.ToInstruction(saved));
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Item", MethodSig.CreateInstance(module.CorLibTypes.String, property.ToTypeSig()), dictionary)));
                il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction()); return;
            }
            if (mode is "escape" or "duplicate-escape")
            {
                if (mode == "duplicate-escape") il.Add(OpCodes.Dup.ToInstruction());
                il.Add(OpCodes.Pop.ToInstruction());
                if (mode == "escape") { il.Add(OpCodes.Ret.ToInstruction()); return; }
            }
            if (mode is "local" or "address")
            {
                var local = new Local(property.ToTypeSig()); method.Body.Variables.Add(local);
                il.Add(OpCodes.Stloc.ToInstruction(local));
                if (mode == "address") { il.Add(OpCodes.Ldloca.ToInstruction(local)); il.Add(OpCodes.Pop.ToInstruction()); }
                il.Add(OpCodes.Ldloc.ToInstruction(local));
            }
            if (mode == "cast") il.Add(OpCodes.Castclass.ToInstruction(property));
            if (mode is "legacy-cast" or "fake-core-cast")
            {
                var reference = new AssemblyRefUser("mscorlib", new Version(2, 0, 0, 0),
                    new PublicKeyToken(mode == "legacy-cast" ? "b77a5c561934e089" : "0000000000000000"));
                il.Add(OpCodes.Castclass.ToInstruction(new TypeRefUser(module, "System.Reflection", "PropertyInfo", reference)));
            }
            if (mode == "declaring-type")
            {
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_DeclaringType",
                    MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig()), property)));
            }
            else
            {
                var setter = mode == "set";
                il.Add(OpCodes.Ldnull.ToInstruction());
                if (setter) il.Add(OpCodes.Ldnull.ToInstruction());
                il.Add(OpCodes.Ldnull.ToInstruction());
                var sig = setter ? MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Object))
                    : MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Object));
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, setter ? "SetValue" : "GetValue", sig,
                    mode == "foreign" ? new TypeRefUser(module, "System.Reflection", "PropertyInfo", new AssemblyRefUser("Foreign")) : property)));
                if (setter) { il.Add(OpCodes.Ret.ToInstruction()); return; }
            }
            il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Use");
        Assert.Equal(expected, ClosedPropertyMetadataUses.IsClosed(method, method.Body.Instructions[0]));
    }
}
