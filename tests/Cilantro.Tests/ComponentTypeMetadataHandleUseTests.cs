using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ComponentTypeMetadataHandleUseTests
{
    [Theory]
    [InlineData("metadata", true)]
    [InlineData("reader", false)]
    [InlineData("method-handle", false)]
    [InlineData("name", false)]
    [InlineData("getter-name", false)]
    [InlineData("type-handle", false)]
    [InlineData("subclass", false)]
    [InlineData("new-slot", false)]
    [InlineData("foreign-base", false)]
    [InlineData("wrong-conversion", false)]
    [InlineData("wrong-property", false)]
    [InlineData("extra-instruction", false)]
    [InlineData("public-helper", false)]
    public void OnlyUnconsumedFrameworkMetadataExcludesPrivateHelper(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var application = SyntheticContext.AddType(module, "Application");
            var helper = new MethodDefUser("Helper", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Static | (mode == "public-helper" ? MethodAttributes.Public : MethodAttributes.Private)) { Body = new CilBody() };
            application.Methods.Add(helper); helper.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var descriptor = SyntheticContext.AddType(module, "Descriptor");
            var system = new AssemblyRefUser(new AssemblyNameInfo(mode == "foreign-base" ? "Untrusted" : "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"));
            descriptor.BaseType = new TypeRefUser(module, "System.ComponentModel", "PropertyDescriptor", system);
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var getter = new MethodDefUser("get_ComponentType", MethodSig.CreateInstance(type.ToTypeSig()), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.SpecialName | (mode == "new-slot" ? MethodAttributes.NewSlot : 0)) { Body = new CilBody() };
            descriptor.Methods.Add(getter);
            descriptor.Properties.Add(new PropertyDefUser("ComponentType", PropertySig.CreateInstance(mode == "wrong-property" ? module.CorLibTypes.Object : type.ToTypeSig())) { GetMethod = getter });
            getter.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(application));
            getter.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, mode == "wrong-conversion" ? "Other" : "GetTypeFromHandle",
                MethodSig.CreateStatic(type.ToTypeSig(), module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()), type)));
            if (mode == "extra-instruction") { getter.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); getter.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); }
            getter.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var reader = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            application.Methods.Add(reader);
            if (mode == "reader") { reader.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); reader.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(getter)); reader.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (mode == "method-handle") { reader.Body.Instructions.Add(OpCodes.Ldftn.ToInstruction(getter)); reader.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (mode is "name" or "getter-name") { reader.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction(mode == "name" ? "ComponentType" : "get_ComponentType")); reader.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (mode == "type-handle") { reader.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(descriptor)); reader.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (mode == "subclass") SyntheticContext.AddType(module, "Derived").BaseType = descriptor;
            reader.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var candidate = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Helper");
        Assert.Equal(expected, new PropertyOnlyTypeHandles(context.Module).IsClosed(candidate));
    }
}
