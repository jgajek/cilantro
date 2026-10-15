using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DefaultDictionaryConstructionTests
{
    [Theory]
    [InlineData("direct", true)]
    [InlineData("escape", true)]
    [InlineData("serialization", true)]
    [InlineData("legacy", true)]
    [InlineData("local", true)]
    [InlineData("field", true)]
    [InlineData("getter", true)]
    [InlineData("comparer", false)]
    [InlineData("foreign", false)]
    [InlineData("unknown-store", false)]
    [InlineData("address", false)]
    public void RequiresAllReceiverSourcesToHaveDefaultConstruction(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var definition = mode == "foreign" ? new TypeRefUser(module, "System.Collections.Generic", "Dictionary`2", new AssemblyRefUser("Foreign"))
                : module.CorLibTypes.GetTypeRef("System.Collections.Generic", "Dictionary`2");
            if (mode == "legacy") definition = new TypeRefUser(module, "System.Collections.Generic", "Dictionary`2",
                new AssemblyRefUser("mscorlib", new Version(2, 0, 0, 0), new PublicKeyToken("b77a5c561934e089")));
            var type = new GenericInstSig(new ClassSig(definition), module.CorLibTypes.String, module.CorLibTypes.String);
            var memberOwner = new TypeSpecUser(type);
            var method = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.Void, type)) { Body = new CilBody() };
            owner.Methods.Add(method);
            var il = method.Body.Instructions;
            if (mode == "comparer") il.Add(OpCodes.Ldnull.ToInstruction());
            il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", mode == "comparer"
                ? MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object)
                : MethodSig.CreateInstance(module.CorLibTypes.Void), memberOwner)));
            if (mode == "escape")
            {
                il.Add(OpCodes.Dup.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetType",
                    MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig()), module.CorLibTypes.Object.TypeDefOrRef)));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            if (mode == "serialization")
            {
                il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "OnDeserialization",
                    MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object), memberOwner)));
            }
            if (mode is "field" or "getter" or "unknown-store")
            {
                var field = new FieldDefUser("Storage", new FieldSig(type), FieldAttributes.Private | FieldAttributes.Static);
                owner.Fields.Add(field); il.Add(OpCodes.Stsfld.ToInstruction(field));
                if (mode == "unknown-store") { il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Stsfld.ToInstruction(field)); }
                if (mode == "getter")
                {
                    var getter = new MethodDefUser("get_Storage", MethodSig.CreateStatic(type), MethodImplAttributes.IL,
                        MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
                    getter.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); getter.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    owner.Methods.Add(getter);
                    var property = new PropertyDefUser("Storage", PropertySig.CreateStatic(type)); property.GetMethods.Add(getter); owner.Properties.Add(property);
                    il.Add(OpCodes.Call.ToInstruction(getter));
                }
                else il.Add(OpCodes.Ldsfld.ToInstruction(field));
            }
            if (mode is "local" or "address")
            {
                var local = new Local(type); method.Body.Variables.Add(local); il.Add(OpCodes.Stloc.ToInstruction(local));
                if (mode == "address") { il.Add(OpCodes.Ldloca.ToInstruction(local)); il.Add(OpCodes.Pop.ToInstruction()); }
                il.Add(OpCodes.Ldloc.ToInstruction(local));
            }
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Count", MethodSig.CreateInstance(module.CorLibTypes.Int32), memberOwner)));
            il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Use");
        var call = method.Body.Instructions.Single(i => i.Operand is IMethod m && m.Name == "get_Count");
        Assert.Equal(expected, DefaultDictionaryConstruction.Receiver(method, call));
        Assert.Equal(expected && mode is not ("escape" or "serialization"), ClosedDictionaryAliases.Analyze(method, call).Closed);
    }
}
