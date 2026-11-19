using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReflectiveFieldInitializationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReflectionRunsBeforeFieldInitConstructorBeforeAccess(bool write)
    {
        using var module = new ModuleDefUser("Fields");
        var owner = new TypeDefUser("Tests", "Owner", module.CorLibTypes.Object.TypeDefOrRef)
        { Attributes = TypeAttributes.NotPublic | TypeAttributes.BeforeFieldInit };
        module.Types.Add(owner);
        var field = Field("Value");
        var other = Field("Other");
        var count = Field("Count");
        var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
        { Body = new CilBody() };
        owner.Methods.Add(initializer);
        foreach (var instruction in new[] { OpCodes.Ldc_I4.ToInstruction(11), OpCodes.Stsfld.ToInstruction(field),
                     OpCodes.Ldc_I4.ToInstruction(22), OpCodes.Stsfld.ToInstruction(other),
                     OpCodes.Ldsfld.ToInstruction(count), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Add.ToInstruction(),
                     OpCodes.Stsfld.ToInstruction(count), OpCodes.Ret.ToInstruction() }) initializer.Body.Instructions.Add(instruction);
        var info = module.CorLibTypes.GetTypeRef("System.Reflection", "FieldInfo");
        var caller = new MethodDefUser("Access", MethodSig.CreateStatic(module.CorLibTypes.Void, info.ToTypeSig()),
            MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
        var host = new TypeDefUser("Tests", "Host", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(host); host.Methods.Add(caller);
        caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
        caller.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
        if (write)
        {
            caller.Body.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        }
        caller.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, write ? "SetValue" : "GetValue",
            write ? MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object)
                : MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object), info)));
        if (!write) caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
        caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var machine = new StaticMachine(modelTypeInitialization: true);
        machine.State.RegisterModuleMetadata(module);
        Assert.True(machine.State.Heap.TryAllocateObject("System.Reflection.FieldInfo", out var receiver));
        machine.State.Heap.TrySetModelValue(receiver, "Metadata", field);
        for (var round = 0; round < 2; round++)
        {
            var result = machine.Execute(caller, [receiver]);
            Assert.True(result.Succeeded, result.Diagnostic);
            Assert.Equal(write ? 7 : 11, machine.State.ReadStaticField(field).AsInt32());
            Assert.Equal(22, machine.State.ReadStaticField(other).AsInt32());
            Assert.Equal(1, machine.State.ReadStaticField(count).AsInt32());
        }

        FieldDef Field(string name)
        {
            var result = new FieldDefUser(name, new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static);
            owner.Fields.Add(result); return result;
        }
    }
}
