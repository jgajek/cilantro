using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

public sealed class TypeRestorationPassTests
{
    [Fact]
    public void PromotesObjectFieldWhenEveryWriterAgrees()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var payload = SyntheticContext.AddType(module, "Payload");
            AddDefaultConstructor(module, payload);
            var host = SyntheticContext.AddType(module, "Host");
            var field = new FieldDefUser(
                "Value",
                new FieldSig(module.CorLibTypes.Object),
                FieldAttributes.Private);
            host.Fields.Add(field);
            AddWriter(module, host, "StoreOnce", field, payload);
            AddWriter(module, host, "StoreTwice", field, payload);
        });

        var result = new TypeRestorationPass().Run(context);
        var field = context.Module.GetTypes()
            .SelectMany(type => type.Fields)
            .Single(item => item.Name == "Value");

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.Equal("Synthetic.Payload", field.FieldSig.Type.FullName);
    }

    [Fact]
    public void LeavesFieldUntouchedWhenWritersDisagree()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var first = SyntheticContext.AddType(module, "First");
            AddDefaultConstructor(module, first);
            var second = SyntheticContext.AddType(module, "Second");
            AddDefaultConstructor(module, second);
            var host = SyntheticContext.AddType(module, "Host");
            var field = new FieldDefUser(
                "Value",
                new FieldSig(module.CorLibTypes.Object),
                FieldAttributes.Private);
            host.Fields.Add(field);
            AddWriter(module, host, "StoreFirst", field, first);
            AddWriter(module, host, "StoreSecond", field, second);
        });

        var result = new TypeRestorationPass().Run(context);
        var field = context.Module.GetTypes()
            .SelectMany(type => type.Fields)
            .Single(item => item.Name == "Value");

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Equal("System.Object", field.FieldSig.Type.FullName);
    }

    [Fact]
    public void LeavesPublicFieldUntouched()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var payload = SyntheticContext.AddType(module, "Payload");
            AddDefaultConstructor(module, payload);
            var host = SyntheticContext.AddType(module, "Host");
            var field = new FieldDefUser(
                "Value",
                new FieldSig(module.CorLibTypes.Object),
                FieldAttributes.Public);
            host.Fields.Add(field);
            AddWriter(module, host, "Store", field, payload);
        });

        var result = new TypeRestorationPass().Run(context);
        var field = context.Module.GetTypes()
            .SelectMany(type => type.Fields)
            .Single(item => item.Name == "Value");

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Equal("System.Object", field.FieldSig.Type.FullName);
    }

    private static void AddDefaultConstructor(ModuleDef module, TypeDef type)
    {
        var constructor = new MethodDefUser(
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName,
            Body = new CilBody()
        };
        constructor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(constructor);
    }

    private static void AddWriter(
        ModuleDef module, TypeDef host, string name, FieldDef field, TypeDef produced)
    {
        var constructor = produced.FindDefaultConstructor();
        var writer = new MethodDefUser(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.Void, host.ToTypeSig()))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        writer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        writer.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, constructor));
        writer.Body.Instructions.Add(Instruction.Create(OpCodes.Stfld, field));
        writer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        host.Methods.Add(writer);
    }
}
