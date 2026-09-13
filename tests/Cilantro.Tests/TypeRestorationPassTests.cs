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
            host.Attributes = TypeAttributes.Public | TypeAttributes.Class;
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

    /// <summary>
    /// A public field of a type nothing outside the assembly can name is promoted.
    /// </summary>
    /// <remarks>
    /// Reactor puts the locals of a rewritten method into a nested class and declares every one of
    /// them public, so reading the field's own access alone declined most of what this pass exists
    /// for. On one payload it left a field written once from <c>Path::Combine</c> declared
    /// <c>object</c>, and the two reads of it then passed an <c>object</c> to
    /// <c>File::WriteAllBytes</c> and <c>Assembly::LoadFile</c>, which ILVerify reports and a reader
    /// has to work out for themselves.
    /// </remarks>
    [Fact]
    public void PromotesPublicFieldOfATypeNothingOutsideCanName()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var payload = SyntheticContext.AddType(module, "Payload");
            AddDefaultConstructor(module, payload);
            var host = SyntheticContext.AddType(module, "Host");
            var locals = Nested(module, host, "Locals");
            var field = new FieldDefUser(
                "Value",
                new FieldSig(module.CorLibTypes.Object),
                FieldAttributes.Public);
            locals.Fields.Add(field);
            AddWriter(module, host, "Store", field, payload, on: locals);
        });

        var result = new TypeRestorationPass().Run(context);
        var field = context.Module.GetTypes()
            .SelectMany(type => type.Fields)
            .Single(item => item.Name == "Value");

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.Equal("Synthetic.Payload", field.FieldSig.Type.FullName);
    }

    /// <summary>
    /// Where the assembly hands its internals to a friend, the same field is left alone.
    /// </summary>
    /// <remarks>
    /// A friend assembly can name the internal types of this one, so their public members really are
    /// a surface something outside binds to, and the broader reading is the right one there.
    /// </remarks>
    [Fact]
    public void LeavesThatFieldAloneWhereTheAssemblyHasAFriend()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var payload = SyntheticContext.AddType(module, "Payload");
            AddDefaultConstructor(module, payload);
            var host = SyntheticContext.AddType(module, "Host");
            var locals = Nested(module, host, "Locals");
            var field = new FieldDefUser(
                "Value",
                new FieldSig(module.CorLibTypes.Object),
                FieldAttributes.Public);
            locals.Fields.Add(field);
            AddWriter(module, host, "Store", field, payload, on: locals);
            Befriend(module);
        });

        var result = new TypeRestorationPass().Run(context);
        var field = context.Module.GetTypes()
            .SelectMany(type => type.Fields)
            .Single(item => item.Name == "Value");

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Equal("System.Object", field.FieldSig.Type.FullName);
    }

    private static TypeDefUser Nested(ModuleDef module, TypeDef enclosing, string name)
    {
        var type = new TypeDefUser(name, module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.NestedPublic | TypeAttributes.Class
        };
        enclosing.NestedTypes.Add(type);
        return type;
    }

    private static void Befriend(ModuleDef module)
    {
        var attribute = new TypeRefUser(
            module,
            "System.Runtime.CompilerServices",
            "InternalsVisibleToAttribute",
            module.CorLibTypes.AssemblyRef);
        var constructor = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
            attribute);
        module.Assembly!.CustomAttributes.Add(new CustomAttribute(
            constructor,
            [new CAArgument(module.CorLibTypes.String, new UTF8String("Friend"))]));
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
        ModuleDef module,
        TypeDef host,
        string name,
        FieldDef field,
        TypeDef produced,
        TypeDef? on = null)
    {
        var constructor = produced.FindDefaultConstructor();
        var writer = new MethodDefUser(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.Void, (on ?? host).ToTypeSig()))
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
