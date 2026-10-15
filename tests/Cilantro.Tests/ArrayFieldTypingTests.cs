using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ArrayFieldTypingTests
{
    [Theory]
    [InlineData("closed", true)]
    [InlineData("instance", true)]
    [InlineData("null-writer", true)]
    [InlineData("same-writer", true)]
    [InlineData("reference-array", true)]
    [InlineData("rank-two", true)]
    [InlineData("padding", true)]
    [InlineData("unknown-writer", false)]
    [InlineData("conflicting-writer", false)]
    [InlineData("null-only", false)]
    [InlineData("address", false)]
    [InlineData("handle", false)]
    [InlineData("type-handle", false)]
    [InlineData("named", false)]
    [InlineData("external", false)]
    [InlineData("serializable", false)]
    [InlineData("alternate-entry", false)]
    [InlineData("generic-owner", false)]
    [InlineData("typed-argument", true)]
    [InlineData("new-array", true)]
    [InlineData("array-return", true)]
    [InlineData("object-return", false)]
    public void RequiresEveryWriterAndAClosedFieldSurface(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Holder");
            if (scenario == "external") owner.Attributes = TypeAttributes.Public;
            if (scenario == "serializable") owner.Attributes |= TypeAttributes.Serializable;
            if (scenario == "generic-owner") owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var instance = scenario == "instance";
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object),
                (scenario == "external" ? FieldAttributes.Public : FieldAttributes.Private) | (instance ? 0 : FieldAttributes.Static));
            owner.Fields.Add(field);
            TypeSig array = scenario == "rank-two" ? new ArraySig(module.CorLibTypes.Int32, 2) :
                new SZArraySig(scenario == "reference-array" ? module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig() : module.CorLibTypes.Int32);
            var store = Add("Store", module.CorLibTypes.Void, instance ? new[] { owner.ToTypeSig(), module.CorLibTypes.Object } : new[] { scenario == "typed-argument" ? array : module.CorLibTypes.Object });
            if (instance) store.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            store.Body.Instructions.Add(scenario == "null-only" ? OpCodes.Ldnull.ToInstruction() : (instance ? OpCodes.Ldarg_1 : OpCodes.Ldarg_0).ToInstruction());
            var write = instance ? OpCodes.Stfld.ToInstruction(field) : OpCodes.Stsfld.ToInstruction(field);
            if (scenario == "alternate-entry")
            { store.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction()); store.Body.Instructions.Add(OpCodes.Brtrue.ToInstruction(write)); }
            if (scenario is "new-array" or "array-return" or "object-return")
            {
                store.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                if (scenario == "new-array")
                {
                    store.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                    store.Body.Instructions.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
                }
                else
                {
                    var factory = Add("Factory", scenario == "array-return" ? array : module.CorLibTypes.Object);
                    factory.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                    factory.Body.Instructions.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
                    factory.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    store.Body.Instructions.Add(OpCodes.Call.ToInstruction(factory));
                }
            }
            else if (scenario is not ("null-only" or "typed-argument")) store.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(array.ToTypeDefOrRef()));
            if (scenario == "padding") store.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
            store.Body.Instructions.Add(write); store.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (scenario.EndsWith("writer", StringComparison.Ordinal))
            {
                var other = Add("Other", module.CorLibTypes.Void, module.CorLibTypes.Object);
                other.Body.Instructions.Add(scenario == "null-writer" ? OpCodes.Ldnull.ToInstruction() : OpCodes.Ldarg_0.ToInstruction());
                if (scenario is "same-writer" or "conflicting-writer") other.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(
                    (scenario == "same-writer" ? array : new SZArraySig(module.CorLibTypes.Byte)).ToTypeDefOrRef()));
                other.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field)); other.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            var read = Add("Read", module.CorLibTypes.Int32, instance ? new[] { owner.ToTypeSig() } : Array.Empty<TypeSig>());
            if (scenario is "address" or "handle" or "type-handle" or "named")
            {
                read.Body.Instructions.Add(scenario switch
                {
                    "address" => OpCodes.Ldsflda.ToInstruction(field), "handle" => OpCodes.Ldtoken.ToInstruction(field),
                    "type-handle" => OpCodes.Ldtoken.ToInstruction(owner), _ => OpCodes.Ldstr.ToInstruction(field.Name.String)
                });
                read.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (instance) read.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            read.Body.Instructions.Add(instance ? OpCodes.Ldfld.ToInstruction(field) : OpCodes.Ldsfld.ToInstruction(field));
            read.Body.Instructions.Add(OpCodes.Ldlen.ToInstruction()); read.Body.Instructions.Add(OpCodes.Conv_I4.ToInstruction()); read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            MethodDef Add(string name, TypeSig result, params TypeSig[] parameters)
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(result, parameters)) { Attributes = MethodAttributes.Static, Body = new CilBody() };
                owner.Methods.Add(method); return method;
            }
        });
        var field = context.Module.GetTypes().SelectMany(t => t.Fields).Single();
        var reader = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read");
        var length = reader.Body.Instructions.Count;
        var result = new ArrayFieldTypingPass().Run(context);
        Assert.Equal(expected ? 1 : 0, result.Changes);
        Assert.Equal(length + (expected ? 1 : 0), reader.Body.Instructions.Count);
        Assert.Equal(ElementType.Object, field.FieldType.ElementType);
        Assert.Equal(0, new ArrayFieldTypingPass().Run(context).Changes);
        if (scenario is "typed-argument" or "new-array" or "array-return" or "object-return")
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try
            {
                context.Module.Write(path);
                var reading = IlVerification.Read(path, []);
                Assert.Empty(reading.Unreadable);
                Assert.Equal(expected ? 0 : 1, reading.Count);
            }
            finally { File.Delete(path); }
        }
    }
}
