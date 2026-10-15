using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class TypeRestorationCopyTests
{
    private static readonly string[] DistinctAssemblies = ["First", "Second"];
    [Theory]
    [InlineData("array", true)]
    [InlineData("local", true)]
    [InlineData("object-local", false)]
    [InlineData("conflict", false)]
    [InlineData("branch", false)]
    [InlineData("address", false)]
    public void RestoresArrayAndFieldCopiesOnlyWithConcreteWriters(string variant, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Copies");
            // Reverse dependency order exercises inference across rounds.
            var destination = new FieldDefUser("Destination", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static);
            var source = new FieldDefUser("Source", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(destination); owner.Fields.Add(source);
            var method = new MethodDefUser("Store", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(method);
            var il = method.Body.Instructions;
            var store = OpCodes.Stsfld.ToInstruction(source);
            if (variant == "branch")
            {
                il.Add(OpCodes.Ldstr.ToInstruction("alternate"));
                il.Add(OpCodes.Br.ToInstruction(store));
            }
            il.Add(OpCodes.Ldc_I4_1.ToInstruction());
            il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));
            if (variant is "local" or "object-local")
            {
                var local = new Local(variant == "local" ? new SZArraySig(module.CorLibTypes.Byte) : module.CorLibTypes.Object);
                method.Body.Variables.Add(local);
                il.Add(OpCodes.Stloc.ToInstruction(local)); il.Add(OpCodes.Ldloc.ToInstruction(local));
            }
            il.Add(store);
            if (variant == "conflict")
            {
                il.Add(OpCodes.Ldstr.ToInstruction("other type")); il.Add(OpCodes.Stsfld.ToInstruction(source));
            }
            if (variant == "address")
            {
                il.Add(OpCodes.Ldsflda.ToInstruction(source)); il.Add(OpCodes.Pop.ToInstruction());
            }
            il.Add(OpCodes.Ldsfld.ToInstruction(source)); il.Add(OpCodes.Stsfld.ToInstruction(destination));
            il.Add(OpCodes.Ret.ToInstruction());
        });
        var instructions = context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions).ToArray();
        var result = new TypeRestorationPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(expected ? 2 : 0, result.Changes);
        Assert.All(context.Module.GetTypes().SelectMany(t => t.Fields),
            field => Assert.Equal(expected ? "System.Byte[]" : "System.Object", field.FieldType.FullName));
        Assert.Equal(instructions, context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions));
        Assert.Equal(0, new TypeRestorationPass().Run(context).Changes);
    }

    [Fact]
    public void SameNameFromDifferentAssembliesIsNotAgreement()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            var method = new MethodDefUser("Store", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(method);
            foreach (var assembly in DistinctAssemblies)
            {
                var element = new TypeRefUser(module, "Example", "SameName", new AssemblyRefUser(assembly));
                method.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                method.Body.Instructions.Add(OpCodes.Newarr.ToInstruction(element));
                method.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
            }
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(0, new TypeRestorationPass().Run(context).Changes);
    }
}
