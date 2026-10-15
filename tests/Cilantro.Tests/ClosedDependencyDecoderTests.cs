using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedDependencyDecoderTests
{
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void SharedInitializationMustRemainImmutable(bool mutable, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Decoder");
            var shared = SyntheticContext.AddType(module, "Lookup");
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Assembly);
            shared.Fields.Add(field);
            var ctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            shared.Methods.Add(ctor);
            ctor.Body.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction()); ctor.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
            ctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var method = new MethodDefUser("Decode", MethodSig.CreateStatic(module.CorLibTypes.GetTypeRef("System.IO", "Stream").ToTypeSig(), module.CorLibTypes.Object))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(method);
            foreach (var i in new[] { OpCodes.Ldsfld.ToInstruction(field), OpCodes.Pop.ToInstruction(), OpCodes.Ldarg_0.ToInstruction(),
                OpCodes.Castclass.ToInstruction(module.CorLibTypes.GetTypeRef("System.IO", "Stream")), OpCodes.Ret.ToInstruction() }) method.Body.Instructions.Add(i);
            if (mutable)
            {
                var writer = new MethodDefUser("Change", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
                owner.Methods.Add(writer);
                writer.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction()); writer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field)); writer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
        });
        var decoder = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Decode");
        var passed = ClosedDependencyDecoder.TryRead(context, decoder, [1, 2, 3], out var result, out var reason);
        Assert.True(passed == expected, reason);
        if (expected) Assert.Equal("Lookup", Assert.Single(result!.Initializers).Name.String);
    }

    [Theory]
    [InlineData("identity", true)]
    [InlineData("empty-initializer", true)]
    [InlineData("mutate-input", false)]
    [InlineData("ambient", false)]
    [InlineData("static-write", false)]
    [InlineData("foreign-stream", false)]
    public void RequiresFixedBytesAndClosedEffects(string variant, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Decoder");
            var stream = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
            var method = new MethodDefUser("Decode", MethodSig.CreateStatic(stream.ToTypeSig(), module.CorLibTypes.Object))
            { Attributes = MethodAttributes.Static | MethodAttributes.Private, Body = new CilBody() };
            owner.Methods.Add(method);
            var il = method.Body.Instructions;
            if (variant == "ambient")
            {
                il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "get_TickCount", MethodSig.CreateStatic(module.CorLibTypes.Int32),
                    module.CorLibTypes.GetTypeRef("System", "Environment"))));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            if (variant == "static-write")
            {
                var field = new FieldDefUser("State", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Private);
                owner.Fields.Add(field);
                il.Add(OpCodes.Ldc_I4_1.ToInstruction()); il.Add(OpCodes.Stsfld.ToInstruction(field));
            }
            if (variant == "mutate-input")
            {
                il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Castclass.ToInstruction(stream));
                il.Add(OpCodes.Ldc_I4_0.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "WriteByte", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Byte), stream)));
            }
            if (variant == "foreign-stream")
            {
                var foreign = new TypeRefUser(module, "System.IO", "MemoryStream", new AssemblyRefUser("Foreign"));
                il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), foreign)));
            }
            else { il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Castclass.ToInstruction(stream)); }
            il.Add(OpCodes.Ret.ToInstruction());
            if (variant == "empty-initializer")
            {
                var ctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
                owner.Methods.Add(ctor);
                var ret = OpCodes.Ret.ToInstruction();
                var branch = OpCodes.Br.ToInstruction(ret);
                ctor.Body.Instructions.Add(OpCodes.Br.ToInstruction(branch));
                ctor.Body.Instructions.Add(ret); ctor.Body.Instructions.Add(branch);
            }
        });
        var decoder = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Decode");
        var passed = ClosedDependencyDecoder.TryRead(context, decoder, [1, 2, 3], out var result, out var reason);
        Assert.True(passed == expected, reason);
        if (expected)
        {
            Assert.Equal(new byte[] { 1, 2, 3 }, result!.Bytes);
            Assert.Empty(result.Initializers);
        }
    }
}
