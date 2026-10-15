using System.Buffers.Binary;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DependencySliceSourceTests
{
    [Theory]
    [InlineData("plain", true)]
    [InlineData("alias", true)]
    [InlineData("later-seek", true)]
    [InlineData("partial-read", false)]
    [InlineData("mutate-buffer", false)]
    [InlineData("escape-buffer", false)]
    [InlineData("stored-stream", false)]
    [InlineData("unknown-offset", false)]
    [InlineData("skip-read", false)]
    [InlineData("other-caller", false)]
    [InlineData("changed-resource", false)]
    [InlineData("open-index", false)]
    [InlineData("repeated-allocation", false)]
    [InlineData("buffer-address", false)]
    [InlineData("observes-input", true)]
    [InlineData("stream-type-test", true)]
    [InlineData("early-buffer-address", false)]
    [InlineData("reader-identity", true)]
    [InlineData("buffer-identity", true)]
    [InlineData("reader-escape", false)]
    [InlineData("reader-cast", true)]
    public void RequiresCompleteUnmodifiedSliceAndFreshInlineStream(string variant, bool expected)
    {
        const int mask = 0x123456;
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var record = SyntheticContext.AddType(module, "Entry");
            var offset = new FieldDefUser("Offset", new FieldSig(module.CorLibTypes.Int64), FieldAttributes.Public);
            record.Fields.Add(offset);
            var table = new FieldDefUser("Table", new FieldSig(module.CorLibTypes.GetTypeRef("System.Collections", "Hashtable").ToTypeSig()), FieldAttributes.Static);
            owner.Fields.Add(table);
            var streamType = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
            var memoryType = module.CorLibTypes.GetTypeRef("System.IO", "MemoryStream");
            var readerType = module.CorLibTypes.GetTypeRef("System.IO", "BinaryReader");
            var build = Method("Build", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object));
            build.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); owner.Methods.Add(build);
            var decode = Method("Decode", MethodSig.CreateStatic(streamType.ToTypeSig(), module.CorLibTypes.Object));
            decode.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); decode.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); owner.Methods.Add(decode);
            if (variant == "observes-input")
            {
                decode.Body.Instructions[0].OpCode = OpCodes.Ldarg_0;
                decode.Body.Instructions.Insert(1, OpCodes.Castclass.ToInstruction(streamType));
            }
            var resolver = Method("Resolve", MethodSig.CreateStatic(module.CorLibTypes.Void, record.ToTypeSig(), module.CorLibTypes.Boolean));
            owner.Methods.Add(resolver);
            var stream = new Local(streamType.ToTypeSig()); var reader = new Local(readerType.ToTypeSig());
            var buffer = new Local(new SZArraySig(module.CorLibTypes.Byte)); var alias = new Local(module.CorLibTypes.Object);
            foreach (var local in new[] { stream, reader, buffer, alias }) resolver.Body.Variables.Add(local);
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var getType = new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(type.ToTypeSig(),
                module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()), type);
            var getAssembly = new MemberRefUser(module, "get_Assembly", MethodSig.CreateInstance(assembly.ToTypeSig()), type);
            var open = new MemberRefUser(module, "GetManifestResourceStream", MethodSig.CreateInstance(streamType.ToTypeSig(), module.CorLibTypes.String), assembly);
            var seek = new MemberRefUser(module, "Seek", MethodSig.CreateInstance(module.CorLibTypes.Int64, module.CorLibTypes.Int64,
                module.CorLibTypes.GetTypeRef("System.IO", "SeekOrigin").ToTypeSig()), streamType);
            var makeReader = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, streamType.ToTypeSig()), readerType);
            var readLength = new MemberRefUser(module, "ReadInt32", MethodSig.CreateInstance(module.CorLibTypes.Int32), readerType);
            var readBytes = new MemberRefUser(module, "Read", MethodSig.CreateInstance(module.CorLibTypes.Int32,
                new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.Int32, module.CorLibTypes.Int32), readerType);
            var makeMemory = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.Byte)), memoryType);
            var il = resolver.Body.Instructions;
            if (variant == "early-buffer-address") { il.Add(OpCodes.Ldloca.ToInstruction(buffer)); il.Add(OpCodes.Pop.ToInstruction()); }
            foreach (var i in new[] { OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Call.ToInstruction(getType), OpCodes.Callvirt.ToInstruction(getAssembly),
                OpCodes.Ldstr.ToInstruction("bundle"), OpCodes.Callvirt.ToInstruction(open), OpCodes.Stloc.ToInstruction(stream),
                OpCodes.Ldloc.ToInstruction(stream), OpCodes.Call.ToInstruction(build), OpCodes.Ldloc.ToInstruction(stream) }) il.Add(i);
            if (variant == "unknown-offset") il.Add(OpCodes.Ldarg_1.ToInstruction());
            else { il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Ldfld.ToInstruction(offset)); }
            foreach (var i in new[] { OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Callvirt.ToInstruction(seek), OpCodes.Pop.ToInstruction(),
                OpCodes.Ldloc.ToInstruction(stream), OpCodes.Newobj.ToInstruction(makeReader), OpCodes.Stloc.ToInstruction(reader),
                OpCodes.Ldloc.ToInstruction(reader), OpCodes.Callvirt.ToInstruction(readLength), Instruction.CreateLdcI4(mask), OpCodes.Xor.ToInstruction(),
                OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef), OpCodes.Stloc.ToInstruction(buffer) }) il.Add(i);
            var afterRead = OpCodes.Nop.ToInstruction();
            if (variant == "skip-read") { il.Add(OpCodes.Ldarg_1.ToInstruction()); il.Add(OpCodes.Brfalse.ToInstruction(afterRead)); }
            il.Add(OpCodes.Ldloc.ToInstruction(reader)); il.Add(OpCodes.Ldloc.ToInstruction(buffer)); il.Add(OpCodes.Ldc_I4_0.ToInstruction());
            if (variant == "partial-read") il.Add(OpCodes.Ldc_I4_2.ToInstruction());
            else { il.Add(OpCodes.Ldloc.ToInstruction(buffer)); il.Add(OpCodes.Ldlen.ToInstruction()); il.Add(OpCodes.Conv_I4.ToInstruction()); }
            il.Add(OpCodes.Callvirt.ToInstruction(readBytes)); il.Add(OpCodes.Pop.ToInstruction()); il.Add(afterRead);
            if (variant == "reader-cast")
            {
                il.Add(OpCodes.Ldloc.ToInstruction(reader)); il.Add(OpCodes.Castclass.ToInstruction(readerType)); il.Add(OpCodes.Pop.ToInstruction());
            }
            if (variant == "repeated-allocation")
            {
                il.Add(OpCodes.Ldc_I4_4.ToInstruction()); il.Add(OpCodes.Ldarg_1.ToInstruction());
                il.Add(OpCodes.Brtrue.ToInstruction(il.Single(i => i.OpCode.Code == Code.Newarr)));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            if (variant == "buffer-address") { il.Add(OpCodes.Ldloca.ToInstruction(buffer)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (variant is "reader-identity" or "buffer-identity")
            {
                il.Add(OpCodes.Ldloc.ToInstruction(variant == "reader-identity" ? reader : buffer));
                il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ceq.ToInstruction()); il.Add(OpCodes.Pop.ToInstruction());
            }
            if (variant == "reader-escape")
            {
                il.Add(OpCodes.Ldloc.ToInstruction(reader));
                il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Consume", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                    new TypeRefUser(module, "Application", "Sink", new AssemblyRefUser("External")))));
            }
            if (variant == "mutate-buffer")
                foreach (var i in new[] { OpCodes.Ldloc.ToInstruction(buffer), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Stelem_I1.ToInstruction() }) il.Add(i);
            if (variant == "escape-buffer")
            {
                il.Add(OpCodes.Ldloc.ToInstruction(buffer));
                il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Consume", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                    new TypeRefUser(module, "Application", "Sink", new AssemblyRefUser("External")))));
            }
            if (variant == "later-seek")
                foreach (var i in new[] { OpCodes.Ldloc.ToInstruction(stream), OpCodes.Ldc_I8.ToInstruction(0L), OpCodes.Ldc_I4_0.ToInstruction(),
                    OpCodes.Callvirt.ToInstruction(seek), OpCodes.Pop.ToInstruction() }) il.Add(i);
            if (variant == "alias") { il.Add(OpCodes.Ldloc.ToInstruction(buffer)); il.Add(OpCodes.Stloc.ToInstruction(alias)); }
            if (variant == "stream-type-test")
            { il.Add(OpCodes.Ldloc.ToInstruction(stream)); il.Add(OpCodes.Isinst.ToInstruction(memoryType)); il.Add(OpCodes.Pop.ToInstruction()); }
            il.Add(OpCodes.Ldloc.ToInstruction(variant == "alias" ? alias : buffer)); il.Add(OpCodes.Newobj.ToInstruction(makeMemory));
            if (variant == "stored-stream") { il.Add(OpCodes.Stloc.ToInstruction(alias)); il.Add(OpCodes.Ldloc.ToInstruction(alias)); }
            il.Add(OpCodes.Call.ToInstruction(decode)); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
            if (variant == "other-caller")
            {
                var other = Method("Other", MethodSig.CreateStatic(module.CorLibTypes.Void)); owner.Methods.Add(other);
                foreach (var i in new[] { OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(decode), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction() }) other.Body.Instructions.Add(i);
            }
            var bytes = new byte[16]; BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), 4 ^ mask);
            bytes[12] = 0xA1; bytes[13] = 0xB2; bytes[14] = 0xC3; bytes[15] = 0xD4;
            module.Resources.Add(new EmbeddedResource("bundle", bytes, ManifestResourceAttributes.Private));
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "Host");
        var record = context.Module.GetTypes().Single(t => t.Name == "Entry");
        var resource = context.Module.Resources.OfType<EmbeddedResource>().Single();
        var index = new DependencyIndexConstruction.Snapshot(RecoveredResourceOrigin.Capture(resource), owner.Fields.Single(),
            [new("Key", record, new Dictionary<FieldDef, long> { [record.Fields.Single()] = 8 })], 16);
        if (variant == "changed-resource")
        { context.Module.Resources.Clear(); context.Module.Resources.Add(new EmbeddedResource("bundle", new byte[] { 1 }, ManifestResourceAttributes.Private)); }
        // These fixtures isolate slice analysis under previously established index
        // construction/source/consumer facts. Real-corpus trials run all three.
        var proof = new EmbeddedDependencyRecoveryPass.ValidatedIndex(owner.Methods.Single(m => m.Name == "Resolve"),
            owner.Methods.Single(m => m.Name == "Build"), index, variant != "open-index", true);
        var actual = DependencySliceSource.TryRead(proof, owner.Methods.Single(m => m.Name == "Decode"), out var slices, out var reason);
        Assert.True(actual == expected, reason);
        if (!expected) { Assert.Empty(slices); return; }
        var slice = Assert.Single(slices);
        Assert.Equal(12, slice.Offset); Assert.Equal(new byte[] { 0xA1, 0xB2, 0xC3, 0xD4 }, slice.Bytes);
        var discard = DependencySliceSource.TryDiscard(proof, owner.Methods.Single(m => m.Name == "Decode"), out var plan, out reason);
        Assert.Equal(variant is not ("observes-input" or "stream-type-test"), discard);
        if (discard)
        {
            Assert.NotNull(plan);
            Assert.Contains(plan.Reads, r => r.Pops == 4 && r.Value == 4 && !r.Wide);
            Assert.Contains(plan.Reads, r => r.Pops == 1 && r.Value == (4 ^ mask) && !r.Wide);
            Assert.Contains(plan.Reads, r => r.Call.OpCode.Code == Code.Ldlen && r.Value == 4 && r.Native);
            Assert.Equal(variant is "reader-identity" or "buffer-identity" ? 1 : 3, plan.UnobservedAllocations.Count);
            Assert.Equal(variant == "reader-cast" ? 1 : 0, plan.RedundantCasts.Count);
            if (variant is "reader-identity" or "buffer-identity")
                Assert.Contains("MemoryStream", Assert.Single(plan.UnobservedAllocations).Operand.ToString());
        }
    }

    private static MethodDefUser Method(string name, MethodSig signature) => new(name, signature)
        { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
}
