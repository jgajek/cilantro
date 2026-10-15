using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Strings;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorStringCacheWritersTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CapturedTableRetainsOnlyFieldsWithThoseExactBytes(bool secondTable)
    {
        using var module = new ModuleDefUser("capture");
        var owner = SyntheticContext.AddType(module, "Tables");
        var first = new FieldDefUser("First", new FieldSig(new SZArraySig(module.CorLibTypes.Byte)), FieldAttributes.Static);
        var alias = new FieldDefUser("Alias", first.FieldSig, first.Attributes);
        var other = new FieldDefUser("Other", first.FieldSig, first.Attributes);
        owner.Fields.Add(first); owner.Fields.Add(alias); owner.Fields.Add(other);
        var machine = new StaticMachine();
        byte[] bytes = [2, 0, 0, 0, 65, 0, 2, 0, 0, 0, 66, 0];
        Assert.True(machine.State.Heap.TryAllocateByteArray(bytes, out var table));
        Assert.True(machine.State.Heap.TryAllocateByteArray(bytes, out var copy));
        Assert.True(machine.State.Heap.TryAllocateByteArray(secondTable ? [2, 0, 0, 0, 67, 0, 2, 0, 0, 0, 68, 0] : [1, 2, 3], out var unrelated));
        machine.State.WriteStaticField(first, table); machine.State.WriteStaticField(alias, copy); machine.State.WriteStaticField(other, unrelated);
        var captures = StaticStringTableInterpreter.Framed(machine);
        Assert.Equal(secondTable ? 2 : 1, captures.Length);
        var captured = Assert.Single(captures, c => c.Bytes.AsSpan().SequenceEqual(bytes));
        Assert.Equal(new[] { alias.FullName, first.FullName }, captured.TableFields);
        Assert.DoesNotContain(other.FullName, captured.TableFields);
    }

    [Theory]
    [InlineData("closed", true)]
    [InlineData("input-store", false)]
    [InlineData("input-publication", false)]
    [InlineData("merged-input", false)]
    [InlineData("other-field", false)]
    [InlineData("call", false)]
    [InlineData("live", false)]
    [InlineData("reader-remains", false)]
    [InlineData("no-cache-capture", false)]
    [InlineData("one-resource", false)]
    [InlineData("incomplete", false)]
    [InlineData("foreign-local", false)]
    public void RetiresOnlyClosedWritersToCapturedRetiredCache(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("strings", [1], ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("proxies", [2], ManifestResourceAttributes.Private));
            var owner = SyntheticContext.AddType(module, "a1B2c3D4e5F6"); owner.Namespace = "ordinary";
            var bytes = new SZArraySig(module.CorLibTypes.Byte);
            var cache = new FieldDefUser("Cache", new FieldSig(bytes), FieldAttributes.Private | FieldAttributes.Static);
            var other = new FieldDefUser("Application", new FieldSig(bytes), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(cache); owner.Fields.Add(other);
            var reader = Add(owner, "ReadString");
            reader.Body.Instructions.Insert(0, OpCodes.Ldsfld.ToInstruction(cache)); reader.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
            Add(owner, "BindProxy"); Add(owner, "Keep"); Add(owner, "ApplicationHelper");
            var writer = new MethodDefUser("WriteCache", MethodSig.CreateStatic(module.CorLibTypes.Void, bytes, bytes, bytes),
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(writer); writer.Body.Variables.Add(new Local(bytes));
            var il = writer.Body.Instructions;
            il.Add(OpCodes.Ldc_I4_1.ToInstruction()); il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef)); il.Add(OpCodes.Stloc_0.ToInstruction());
            var store = (scenario == "input-store" ? OpCodes.Ldarg_0 : OpCodes.Ldloc_0).ToInstruction();
            if (scenario == "merged-input")
            {
                il.Add(OpCodes.Ldarg_1.ToInstruction()); il.Add(OpCodes.Ldlen.ToInstruction()); il.Add(OpCodes.Brtrue.ToInstruction(store));
                il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Stloc_0.ToInstruction());
            }
            il.Add(store); il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ldc_I4_7.ToInstruction()); il.Add(OpCodes.Stelem_I1.ToInstruction());
            il.Add((scenario == "input-publication" ? OpCodes.Ldarg_0 : OpCodes.Ldloc_0).ToInstruction());
            il.Add(OpCodes.Stsfld.ToInstruction(scenario == "other-field" ? other : cache));
            if (scenario == "call") il.Add(OpCodes.Call.ToInstruction(owner.Methods.Single(m => m.Name == "ApplicationHelper")));
            il.Add(OpCodes.Ret.ToInstruction());
            var root = Add(module.GlobalType, ".cctor"); root.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
            root.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(owner.Methods.Single(m => m.Name == "Keep")));
            if (scenario == "live")
            {
                for (var i = 0; i < 3; i++) root.Body.Instructions.Insert(i, OpCodes.Ldnull.ToInstruction());
                root.Body.Instructions.Insert(3, OpCodes.Call.ToInstruction(writer));
            }
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "a1B2c3D4e5F6");
        var reader = owner.Methods.Single(m => m.Name == "ReadString");
        var cache = owner.Fields.Single(f => f.Name == "Cache");
        if (scenario == "foreign-local")
        {
            var store = owner.Methods.Single(m => m.Name == "WriteCache").Body.Instructions[2];
            store.OpCode = OpCodes.Stloc; store.Operand = new Local(cache.FieldType);
        }
        var resources = context.Module.Resources.OfType<EmbeddedResource>().ToArray();
        var origin = RecoveredResourceOrigin.Capture(resources[0]);
        DecodedResourceOwnership.Remember(context, origin, [reader]);
        if (scenario != "one-resource") DecodedResourceOwnership.Remember(context, RecoveredResourceOrigin.Capture(resources[1]), [owner.Methods.Single(m => m.Name == "BindProxy")], [owner]);
        ReactorStringCacheWriters.Remember(context, reader, new CapturedStringTable("test", [], [], new Dictionary<uint, int>(), origin,
            scenario == "no-cache-capture" ? [] : [cache.FullName]));
        if (scenario != "reader-remains") owner.Methods.Remove(reader);
        context.SetFact("method-protection.complete", scenario != "incomplete"); context.SetFact("options.removeRuntime", true);
        context.SetFact("reactor.structure", new ReactorStructureFacts(0, 0, 0, 0, 0, 0, 0, false, false, ReactorCapability.ProtectedStrings, 1, "test"));
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(removed, !owner.Methods.Any(m => m.Name == "WriteCache"));
        Assert.Contains(owner.Methods, m => m.Name == "ApplicationHelper");
        Assert.Contains(owner.Fields, f => f.Name == "Application");
    }

    private static MethodDefUser Add(TypeDef owner, string name)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(owner.Module.CorLibTypes.Void), MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
        owner.Methods.Add(method); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); return method;
    }
}
