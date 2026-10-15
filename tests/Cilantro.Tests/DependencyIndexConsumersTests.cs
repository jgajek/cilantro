using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DependencyIndexConsumersTests
{
    [Theory]
    [InlineData("read-cache", true)]
    [InlineData("out-entry", true)]
    [InlineData("mutate-table", false)]
    [InlineData("escape-table", false)]
    [InlineData("mutate-offset", false)]
    [InlineData("field-address", false)]
    [InlineData("foreign-read", false)]
    [InlineData("escape-entry", false)]
    [InlineData("alias-entry", false)]
    [InlineData("constructor-call", false)]
    [InlineData("out-object-local", false)]
    [InlineData("handler-escape", false)]
    public void KeepsCacheWritesButRefusesIndexMutationAndEscape(string variant, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var record = SyntheticContext.AddType(module, "Entry");
            var offset = new FieldDefUser("Offset", new FieldSig(module.CorLibTypes.Int64), FieldAttributes.Public);
            var cache = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Public);
            record.Fields.Add(offset); record.Fields.Add(cache);
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int64))
                { Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            record.Methods.Add(ctor);
            foreach (var i in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Stfld.ToInstruction(offset), OpCodes.Ret.ToInstruction() })
                ctor.Body.Instructions.Add(i);
            var tableType = module.CorLibTypes.GetTypeRef("System.Collections", "Hashtable");
            var table = new FieldDefUser("Table", new FieldSig(tableType.ToTypeSig()), FieldAttributes.Private | FieldAttributes.Static);
            var alias = new FieldDefUser("Alias", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static);
            owner.Fields.Add(table); owner.Fields.Add(alias);
            var build = Method("Build", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object));
            owner.Methods.Add(build);
            foreach (var i in new[] { OpCodes.Ldc_I8.ToInstruction(8L), OpCodes.Newobj.ToInstruction(ctor), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction() })
                build.Body.Instructions.Add(i);
            var getOwner = variant == "foreign-read" ? new TypeRefUser(module, "System.Collections", "Hashtable", new AssemblyRefUser("Foreign")) : tableType;
            var get = new MemberRefUser(module, "get_Item", MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object), getOwner);
            var external = new MemberRefUser(module, "Consume", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                new TypeRefUser(module, "Application", "Sink", new AssemblyRefUser("External")));
            var select = Method("Select", MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.Object, new ByRefSig(record.ToTypeSig())));
            owner.Methods.Add(select);
            foreach (var i in new[] { OpCodes.Ldarg_1.ToInstruction(), OpCodes.Ldsfld.ToInstruction(table), OpCodes.Ldarg_0.ToInstruction(),
                OpCodes.Callvirt.ToInstruction(get), OpCodes.Castclass.ToInstruction(record), OpCodes.Stind_Ref.ToInstruction(),
                OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ret.ToInstruction() }) select.Body.Instructions.Add(i);
            var resolver = Method("Resolve", MethodSig.CreateStatic(module.CorLibTypes.Void)); owner.Methods.Add(resolver);
            var entry = new Local(record.ToTypeSig()); var temporary = new Local(module.CorLibTypes.Object);
            resolver.Body.Variables.Add(entry); resolver.Body.Variables.Add(temporary);
            var il = resolver.Body.Instructions;
            var start = OpCodes.Ldsfld.ToInstruction(table); il.Add(start);
            il.Add(OpCodes.Stloc.ToInstruction(temporary));
            if (variant == "escape-table") { il.Add(OpCodes.Ldloc.ToInstruction(temporary)); il.Add(OpCodes.Stsfld.ToInstruction(alias)); }
            if (variant == "mutate-table")
            {
                il.Add(OpCodes.Ldloc.ToInstruction(temporary)); il.Add(OpCodes.Castclass.ToInstruction(tableType));
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Clear", MethodSig.CreateInstance(module.CorLibTypes.Void), tableType)));
            }
            if (variant is "out-entry" or "out-object-local")
            {
                il.Add(OpCodes.Ldstr.ToInstruction("Key")); il.Add(OpCodes.Ldloca.ToInstruction(variant == "out-entry" ? entry : temporary));
                il.Add(OpCodes.Call.ToInstruction(select)); il.Add(OpCodes.Pop.ToInstruction());
            }
            else
            {
                il.Add(OpCodes.Ldloc.ToInstruction(temporary)); il.Add(OpCodes.Castclass.ToInstruction(tableType));
                il.Add(OpCodes.Ldstr.ToInstruction("Key")); il.Add(OpCodes.Callvirt.ToInstruction(get));
                il.Add(OpCodes.Castclass.ToInstruction(record)); il.Add(OpCodes.Stloc.ToInstruction(entry));
            }
            il.Add(OpCodes.Ldloc.ToInstruction(entry)); il.Add(OpCodes.Ldfld.ToInstruction(offset)); il.Add(OpCodes.Pop.ToInstruction());
            il.Add(OpCodes.Ldloc.ToInstruction(entry)); il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Stfld.ToInstruction(cache));
            if (variant == "mutate-offset") { il.Add(OpCodes.Ldloc.ToInstruction(entry)); il.Add(OpCodes.Ldc_I8.ToInstruction(9L)); il.Add(OpCodes.Stfld.ToInstruction(offset)); }
            if (variant == "field-address") { il.Add(OpCodes.Ldloc.ToInstruction(entry)); il.Add(OpCodes.Ldflda.ToInstruction(offset)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (variant == "constructor-call") { il.Add(OpCodes.Ldloc.ToInstruction(entry)); il.Add(OpCodes.Ldc_I8.ToInstruction(9L)); il.Add(OpCodes.Call.ToInstruction(ctor)); }
            if (variant == "escape-entry") { il.Add(OpCodes.Ldloc.ToInstruction(entry)); il.Add(OpCodes.Call.ToInstruction(external)); }
            if (variant is "alias-entry" or "handler-escape")
            {
                il.Add(OpCodes.Ldloc.ToInstruction(entry)); il.Add(OpCodes.Stloc.ToInstruction(temporary));
                if (variant == "alias-entry") { il.Add(OpCodes.Ldloc.ToInstruction(temporary)); il.Add(OpCodes.Call.ToInstruction(external)); }
            }
            var ret = OpCodes.Ret.ToInstruction();
            if (variant == "handler-escape")
            {
                // An exception can occur before a later overwrite of the alias.
                il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(external));
                il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Stloc.ToInstruction(temporary)); il.Add(OpCodes.Leave.ToInstruction(ret));
                var handler = OpCodes.Pop.ToInstruction(); il.Add(handler);
                il.Add(OpCodes.Ldloc.ToInstruction(temporary)); il.Add(OpCodes.Call.ToInstruction(external)); il.Add(OpCodes.Leave.ToInstruction(ret));
                resolver.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
                    { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = ret, CatchType = module.CorLibTypes.GetTypeRef("System", "Exception") });
            }
            il.Add(ret);
            module.Resources.Add(new EmbeddedResource("bundle", new byte[] { 1 }, ManifestResourceAttributes.Private));
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "Host");
        var record = context.Module.GetTypes().Single(t => t.Name == "Entry");
        var resource = context.Module.Resources.OfType<EmbeddedResource>().Single();
        var snapshot = new DependencyIndexConstruction.Snapshot(RecoveredResourceOrigin.Capture(resource), owner.Fields.Single(f => f.Name == "Table"),
            [new("Key", record, new Dictionary<FieldDef, long> { [record.Fields.Single(f => f.Name == "Offset")] = 8 })], 0);
        var actual = DependencyIndexConsumers.Check(owner.Methods.Single(m => m.Name == "Resolve"), owner.Methods.Single(m => m.Name == "Build"), snapshot, out var reason);
        Assert.True(actual == expected, reason);
    }

    private static MethodDefUser Method(string name, MethodSig signature) => new(name, signature)
        { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
}
