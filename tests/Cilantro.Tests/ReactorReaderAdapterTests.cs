using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorReaderAdapterTests
{
    [Theory]
    [InlineData("dead", true)]
    [InlineData("live", false)]
    [InlineData("handle", false)]
    [InlineData("extra-method", false)]
    [InlineData("changed-body", false)]
    [InlineData("foreign-reader", false)]
    [InlineData("one-resource", false)]
    [InlineData("incomplete", false)]
    public void RemovesOnlyCompleteAttributedDeadAdapter(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("strings", [1], ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("proxies", [2], ManifestResourceAttributes.Private));
            var owner = SyntheticContext.AddType(module, "a1B2c3D4e5F6"); owner.Namespace = "ordinary";
            var nested = new TypeDefUser("", "ReaderAdapter", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.NestedPrivate };
            owner.NestedTypes.Add(nested);
            var reader = new TypeRefUser(module, "System.IO", "BinaryReader", scenario == "foreign-reader" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
            var field = new FieldDefUser("Reader", new FieldSig(reader.ToTypeSig()), FieldAttributes.Private); nested.Fields.Add(field);
            var bytes = new SZArraySig(module.CorLibTypes.Byte);
            var operations = new[] {
                ("get_BaseStream", MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System.IO", "Stream").ToTypeSig())),
                ("ReadBytes", MethodSig.CreateInstance(bytes, module.CorLibTypes.Int32)),
                ("Read", MethodSig.CreateInstance(module.CorLibTypes.Int32, bytes, module.CorLibTypes.Int32, module.CorLibTypes.Int32)),
                ("Close", MethodSig.CreateInstance(module.CorLibTypes.Void)) };
            foreach (var (name, signature) in operations)
            {
                var adapter = new MethodDefUser(name, signature, MethodAttributes.Assembly | MethodAttributes.HideBySig) { Body = new CilBody() };
                nested.Methods.Add(adapter);
                adapter.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); adapter.Body.Instructions.Add(OpCodes.Ldfld.ToInstruction(field));
                foreach (var parameter in adapter.Parameters.Skip(1)) adapter.Body.Instructions.Add(OpCodes.Ldarg.ToInstruction(parameter));
                adapter.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, name, signature, reader)));
                if (scenario == "changed-body" && name == "Close") { adapter.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("application")); adapter.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
                adapter.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                var thunk = new MethodDefUser("Forward" + name, MethodSig.CreateStatic(signature.RetType,
                    new[] { module.CorLibTypes.Object }.Cast<TypeSig>().Concat(signature.Params).ToArray()), MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
                owner.Methods.Add(thunk);
                foreach (var parameter in thunk.Parameters) thunk.Body.Instructions.Add(OpCodes.Ldarg.ToInstruction(parameter));
                thunk.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(adapter)); thunk.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            if (scenario == "extra-method") Add(nested, "UnusedApplicationHelper");
            Add(owner, "ReadString"); Add(owner, "BindProxy"); Add(owner, "Keep"); Add(owner, "UnusedApplicationHelper");
            var root = Add(module.GlobalType, ".cctor"); root.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
            root.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(owner.Methods.Single(m => m.Name == "Keep")));
            var forward = owner.Methods.Single(m => m.Name == "Forwardget_BaseStream");
            if (scenario == "live") { root.Body.Instructions.Insert(0, OpCodes.Ldnull.ToInstruction()); root.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(forward)); root.Body.Instructions.Insert(2, OpCodes.Pop.ToInstruction()); }
            if (scenario == "handle") { root.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(nested)); root.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction()); }
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "a1B2c3D4e5F6");
        var resources = context.Module.Resources.OfType<EmbeddedResource>().ToArray();
        DecodedResourceOwnership.Remember(context, RecoveredResourceOrigin.Capture(resources[0]), [owner.Methods.Single(m => m.Name == "ReadString")]);
        if (scenario != "one-resource") DecodedResourceOwnership.Remember(context, RecoveredResourceOrigin.Capture(resources[1]), [owner.Methods.Single(m => m.Name == "BindProxy")], [owner]);
        context.SetFact("method-protection.complete", scenario != "incomplete"); context.SetFact("options.removeRuntime", true);
        context.SetFact("reactor.structure", new ReactorStructureFacts(0, 0, 0, 0, 0, 0, 0, false, false, ReactorCapability.ProtectedStrings, 1, "test"));
        new RuntimeCleanupPass().Run(context); new RuntimeCleanupPass().Run(context);
        Assert.Equal(removed, !owner.NestedTypes.Any(t => t.Name == "ReaderAdapter"));
        if (removed) Assert.DoesNotContain(owner.Methods, m => m.Name.String.StartsWith("Forward", StringComparison.Ordinal));
        Assert.Contains(owner.Methods, m => m.Name == "UnusedApplicationHelper");
    }

    private static MethodDefUser Add(TypeDef owner, string name)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(owner.Module.CorLibTypes.Void), MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
        owner.Methods.Add(method); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); return method;
    }
}
