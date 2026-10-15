using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class RetiredDependencyResourceTests
{
    [Theory]
    [InlineData("retired", 1)]
    [InlineData("uncertified", 0)]
    [InlineData("payload", 0)]
    [InlineData("resolver", 0)]
    [InlineData("helper", 0)]
    [InlineData("index", 0)]
    [InlineData("mutable-data", 0)]
    [InlineData("detached-helper", 0)]
    [InlineData("duplicate-source", 0)]
    [InlineData("signature", 0)]
    [InlineData("layout", 0)]
    [InlineData("source", 0)]
    [InlineData("literal", 0)]
    [InlineData("reader", 1)]
    [InlineData("native", 1)]
    [InlineData("application", 0)]
    [InlineData("disabled", 0)]
    [InlineData("foreign", 1)]
    public void RemovesOnlyCertifiedRetiredBundle(string scenario, int expected)
    {
        byte[] payload;
        using (var benign = SyntheticContext.Build(module => SyntheticContext.AddType(module, "Payload")))
        using (var bytes = new MemoryStream()) { benign.Module.Write(bytes); payload = bytes.ToArray(); }
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("bundle", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("unrelated", new byte[] { 4, 5 }, ManifestResourceAttributes.Private));
            var holder = DependencyDecoderCompletionPass.BuildHolder(module,
                new ClosedDependencyDecoder.Result(payload, [], new HashSet<MethodDef>(), 0));
            module.Types.Add(holder);
            var owner = SyntheticContext.AddType(module, "App");
            var resolver = new MethodDefUser("Resolve", MethodSig.CreateStatic(new SZArraySig(module.CorLibTypes.Byte)))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(resolver);
            resolver.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            resolver.Body.Instructions.Add(OpCodes.Call.ToInstruction(holder.Methods[0]));
            var memory = module.CorLibTypes.GetTypeRef("System.IO", "MemoryStream");
            resolver.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(memory));
            resolver.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ToArray",
                MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Byte)), memory)));
            resolver.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var index = new MethodDefUser("Index", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(index); index.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(run);
            var assembly = new TypeRefUser(module, "System.Reflection", "Assembly",
                scenario == "foreign" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
            run.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)));
            run.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            if (scenario == "reader")
            {
                run.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); run.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                run.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetManifestResourceStream",
                    MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System.IO", "Stream").ToTypeSig(), module.CorLibTypes.String), assembly)));
                run.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario == "literal")
            { run.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("bundle")); run.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "native") owner.Methods.Add(new MethodDefUser("Native", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static | MethodAttributes.PinvokeImpl,
                ImplMap = new ImplMapUser(new ModuleRefUser(module, "unknown.dll"), "Read", 0) });
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var helper = methods.Single(m => m.Name == "Open");
        var resolver = methods.Single(m => m.Name == "Resolve");
        var index = methods.Single(m => m.Name == "Index");
        Assert.True(DependencyArrayCompletion.Apply(context, helper));
        var origin = RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0]);
        var proof = RetiredDependencyResource.Capture(origin, resolver, index, helper);
        Assert.NotNull(proof);
        context.SetFact<IReadOnlyList<RecoveredResourceOrigin>>(DependencyInputCompletionPass.RetiredResourcesFact, [origin]);
        if (scenario != "uncertified") context.SetFact<IReadOnlyList<RetiredDependencyResource>>(RetiredDependencyResource.Fact, [proof]);
        // Unrelated attributed resources must not inherit the metadata-removal exception.
        context.SetFact("proxy.validatedResource", RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[1]));
        context.SetFact("options.removeRuntime", scenario != "disabled");
        if (scenario == "payload") helper.DeclaringType.Fields[0].InitialValue[0] ^= 1;
        if (scenario == "resolver") resolver.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
        if (scenario == "helper") helper.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
        if (scenario == "index") index.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
        if (scenario == "mutable-data") helper.DeclaringType.Fields[0].IsInitOnly = false;
        if (scenario == "detached-helper") helper.DeclaringType.Methods.Remove(helper);
        if (scenario == "duplicate-source") context.Module.Resources.Add(new EmbeddedResource("bundle", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Private));
        if (scenario == "signature") helper.MethodSig.Params.Add(context.Module.CorLibTypes.Int32);
        if (scenario == "layout") helper.DeclaringType.NestedTypes[0].ClassLayout.PackingSize = 2;
        if (scenario == "source") context.Module.Resources[0] = new EmbeddedResource("bundle", new byte[] { 9 }, ManifestResourceAttributes.Private);
        if (scenario == "application") context.SetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles",
            [new("bundle", ResourceRole.ManagedPayload, 1, [], [])]);
        var bodies = methods.ToDictionary(m => m, MethodBodySnapshot.Capture);
        Assert.Equal(expected, new ProtectorResourceCleanupPass().Run(context).Changes);
        Assert.Equal((scenario == "duplicate-source" ? 3 : 2) - expected, context.Module.Resources.Count);
        Assert.Contains(context.Module.Resources, r => r.Name == "unrelated");
        Assert.True(bodies.All(p => p.Value.StructurallyEquals(p.Key)));
        if (expected == 1)
        {
            Assert.Equal(payload, helper.DeclaringType.Fields[0].InitialValue);
            using var bytes = new MemoryStream(); context.Module.Write(bytes);
            using var reloaded = ModuleDefMD.Load(bytes.ToArray());
            Assert.Single(reloaded.Resources);
        }
    }
}
