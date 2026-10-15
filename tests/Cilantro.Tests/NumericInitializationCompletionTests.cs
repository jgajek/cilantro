using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class NumericInitializationCompletionTests
{
    [Theory]
    [InlineData("removed", 1)] [InlineData("owner-retained", 0)]
    [InlineData("changed-bytes", 0)] [InlineData("literal-consumer", 0)]
    public void NumericResourceRemovalRequiresCommittedRetirementAndPhysicalCleanup(string variant, int removed)
    {
        using var context = Fixture("resource");
        var owner = context.Module.GetTypes().Single(t => t.Name == "Numeric");
        var bridge = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Bridge");
        context.SetFact("options.removeRuntime", true);
        context.SetFact(NumericTableRecoveryPass.InitializationBridgesFact,
            new List<NumericTableRecoveryPass.InitializationBridge> { new(bridge, owner.Fields.Single()) });
        Assert.Equal(1, new NumericInitializationCompletionPass().Run(context).Changes);
        Assert.Empty(NumericResourceOwnership.RemovedOrigins(context));
        if (variant != "owner-retained")
        {
            Assert.Equal(PassStatus.Success, new NumericRuntimeCleanupPass().Run(context).Status);
            Assert.Single(NumericResourceOwnership.RemovedOrigins(context));
        }
        if (variant == "changed-bytes")
        {
            context.Module.Resources.Clear();
            context.Module.Resources.Add(new EmbeddedResource("numeric", new byte[] { 9 }, ManifestResourceAttributes.Private));
        }
        if (variant == "literal-consumer")
        {
            bridge.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("numeric"));
            bridge.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        var result = new ProtectorResourceCleanupPass().Run(context);
        Assert.Equal(removed, result.Changes);
        Assert.Equal(1 - removed, context.Module.Resources.Count);
    }

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)] [InlineData(false, true)]
    public void PackedArraySiblingAttributionStillRequiresDeadness(bool called, bool unrelatedReader)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host"); host.Attributes |= TypeAttributes.Public;
            var holder = SyntheticContext.AddType(module, "Holder");
            var other = SyntheticContext.AddType(module, "Other");
            var reader = new MethodDefUser("Read", MethodSig.CreateStatic(
                module.CorLibTypes.GetTypeRef("System", "Array").ToTypeSig(), module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            (unrelatedReader ? other : holder).Methods.Add(reader);
            Add(reader, OpCodes.Ldnull.ToInstruction(), OpCodes.Ret.ToInstruction());
            var wrapper = new MethodDefUser("Wrapper", reader.MethodSig)
                { Attributes = MethodAttributes.Static | MethodAttributes.Private, Body = new CilBody() };
            host.Methods.Add(wrapper);
            Add(wrapper, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Castclass.ToInstruction(new TypeSpecUser(new SZArraySig(module.CorLibTypes.Byte))),
                OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void,
                    new SZArraySig(module.CorLibTypes.Byte)), module.CorLibTypes.GetTypeRef("System.IO", "MemoryStream"))),
                OpCodes.Call.ToInstruction(reader), OpCodes.Ret.ToInstruction());
            if (called)
            {
                var run = new MethodDefUser("Run", reader.MethodSig)
                    { Attributes = MethodAttributes.Static | MethodAttributes.Public, Body = new CilBody() };
                host.Methods.Add(run);
                Add(run, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(wrapper), OpCodes.Ret.ToInstruction());
            }
        });
        var wrapper = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Wrapper");
        var holder = context.Module.GetTypes().Single(t => t.Name == "Holder");
        var attributable = NumericTableRecoveryPass.IsNumericArrayWrapper(wrapper, holder);
        Assert.Equal(!unrelatedReader, attributable);
        if (attributable) Cilantro.Core.Analysis.RecoveryOrphans.Declare(context, wrapper);
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.Equal(called || unrelatedReader, context.Module.GetTypes().SelectMany(t => t.Methods).Contains(wrapper));
    }

    [Theory]
    [InlineData("closed", true)] [InlineData("consumer", false)]
    [InlineData("mutation", false)] [InlineData("external-write", false)]
    [InlineData("unknown-call", false)] [InlineData("throw", false)]
    [InlineData("reentry", false)] [InlineData("no-provenance", false)]
    [InlineData("disabled", false)]
    [InlineData("inherited-finalizer", false)]
    [InlineData("dead-finalizer", true)]
    public void RetiresOnlyPrivateConstructionAndKeepsSharedInitialization(string variant, bool expected)
    {
        using var context = Fixture(variant);
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var bridge = methods.Single(m => m.Name == "Bridge");
        var caller = methods.Single(m => m.Name == "Run");
        var holder = context.Module.GetTypes().Single(t => t.Name == "Numeric").Fields.Single();
        context.SetFact("options.removeRuntime", variant != "disabled");
        if (variant != "no-provenance")
            context.SetFact(NumericTableRecoveryPass.InitializationBridgesFact,
                new List<NumericTableRecoveryPass.InitializationBridge> { new(bridge, holder) });
        var original = bridge.Body;
        var result = new NumericInitializationCompletionPass().Run(context);
        Assert.True(result.Changes == (expected ? 1 : 0), string.Join("\n", result.Diagnostics));
        if (!expected) { Assert.Same(original, bridge.Body); return; }
        Assert.Equal(new[] { Code.Ldtoken, Code.Call, Code.Ret }, bridge.Body.Instructions.Select(i => i.OpCode.Code));
        Assert.Equal("Shared", ((ITypeDefOrRef)bridge.Body.Instructions[0].Operand).Name.String);
        Assert.True(context.TryGetFact<IReadOnlySet<TypeDef>>(NumericInitializationCompletionPass.SharedTypesFact, out var retained));
        Assert.Contains(context.Module.GetTypes().Single(t => t.Name == "Shared"), retained!);
        var machine = new StaticMachine(modelTypeInitialization: true);
        machine.State.RegisterModuleMetadata(context.Module);
        var answer = machine.Execute(caller);
        Assert.True(answer.Succeeded, answer.Diagnostic);
        Assert.Equal(7, answer.Value.AsInt32());
        Assert.DoesNotContain(machine.State.StaticFields, p => p.Key.Contains("Holder", StringComparison.Ordinal));
        var cleanup = new NumericRuntimeCleanupPass().Run(context);
        Assert.Equal(PassStatus.Success, cleanup.Status);
        Assert.DoesNotContain(context.Module.GetTypes(), t => t.Name == "Numeric");
        Assert.Contains(context.Module.GetTypes(), t => t.Name == "Shared");
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context)).Passed);
        Assert.Equal(0, new NumericInitializationCompletionPass().Run(context).Changes);
    }

    private static ArtifactContext Fixture(string variant) => SyntheticContext.Build(module =>
    {
        var owner = SyntheticContext.AddType(module, "Numeric");
        var shared = SyntheticContext.AddType(module, "Shared");
        var host = SyntheticContext.AddType(module, "Host");
        if (variant == "inherited-finalizer")
        {
            var parent = SyntheticContext.AddType(module, "Finalizable");
            owner.BaseType = parent;
            var finalizer = new MethodDefUser("Finalize", MethodSig.CreateInstance(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Virtual, Body = new CilBody() };
            parent.Methods.Add(finalizer);
            Add(finalizer, OpCodes.Ret.ToInstruction());
        }
        var data = new FieldDefUser("Data", new FieldSig(new SZArraySig(module.CorLibTypes.Int32)), FieldAttributes.Static);
        shared.Fields.Add(data);
        var holder = new FieldDefUser("Holder", new FieldSig(owner.ToTypeSig()), FieldAttributes.Static | FieldAttributes.InitOnly);
        owner.Fields.Add(holder);
        var bridge = new MethodDefUser("Bridge", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
        host.Methods.Add(bridge);
        Add(bridge, OpCodes.Ldsfld.ToInstruction(holder), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        var sharedInit = shared.FindOrCreateStaticConstructor(); sharedInit.Body.Instructions.Clear();
        if (variant == "reentry") Add(sharedInit, OpCodes.Call.ToInstruction(bridge));
        Add(sharedInit, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef),
            OpCodes.Dup.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldc_I4_7.ToInstruction(),
            OpCodes.Stelem_I4.ToInstruction(), OpCodes.Stsfld.ToInstruction(data), OpCodes.Ret.ToInstruction());
        var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
        owner.Methods.Add(ctor);
        Add(ctor, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)), OpCodes.Ldsfld.ToInstruction(data));
        if (variant == "mutation") Add(ctor, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stelem_I4.ToInstruction());
        else Add(ctor, OpCodes.Pop.ToInstruction());
        if (variant == "external-write")
        {
            var external = new FieldDefUser("Effect", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static); host.Fields.Add(external);
            Add(ctor, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(external));
        }
        if (variant == "unknown-call") Add(ctor, OpCodes.Call.ToInstruction(new MemberRefUser(module, "WriteLine",
            MethodSig.CreateStatic(module.CorLibTypes.Void), module.CorLibTypes.GetTypeRef("System", "Console"))));
        if (variant == "resource")
        {
            module.Resources.Add(new EmbeddedResource("numeric", new byte[] { 1, 2 }, ManifestResourceAttributes.Private));
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            Add(ctor, OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly",
                    MethodSig.CreateStatic(assembly.ToTypeSig()), assembly)),
                OpCodes.Ldstr.ToInstruction("numeric"),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetManifestResourceStream",
                    MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System.IO", "Stream").ToTypeSig(), module.CorLibTypes.String), assembly)),
                OpCodes.Pop.ToInstruction());
        }
        if (variant == "throw") Add(ctor, OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
        if (variant == "dead-finalizer")
        {
            var unused = SyntheticContext.AddType(module, "UnusedFinalizable");
            var unusedCtor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            unused.Methods.Add(unusedCtor);
            Add(unusedCtor, OpCodes.Ret.ToInstruction());
            var finalizer = new MethodDefUser("Finalize", MethodSig.CreateInstance(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Virtual, Body = new CilBody() };
            unused.Methods.Add(finalizer);
            Add(finalizer, OpCodes.Ret.ToInstruction());
            var done = OpCodes.Nop.ToInstruction();
            Add(ctor, OpCodes.Br.ToInstruction(done), OpCodes.Newobj.ToInstruction(unusedCtor), OpCodes.Pop.ToInstruction(), done);
        }
        Add(ctor, OpCodes.Ret.ToInstruction());
        var init = owner.FindOrCreateStaticConstructor(); init.Body.Instructions.Clear();
        Add(init, OpCodes.Newobj.ToInstruction(ctor), OpCodes.Stsfld.ToInstruction(holder), OpCodes.Ret.ToInstruction());
        var caller = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Static | MethodAttributes.Public, Body = new CilBody() };
        host.Methods.Add(caller);
        if (variant == "consumer") Add(caller, OpCodes.Ldsfld.ToInstruction(holder), OpCodes.Pop.ToInstruction());
        Add(caller, OpCodes.Call.ToInstruction(bridge), OpCodes.Ldsfld.ToInstruction(data), OpCodes.Ldc_I4_0.ToInstruction(),
            OpCodes.Ldelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction());
    });

    private static void Add(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }
}
