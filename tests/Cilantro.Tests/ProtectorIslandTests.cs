using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ProtectorIslandTests
{
    private static readonly string[] ResourceNames = ["vm.data", "shared.data", "payload.data"];

    [Fact]
    public void UnrelatedReflectiveConstructionDoesNotRetainAnIsolatedVmOverride()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var engine = SyntheticContext.AddType(module, "Engine");
            var virtualMethod = new MethodDefUser("ToString", MethodSig.CreateInstance(module.CorLibTypes.String),
                MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig)
                { Body = new CilBody() };
            virtualMethod.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("VM state"));
            virtualMethod.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            engine.Methods.Add(virtualMethod);
            var app = SyntheticContext.AddType(module, "Application"); app.Attributes = TypeAttributes.Public;
            var importer = new Importer(module);
            var read = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.String, importer.ImportAsTypeSig(typeof(Type))),
                MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            app.Methods.Add(read);
            read.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            read.Body.Instructions.Add(OpCodes.Call.ToInstruction(importer.Import(typeof(Activator).GetMethod("CreateInstance", [typeof(Type)])!)));
            read.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(importer.Import(typeof(object).GetMethod("ToString")!)));
            read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var engineType = context.Module.GetTypes().Single(type => type.Name == "Engine");
        var reachability = ModuleReachability.ComputeWithInstances(context.Module, false, []);
        Assert.NotNull(reachability.InstanceRefusal);
        Assert.True(reachability.IsReachable(engineType.Methods.Single()));
        context.SetFact<IReadOnlySet<uint>>(ProtectorIslands.VmTypesFact, new HashSet<uint> { engineType.MDToken.Raw });
        context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.DoesNotContain(context.Module.GetTypes(), type => type.Name == "Engine");
        Assert.Contains(context.Module.GetTypes(), type => type.Name == "Application" && type.Methods.Any(method => method.Name == "Read"));
    }

    [Fact]
    public void ReflectionRoundTripStillFindsTheApplicationMethodAfterTokenCompaction()
    {
        using var context = SyntheticContext.Build(module =>
        {
            Method(module, SyntheticContext.AddType(module, "Engine"), "Interpret");
            var app = SyntheticContext.AddType(module, "Application"); app.Attributes = TypeAttributes.Public;
            Method(module, app, "Target").Attributes |= MethodAttributes.Public;
            var importer = new Importer(module);
            var read = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Object,
                importer.ImportAsTypeSig(typeof(System.Reflection.MemberInfo))), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            app.Methods.Add(read);
            read.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            read.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(importer.Import(typeof(System.Reflection.MemberInfo).GetProperty("Module")!.GetMethod!)));
            read.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            read.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(importer.Import(typeof(System.Reflection.MemberInfo).GetProperty("MetadataToken")!.GetMethod!)));
            read.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(importer.Import(typeof(System.Reflection.Module).GetMethod("ResolveMethod", [typeof(int)])!)));
            read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var before = Check();
        context.SetFact<IReadOnlySet<uint>>(ProtectorIslands.VmTypesFact,
            context.Module.GetTypes().Where(type => type.Name == "Engine").Select(type => type.MDToken.Raw).ToHashSet());
        context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.DoesNotContain(context.Module.GetTypes(), type => type.Name == "Engine");
        Assert.NotEqual(before, Check());

        int Check()
        {
            // Execute only this source-built benign fixture, never a corpus input.
            using var stream = new MemoryStream(); context.Module.Write(stream);
            var assembly = System.Reflection.Assembly.Load(stream.ToArray());
            var type = assembly.GetType("Synthetic.Application", throwOnError: true)!;
            var target = type.GetMethod("Target")!;
            Assert.Equal(target, type.GetMethod("Read")!.Invoke(null, [target]));
            return target.MetadataToken;
        }
    }

    [Fact]
    public void VmOnlyResourceIsRemovedButSharedAndApplicationResourcesSurvive()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var entry = Method(module, SyntheticContext.AddType(module, "Engine"), "Interpret");
            foreach (var name in ResourceNames)
            {
                module.Resources.Add(new EmbeddedResource(name, [1, 2, 3], ManifestResourceAttributes.Private));
                entry.Body.Instructions.Insert(0, OpCodes.Pop.ToInstruction());
                entry.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction(name));
            }
            var app = SyntheticContext.AddType(module, "Application"); app.Attributes = TypeAttributes.Public;
            var read = Method(module, app, "Read"); read.Attributes |= MethodAttributes.Public;
            read.Body.Instructions.Insert(0, OpCodes.Pop.ToInstruction());
            read.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("shared.data"));
        });
        context.SetFact<IReadOnlySet<uint>>(ProtectorIslands.VmTypesFact,
            context.Module.GetTypes().Where(type => type.Name == "Engine").Select(type => type.MDToken.Raw).ToHashSet());
        context.SetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles",
            [new ResourceRoleFact("payload.data", ResourceRole.ManagedPayload, 1, [], [])]);
        context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.DoesNotContain(context.Module.Resources, resource => resource.Name == "vm.data");
        Assert.Contains(context.Module.Resources, resource => resource.Name == "shared.data");
        Assert.Contains(context.Module.Resources, resource => resource.Name == "payload.data");
        Assert.True(context.TryGetFact<IReadOnlySet<string>>("cleanup.removedResources", out var removed));
        Assert.Equal("vm.data", Assert.Single(removed!));
    }

    [Theory]
    [InlineData(false, false, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    public void OnlyIsolatedPrivateIdentifiedEnginesAreRemoved(bool applicationReference, bool publicEngine, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var engine = SyntheticContext.AddType(module, "Engine");
            if (publicEngine) engine.Attributes = TypeAttributes.Public;
            var entry = Method(module, engine, "Interpret");
            var app = SyntheticContext.AddType(module, "Application"); app.Attributes = TypeAttributes.Public;
            var main = Method(module, app, "Main"); main.Attributes |= MethodAttributes.Public;
            if (applicationReference) main.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(entry));
        });
        var engineType = context.Module.GetTypes().Single(t => t.Name == "Engine");
        context.SetFact<IReadOnlySet<uint>>(ProtectorIslands.VmTypesFact, new HashSet<uint> { engineType.MDToken.Raw });
        context.SetFact("options.removeRuntime", true);
        var result = new RuntimeCleanupPass().Run(context);
        Assert.Equal(removed, !context.Module.GetTypes().Contains(engineType));
        Assert.NotEqual(PassStatus.Failed, result.Status);
        Assert.Contains(context.Module.GetTypes(), type => type.Name == "Application");
        using var stream = new MemoryStream(); context.Module.Write(stream);
        using var reloaded = ModuleDefMD.Load(stream.ToArray());
        Assert.Equal(removed, !reloaded.GetTypes().Any(type => type.Name == "Engine"));
    }

    [Fact]
    public void OpaqueApplicationTokenUseWithholdsDeletionAndRestoresTypeOrder()
    {
        using var context = SyntheticContext.Build(module =>
        {
            Method(module, SyntheticContext.AddType(module, "Engine"), "Interpret");
            var app = SyntheticContext.AddType(module, "Application"); app.Attributes = TypeAttributes.Public;
            var method = Method(module, app, "Read"); method.Attributes |= MethodAttributes.Public;
            var il = method.Body.Instructions; il.Clear();
            il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldc_I4.ToInstruction(0x06000001));
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ResolveMethod",
                MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Int32), module.CorLibTypes.GetTypeRef("System.Reflection", "Module"))));
            il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        var before = context.Module.GetTypes().ToArray();
        context.SetFact<IReadOnlySet<uint>>(ProtectorIslands.VmTypesFact,
            before.Where(t => t.Name == "Engine").Select(t => t.MDToken.Raw).ToHashSet());
        context.SetFact("options.removeRuntime", true);
        var result = new RuntimeCleanupPass().Run(context);
        Assert.Equal(0, result.Changes);
        Assert.Equal(before, context.Module.GetTypes().ToArray());
        Assert.Contains(result.Diagnostics, text => text.Contains("numeric metadata tokens", StringComparison.Ordinal));
    }

    private static MethodDefUser Method(ModuleDef module, TypeDef type, string name)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); type.Methods.Add(method); return method;
    }
}
