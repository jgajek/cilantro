using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

public sealed class TokenRecoveryPassTests
{
    [Fact]
    public void RewritesConstantTypeTokenProxyToDirectHandleLoad()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var target = SyntheticContext.AddType(module, "Target");
            BuildResolveTypeProxy(module, target);
        });
        // Tokens only exist after serialization, so bind the proxy's constant to the reloaded
        // target's real metadata token before running the pass.
        var reloadedTarget = context.Module.GetTypes().Single(type => type.Name == "Target");
        var proxy = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Single(method => method.Name == "Proxy");
        var constant = proxy.Body.Instructions.Single(instruction => instruction.IsLdcI4());
        constant.OpCode = OpCodes.Ldc_I4;
        constant.Operand = (int)reloadedTarget.MDToken.Raw;

        var result = new TokenRecoveryPass().Run(context);
        var rewritten = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Single(method => method.Name == "Proxy");
        var codes = rewritten.Body.Instructions.Select(instruction => instruction.OpCode.Code).ToArray();

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.Contains(Code.Ldtoken, codes);
        Assert.DoesNotContain(rewritten.Body.Instructions,
            instruction => instruction.Operand is IMethod called &&
                called.Name == "ResolveType");
        Assert.Contains(rewritten.Body.Instructions,
            instruction => instruction.Operand is IMethod called &&
                called.Name == "GetTypeFromHandle");
    }

    [Fact]
    public void LeavesResolveWithNonConstantArgumentUntouched()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var resolveType = new Importer(module).Import(typeof(System.Reflection.Module)
                .GetMethod(nameof(System.Reflection.Module.ResolveType), [typeof(int)])!);
            var method = new MethodDefUser(
                "Proxy",
                MethodSig.CreateStatic(
                    module.CorLibTypes.Void,
                    module.CorLibTypes.GetTypeRef("System.Reflection", "Module").ToTypeSig(),
                    module.CorLibTypes.Int32))
            {
                Attributes = MethodAttributes.Public | MethodAttributes.Static,
                Body = new CilBody()
            };
            // The token flows from a parameter, so no constant can be proven.
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, resolveType));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            host.Methods.Add(method);
        });

        var result = new TokenRecoveryPass().Run(context);
        var method = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Single(item => item.Name == "Proxy");

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(method.Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.Name == "ResolveType");
    }

    [Fact]
    public void RewritesAForwardedTokenWhenTheCachedHandleIsThisModules()
    {
        using var context = SyntheticContext.Build(module =>
        {
            SyntheticContext.AddType(module, "Target");
            BuildHandleForwarder(module, seedFromThisModule: true);
        });
        var target = context.Module.GetTypes().Single(type => type.Name == "Target");
        var site = SiteOf(context);
        BindConstant(site, (int)target.MDToken.Raw);

        var result = new TokenRecoveryPass().Run(context);
        site = SiteOf(context);
        var handleLoad = site.Body.Instructions
            .SingleOrDefault(instruction => instruction.OpCode.Code == Code.Ldtoken);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.NotNull(handleLoad);
        Assert.Equal("Target", ((ITypeDefOrRef)handleLoad!.Operand).Name);
        Assert.DoesNotContain(site.Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.Name == "Forward");
    }

    [Fact]
    public void LeavesAForwardedTokenAloneWhenTheCachedHandleIsAnotherModules()
    {
        using var context = SyntheticContext.Build(module =>
        {
            SyntheticContext.AddType(module, "Target");
            BuildHandleForwarder(module, seedFromThisModule: false);
        });
        var target = context.Module.GetTypes().Single(type => type.Name == "Target");
        BindConstant(SiteOf(context), (int)target.MDToken.Raw);

        var result = new TokenRecoveryPass().Run(context);
        var site = SiteOf(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(site.Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.Name == "Forward");
    }

    private static MethodDef SiteOf(ArtifactContext context) =>
        context.Module.GetTypes().SelectMany(type => type.Methods).Single(item => item.Name == "Site");

    /// <summary>
    /// Points the site's placeholder constant at a token only the reloaded module can supply.
    /// </summary>
    private static void BindConstant(MethodDef site, int token)
    {
        var constant = site.Body.Instructions.Single(instruction => instruction.IsLdcI4());
        constant.OpCode = OpCodes.Ldc_I4;
        constant.Operand = token;
    }

    /// <summary>
    /// Builds Reactor's second token idiom: a cached module handle, a forwarder that resolves
    /// against it, and a site that pushes a token and calls the forwarder.
    /// </summary>
    /// <param name="seedFromThisModule">
    /// Whether the initializer reaches the handle from a type defined here, which is the only thing
    /// that tells the pass the tokens mean anything in this module.
    /// </param>
    private static void BuildHandleForwarder(ModuleDefUser module, bool seedFromThisModule)
    {
        var importer = new Importer(module);
        var anchor = SyntheticContext.AddType(module, "Anchor");
        var moduleHandleSig = module.CorLibTypes.GetTypeRef("System", "ModuleHandle").ToTypeSig();
        var typeHandleSig = module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig();
        var handle = new FieldDefUser(
            "Handle",
            new FieldSig(moduleHandleSig),
            FieldAttributes.Private | FieldAttributes.Static);
        anchor.Fields.Add(handle);

        // The resolve is referenced by name rather than imported, so the test does not depend on the
        // shape of the API surface the test host happens to expose.
        var resolve = new MemberRefUser(
            module,
            "GetRuntimeTypeHandleFromMetadataToken",
            MethodSig.CreateStatic(typeHandleSig, module.CorLibTypes.Int32),
            module.CorLibTypes.GetTypeRef("System", "ModuleHandle"));

        var forward = new MethodDefUser(
            "Forward",
            MethodSig.CreateStatic(typeHandleSig, module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Private | MethodAttributes.Static,
            Body = new CilBody()
        };
        forward.Body.Instructions.Add(Instruction.Create(OpCodes.Ldsflda, handle));
        forward.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        forward.Body.Instructions.Add(Instruction.Create(OpCodes.Call, resolve));
        forward.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        anchor.Methods.Add(forward);

        var initializer = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Private | MethodAttributes.Static |
                MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
            Body = new CilBody()
        };
        // typeof(seed).Assembly.GetModules()[0].ModuleHandle, the roundabout way Reactor names a
        // module. A type defined here makes it this module's; System.String makes it the corlib's.
        var seed = seedFromThisModule
            ? (ITypeDefOrRef)anchor
            : module.CorLibTypes.String.ToTypeDefOrRef();
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, seed));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Call, importer.Import(
            typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle), [typeof(RuntimeTypeHandle)])!)));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, importer.Import(
            typeof(Type).GetProperty(nameof(Type.Assembly))!.GetGetMethod()!)));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, importer.Import(
            typeof(System.Reflection.Assembly).GetMethod(
                nameof(System.Reflection.Assembly.GetModules), Type.EmptyTypes)!)));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldelem_Ref));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, importer.Import(
            typeof(System.Reflection.Module).GetProperty(
                nameof(System.Reflection.Module.ModuleHandle))!.GetGetMethod()!)));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, handle));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        anchor.Methods.Add(initializer);

        var site = new MethodDefUser("Site", MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        site.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0));
        site.Body.Instructions.Add(Instruction.Create(OpCodes.Call, forward));
        site.Body.Instructions.Add(Instruction.Create(OpCodes.Call, importer.Import(
            typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle), [typeof(RuntimeTypeHandle)])!)));
        site.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
        site.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        SyntheticContext.AddType(module, "Caller").Methods.Add(site);
    }

    private static void BuildResolveTypeProxy(ModuleDefUser module, TypeDef target)
    {
        _ = target;
        var host = SyntheticContext.AddType(module, "Host");
        var resolveType = new Importer(module).Import(typeof(System.Reflection.Module)
            .GetMethod(nameof(System.Reflection.Module.ResolveType), [typeof(int)])!);
        var moduleSig = module.CorLibTypes.GetTypeRef("System.Reflection", "Module").ToTypeSig();
        var proxy = new MethodDefUser(
            "Proxy",
            MethodSig.CreateStatic(module.CorLibTypes.Void, moduleSig))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        // Receiver load, placeholder constant token, resolve, discard: the canonical proxy shape.
        // The constant is rebound to the reloaded target token by the caller.
        proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0));
        proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, resolveType));
        proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
        proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        host.Methods.Add(proxy);
    }
}
