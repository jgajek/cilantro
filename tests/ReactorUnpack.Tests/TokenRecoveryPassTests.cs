using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

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
