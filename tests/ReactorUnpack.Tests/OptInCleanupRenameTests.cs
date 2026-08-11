using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Recovery;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Tests;

public sealed class OptInCleanupRenameTests
{
    [Theory]
    [InlineData("H1lrRRwH0tOVtn61XvY", true)]
    [InlineData("bGcJ4pwhljTUS1IQGf6", true)]
    [InlineData("gFvcpJGhiO", true)]
    [InlineData("vwAcYxvHwU", true)]
    [InlineData("Program", false)]
    [InlineData("GetValue", false)]
    [InlineData("DecryptString", false)]
    [InlineData("Utf8Encoder", false)]
    [InlineData("field", false)]
    public void NameHeuristicRecognizesGeneratedIdentifiers(string name, bool expected) =>
        Assert.Equal(expected, ReactorNameHeuristics.IsGeneratedName(name));

    [Fact]
    public void CleanupIsWithheldWithoutTheOptIn()
    {
        using var context = SyntheticContext.Build(module =>
        {
            AddDeadProxy(module, "Proxy0");
            SyntheticContext.AddType(module, "Host");
        });

        var result = new RuntimeCleanupPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(context.Module.GetTypes(), type => type.Name == "Proxy0");
    }

    [Fact]
    public void CleanupRemovesUnreferencedProxyAndTheOutputReloads()
    {
        using var context = SyntheticContext.Build(module =>
        {
            AddDeadProxy(module, "DeadProxy");
            SyntheticContext.AddType(module, "Host");
        });
        context.SetFact("options.removeRuntime", true);

        var result = new RuntimeCleanupPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.DoesNotContain(context.Module.GetTypes(), type => type.Name == "DeadProxy");
        AssertWritesAndVerifies(context);
    }

    [Fact]
    public void CleanupKeepsProxyThatSurvivingCodeReferences()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var proxy = AddDeadProxy(module, "LiveProxy");
            var host = SyntheticContext.AddType(module, "Host");
            host.Fields.Add(new FieldDefUser(
                "handle", new FieldSig(proxy.ToTypeSig()), FieldAttributes.Private));
        });
        context.SetFact("options.removeRuntime", true);

        var result = new RuntimeCleanupPass().Run(context);

        Assert.Equal(0, result.Changes);
        Assert.Contains(context.Module.GetTypes(), type => type.Name == "LiveProxy");
    }

    [Fact]
    public void UnreferencedProxyFixpointKeepsChainsReachableFromSurvivors()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var proxyA = AddDeadProxy(module, "ProxyA");
            var proxyB = AddDeadProxy(module, "ProxyB");
            AddDeadProxy(module, "ProxyC");
            // B references A, and a surviving host references B, so both A and B must be kept.
            proxyB.Fields.Add(new FieldDefUser(
                "a", new FieldSig(proxyA.ToTypeSig()), FieldAttributes.Static));
            var host = SyntheticContext.AddType(module, "Host");
            host.Fields.Add(new FieldDefUser(
                "b", new FieldSig(proxyB.ToTypeSig()), FieldAttributes.Private));
        });

        var candidates = context.Module.GetTypes()
            .Where(ReactorStructureDetector.IsDelegateProxy)
            .ToHashSet();
        var removable = RuntimeCleanupPass.ComputeUnreferencedProxies(context.Module, candidates);

        Assert.Equal(["ProxyC"], removable.Select(type => type.Name.String).Order());
    }

    [Fact]
    public void RenamingIsWithheldWithoutTheOptIn()
    {
        using var context = SyntheticContext.Build(BuildRenamableModule);

        var result = new SymbolRenamingPass().Run(context);

        Assert.Equal(0, result.Changes);
    }

    [Fact]
    public void RenamingRewritesGeneratedNamesAndDeclaresTheApiDelta()
    {
        using var context = SyntheticContext.Build(BuildRenamableModule);
        context.SetFact("options.renameSymbols", true);

        var result = new SymbolRenamingPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.True(result.Changes >= 2);
        var host = context.Module.GetTypes().Single(type => type.Name.StartsWith("ReactorType_"));
        Assert.Contains(host.Methods, method => method.Name.StartsWith("reactorMethod_"));
        Assert.Contains(host.Fields, field => field.Name.StartsWith("reactorField_"));
        // The readable public method keeps its own name even though its full name changed.
        Assert.Contains(host.Methods, method => method.Name == "DoWork");
        AssertWritesAndVerifies(context);
    }

    private static void BuildRenamableModule(ModuleDefUser module)
    {
        var type = new TypeDefUser("Synthetic", "aB3xYz9QmLp", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.NotPublic | TypeAttributes.Class
        };
        module.Types.Add(type);
        type.Fields.Add(new FieldDefUser(
            "vwAcYxvHwU", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Private));
        type.Methods.Add(NewVoidMethod(module, "kT7mNpQrStU", MethodAttributes.Assembly));
        type.Methods.Add(NewVoidMethod(module, "DoWork", MethodAttributes.Public));
    }

    private static MethodDefUser NewVoidMethod(ModuleDef module, string name, MethodAttributes access)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = access | MethodAttributes.Static,
            Body = new CilBody()
        };
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static TypeDefUser AddDeadProxy(ModuleDefUser module, string name)
    {
        var multicastDelegate = new TypeRefUser(
            module, "System", "MulticastDelegate", module.CorLibTypes.AssemblyRef);
        var proxy = new TypeDefUser("Synthetic", name, multicastDelegate)
        {
            Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed
        };
        module.Types.Add(proxy);
        proxy.Fields.Add(new FieldDefUser(
            "instance", new FieldSig(proxy.ToTypeSig()), FieldAttributes.Static | FieldAttributes.Assembly));
        return proxy;
    }

    private static void AssertWritesAndVerifies(ArtifactContext context)
    {
        var allowance = BuildAllowance(context);
        var path = Path.Combine(Path.GetTempPath(), $"ReactorUnpack.OptIn.{Guid.NewGuid():N}.dll");
        try
        {
            context.Module.Write(path);
            var verification = AssemblyVerifier.VerifyFile(
                path, context.OriginalIdentity, context.OriginalStructure, allowance);
            Assert.True(verification.Passed, string.Join("; ", verification.Diagnostics));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static RewriteAllowance BuildAllowance(ArtifactContext context)
    {
        context.TryGetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", out var removedMethods);
        context.TryGetFact<IReadOnlySet<string>>("cleanup.removedPublicApi", out var cleanupApi);
        context.TryGetFact<int>("cleanup.removedTypeCount", out var removedTypeCount);
        context.TryGetFact<int>("cleanup.removedFieldCount", out var removedFieldCount);
        context.TryGetFact<IReadOnlySet<string>>("rename.removedPublicApi", out var renameRemoved);
        context.TryGetFact<IReadOnlySet<string>>("rename.addedPublicApi", out var renameAdded);
        var removedApi = new HashSet<string>(StringComparer.Ordinal);
        if (cleanupApi is not null) removedApi.UnionWith(cleanupApi);
        if (renameRemoved is not null) removedApi.UnionWith(renameRemoved);
        return new RewriteAllowance(
            RemovedPublicApi: removedApi,
            RemovedMethodTokens: removedMethods,
            RemovedTypeCount: removedTypeCount,
            RemovedFieldCount: removedFieldCount,
            AddedPublicApi: renameAdded);
    }
}
