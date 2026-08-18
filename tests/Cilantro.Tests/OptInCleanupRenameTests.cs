using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;

namespace Cilantro.Tests;

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
        DeclareProxyOrphaned(context, "DeadProxy");

        var result = new RuntimeCleanupPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.DoesNotContain(context.Module.GetTypes(), type => type.Name == "DeadProxy");
        AssertWritesAndVerifies(context);
    }

    [Fact]
    public void CleanupKeepsDeadCodeRecoveryCannotAccountFor()
    {
        using var context = SyntheticContext.Build(module =>
        {
            AddDeadProxy(module, "UnusedByTheProgram");
            SyntheticContext.AddType(module, "Host");
        });
        context.SetFact("options.removeRuntime", true);

        var result = new RuntimeCleanupPass().Run(context);

        Assert.Equal(0, result.Changes);
        Assert.Contains(context.Module.GetTypes(), type => type.Name == "UnusedByTheProgram");
    }

    [Fact]
    public void CleanupKeepsProxyThatSurvivingCodeReferences()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var proxy = AddDeadProxy(module, "LiveProxy");
            var host = SyntheticContext.AddType(module, "Host");
            // The host has to survive cleanup itself for its reference to mean anything, and only
            // an externally visible type is kept without a call reaching it.
            host.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            host.Fields.Add(new FieldDefUser(
                "handle", new FieldSig(proxy.ToTypeSig()), FieldAttributes.Private));
        });
        context.SetFact("options.removeRuntime", true);
        DeclareProxyOrphaned(context, "LiveProxy");

        new RuntimeCleanupPass().Run(context);

        Assert.Contains(context.Module.GetTypes(), type => type.Name == "LiveProxy");
        Assert.Contains(context.Module.GetTypes(), type => type.Name == "Host");
    }

    [Fact]
    public void CleanupRemovesAnOrphanedMethodFromASurvivingType()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            host.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            host.Methods.Add(NewVoidMethod(module, "Entry", MethodAttributes.Public));
            host.Methods.Add(NewVoidMethod(module, "BypassedForwarder", MethodAttributes.Assembly));
            host.Methods.Add(NewVoidMethod(module, "UnusedHelper", MethodAttributes.Assembly));
        });
        context.SetFact("options.removeRuntime", true);
        RecoveryOrphans.Declare(context, FindMethod(context, "BypassedForwarder"));

        var result = new RuntimeCleanupPass().Run(context);

        Assert.Equal(1, result.Changes);
        var host = context.Module.GetTypes().Single(type => type.Name == "Host");
        Assert.DoesNotContain(host.Methods, method => method.Name == "BypassedForwarder");
        // The program's own unused helper is left exactly where it was.
        Assert.Contains(host.Methods, method => method.Name == "UnusedHelper");
        AssertWritesAndVerifies(context);
    }

    [Fact]
    public void CleanupKeepsAnOrphanedMethodSurvivingCodeStillCalls()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            host.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            var forwarder = NewVoidMethod(module, "StillCalled", MethodAttributes.Assembly);
            host.Methods.Add(forwarder);
            // A virtual method is never removed, so it survives and its call has to stay resolvable.
            var caller = NewVoidMethod(module, "Caller", MethodAttributes.Assembly);
            caller.Attributes = MethodAttributes.Assembly | MethodAttributes.Virtual;
            caller.MethodSig = MethodSig.CreateInstance(module.CorLibTypes.Void);
            caller.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(forwarder));
            host.Methods.Add(caller);
        });
        context.SetFact("options.removeRuntime", true);
        RecoveryOrphans.Declare(context, FindMethod(context, "StillCalled"));

        new RuntimeCleanupPass().Run(context);

        var host = context.Module.GetTypes().Single(type => type.Name == "Host");
        Assert.Contains(host.Methods, method => method.Name == "StillCalled");
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
        var removable = RuntimeCleanupPass.ComputeUnreferenced(context.Module, candidates);

        Assert.Equal(["ProxyC"], removable.Select(type => type.Name.String).Order());
    }

    [Fact]
    public void RenamingIsWithheldWhereTheRunDidNotAskForIt()
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
        var host = context.Module.GetTypes().Single(type => type.Name.StartsWith("GeneratedType_"));
        Assert.Contains(host.Methods, method => method.Name.StartsWith("generatedMethod_"));
        Assert.Contains(host.Fields, field => field.Name.StartsWith("generatedField_"));
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
        proxy.Methods.Add(NewVoidMethod(module, "Dispatch", MethodAttributes.Assembly));
        return proxy;
    }

    /// <summary>
    /// Stands in for the pass that would have redirected every call through the proxy.
    /// </summary>
    private static void DeclareProxyOrphaned(ArtifactContext context, string proxyName) =>
        RecoveryOrphans.Declare(
            context,
            context.Module.GetTypes().Single(type => type.Name == proxyName).Methods);

    private static MethodDef FindMethod(ArtifactContext context, string name) =>
        context.Module.GetTypes().SelectMany(type => type.Methods)
            .Single(method => method.Name == name);

    /// <summary>
    /// Asserts both halves of the pipeline's gate: the module changed only as declared, and the
    /// file is the module.
    /// </summary>
    private static void AssertWritesAndVerifies(ArtifactContext context)
    {
        var inMemory = AssemblyVerifier.Verify(
            context.Module, context.OriginalIdentity, context.OriginalStructure, BuildAllowance(context));
        Assert.True(inMemory.Passed, string.Join("; ", inMemory.Diagnostics));

        var shape = ModuleShape.Capture(context.Module);
        var path = Path.Combine(Path.GetTempPath(), $"Cilantro.OptIn.{Guid.NewGuid():N}.dll");
        try
        {
            context.Module.Write(path);
            var roundTrip = AssemblyVerifier.VerifyRoundTrip(path, shape);
            Assert.True(roundTrip.Passed, string.Join("; ", roundTrip.Diagnostics));
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
