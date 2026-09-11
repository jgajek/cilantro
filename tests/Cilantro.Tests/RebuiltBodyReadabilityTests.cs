using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

/// <summary>
/// Covers the two things done to a rebuilt body after it is written: cleaning it up, and saying
/// what it does.
/// </summary>
/// <remarks>
/// Both exist because of where the rebuild sits. It runs near the end of a run, so a body that
/// arrives there has had none of the folding every other body in the module got, and any account
/// written of it before renaming names members the cleaned copy does not contain. Those were real
/// defects rather than hypothetical ones: the rebuilt body was the only body in the assembly no
/// pass had ever looked at, and the report named the rebuilt method by a name renaming had already
/// replaced, so searching the cleaned copy for it found nothing.
/// </remarks>
public sealed class RebuiltBodyReadabilityTests
{
    /// <summary>
    /// The calls a lifted body makes to helpers that answer the same thing every time are folded,
    /// and the branches that then read a constant go with them.
    /// </summary>
    [Fact]
    public void ARebuiltBodyGetsTheFoldingEveryOtherBodyAlreadyHad()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            host.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            var predicate = AlwaysTrue(module, "OpaquePredicate");
            host.Methods.Add(predicate);
            host.Methods.Add(Branches(module, "WasVirtualized", predicate));
        });
        Mark(context, "WasVirtualized");

        var result = new RebuiltBodyCleanupPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        var body = Find(context, "WasVirtualized").Body;
        Assert.DoesNotContain(
            body.Instructions,
            instruction => instruction.Operand is IMethod called &&
                called.Name == "OpaquePredicate");
        Assert.True(
            context.TryGetFact<int>(RebuiltBodyCleanupPass.FoldedFact, out var folded) && folded == 1,
            "The one call to a constant helper should have been folded.");
    }

    /// <summary>
    /// A body nothing else in the module holds is left alone rather than reported as cleaned, so a
    /// run says it changed something only where it did.
    /// </summary>
    [Fact]
    public void ARunThatBuiltNothingHasNothingToCleanUp()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            host.Methods.Add(Empty(module, "Ordinary"));
        });

        var result = new RebuiltBodyCleanupPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
    }

    /// <summary>
    /// The account names the framework members the body reaches, following the forwarders the
    /// protector left between the two. Those names are the way into a lifted body: a protector
    /// renames what it generates and cannot rename the framework, so they survive when nothing
    /// else does.
    /// </summary>
    [Fact]
    public void TheAccountNamesWhatTheBodyReachesThroughItsForwarders()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            host.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            var forwarder = Forwards(module, "Forwarder", "System", "GC", "Collect");
            host.Methods.Add(forwarder);
            host.Methods.Add(Reaches(module, "WasVirtualized", forwarder));
        });
        Mark(context, "WasVirtualized");

        new RebuiltBodyDigestPass().Run(context);

        var digest = Assert.Single(Digest(context));
        Assert.Contains("GC.Collect", digest.Reaches);
        // The forwarder itself is not named: it is generated, and what a reader wants is the
        // framework member on the far side of it.
        Assert.DoesNotContain("Host.Forwarder", digest.Reaches);
    }

    /// <summary>
    /// That nothing calls a rebuilt method is said outright. It is the usual outcome and it is a
    /// result rather than a fault — recovery replaces the code that needed the method, so the
    /// caller becomes dead and is removed — but a reader who is not told concludes the body was
    /// never written.
    /// </summary>
    [Fact]
    public void ARebuiltMethodNothingCallsIsSaidToBeOne()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            host.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            host.Methods.Add(Empty(module, "WasVirtualized"));
            host.Methods.Add(Calls(module, "StillCalled", "WasVirtualized", host));
        });
        Mark(context, "WasVirtualized");

        new RebuiltBodyDigestPass().Run(context);

        var orphaned = Assert.Single(Digest(context));
        Assert.False(orphaned.Reachable);

        // Made public, the same method is reachable, and the account says so instead.
        Find(context, "WasVirtualized").Attributes =
            MethodAttributes.Public | MethodAttributes.Static;
        new RebuiltBodyDigestPass().Run(context);
        Assert.True(Assert.Single(Digest(context)).Reachable);
    }

    /// <summary>
    /// The account goes where the person reading the body will see it, which is the attribute a
    /// decompiler prints directly above the method rather than a file beside the assembly.
    /// </summary>
    [Fact]
    public void TheAccountIsPutOnTheMethodWhereADecompilerShowsIt()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            host.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            var forwarder = Forwards(module, "Forwarder", "System", "GC", "Collect");
            host.Methods.Add(forwarder);
            host.Methods.Add(Reaches(module, "WasVirtualized", forwarder));
        });
        Mark(context, "WasVirtualized");
        var marker = ReadingMarkerOn(context, "WasVirtualized");

        new RebuiltBodyDigestPass().Run(context);

        var said = marker.ConstructorArguments[0].Value.ToString()!;
        // The warning still comes first: what the body is has to be read before what it does.
        Assert.StartsWith("CILantro built this body", said, StringComparison.Ordinal);
        Assert.Contains("GC.Collect", said, StringComparison.Ordinal);
        Assert.Contains("Nothing in the cleaned copy calls it", said, StringComparison.Ordinal);
    }

    /// <summary>
    /// A rebuilt body is named for the framework it reaches rather than numbered. It is the method
    /// a reader opened the file for and the longest thing in it, so <c>generatedMethod_0075</c> is
    /// the worst place in the assembly for a number.
    /// </summary>
    [Fact]
    public void ARebuiltBodyIsNamedForTheFrameworkItReaches()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            host.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            var forwarder = Forwards(module, "xQ7mZ2pR", "System.Security.Cryptography", "Aes",
                "Create");
            host.Methods.Add(forwarder);
            host.Methods.Add(Reaches(module, "aB3dE4fG", forwarder));
        });
        Mark(context, "aB3dE4fG");
        context.SetFact("options.renameSymbols", true);

        new SymbolRenamingPass().Run(context);

        var renamed = context.Module.GetTypes().SelectMany(type => type.Methods)
            .Select(method => method.Name.String)
            .ToArray();
        Assert.Contains("RebuiltFromVirtualMachineCryptography", renamed);
        // The forwarder beside it is still named for the one member it calls, as before.
        Assert.Contains("Aes_Create", renamed);
    }

    private static IReadOnlyList<RebuiltMethodReport> Digest(ArtifactContext context) =>
        context.TryGetFact<IReadOnlyList<RebuiltMethodReport>>(
            RebuiltBodyDigestPass.DigestFact, out var digest) && digest is not null
            ? digest
            : [];

    /// <summary>Stands in for the rebuild, which is not what these tests are about.</summary>
    private static void Mark(ArtifactContext context, string name)
    {
        var method = Find(context, name);
        context.SetFact<IReadOnlySet<uint>>(
            VirtualizationRebuildPass.RebuiltFact,
            new HashSet<uint> { method.MDToken.Raw });
        ReadingMarker.Add(context.Module).Mark(method);
    }

    private static CustomAttribute ReadingMarkerOn(ArtifactContext context, string name) =>
        Find(context, name).CustomAttributes.Single(attribute =>
            attribute.AttributeType?.Name == "RebuiltFromReadingAttribute");

    private static MethodDef Find(ArtifactContext context, string name) => context.Module.GetTypes()
        .SelectMany(type => type.Methods)
        .Single(method => method.Name == name);

    /// <summary>A body shaped the way a lift leaves one: a helper call deciding a branch.</summary>
    private static MethodDefUser Branches(ModuleDef module, string name, MethodDef helper)
    {
        var method = Empty(module, name);
        var ret = method.Body.Instructions[0];
        method.Body.Instructions.Clear();
        method.Body.Instructions.Add(OpCodes.Call.ToInstruction(helper));
        method.Body.Instructions.Add(OpCodes.Brtrue.ToInstruction(ret));
        method.Body.Instructions.Add(ret);
        return method;
    }

    /// <summary>A body that reaches the framework only through the forwarder in front of it.</summary>
    private static MethodDefUser Reaches(ModuleDef module, string name, MethodDef forwarder)
    {
        var method = Empty(module, name);
        method.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(forwarder));
        return method;
    }

    private static MethodDefUser Calls(
        ModuleDef module,
        string name,
        string target,
        TypeDef host)
    {
        var method = Empty(module, name);
        method.Body.Instructions.Insert(
            0,
            OpCodes.Call.ToInstruction(host.Methods.Single(item => item.Name == target)));
        return method;
    }

    private static MethodDefUser Forwards(
        ModuleDef module,
        string name,
        string @namespace,
        string type,
        string member)
    {
        var method = Empty(module, name);
        method.Body.Instructions.Clear();
        method.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(
            module,
            member,
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            module.CorLibTypes.GetTypeRef(@namespace, type))));
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return method;
    }

    private static MethodDefUser AlwaysTrue(ModuleDef module, string name)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Boolean))
        {
            Attributes = MethodAttributes.Assembly | MethodAttributes.Static,
            ImplAttributes = MethodImplAttributes.IL | MethodImplAttributes.Managed,
            Body = new CilBody()
        };
        method.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
        method.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
        method.Body.Instructions.Add(OpCodes.Ceq.ToInstruction());
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return method;
    }

    private static MethodDefUser Empty(ModuleDef module, string name)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Assembly | MethodAttributes.Static,
            ImplAttributes = MethodImplAttributes.IL | MethodImplAttributes.Managed,
            Body = new CilBody()
        };
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return method;
    }
}
