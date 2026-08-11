using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers the removal of type initializers that recovery emptied.
/// </summary>
/// <remarks>
/// This is the one member cleanup takes without asking whether anything reaches it, so the two
/// halves that replace reachability are what the tests pin down. Emptiness has to be read off the
/// body, which is what keeps an initializer Reactor merely prepended to — the program's own code
/// still sitting underneath — out of reach. Attribution has to be required all the same, or an
/// initializer the program wrote empty would go too, and the point of the rule is that recovery
/// only undoes what it did.
/// </remarks>
public sealed class EmptyTypeInitializerTests
{
    [Fact]
    public void PaddingAndAReturnDoNothing()
    {
        using var context = SyntheticContext.Build(module =>
            Host(module, initializer: [OpCodes.Nop, OpCodes.Nop, OpCodes.Ret]));

        Assert.True(EmptyTypeInitializers.DoesNothing(Initializer(context)));
    }

    [Fact]
    public void AnInitializerThatStillStoresSomethingDoesNot()
    {
        using var context = SyntheticContext.Build(module =>
            Host(module, initializer: [OpCodes.Nop, OpCodes.Ldc_I4_1, OpCodes.Pop, OpCodes.Ret]));

        Assert.False(EmptyTypeInitializers.DoesNothing(Initializer(context)));
    }

    /// <summary>
    /// The case the corpus is full of: the type is alive, so the runtime would run its initializer,
    /// and the initializer has nothing left to run.
    /// </summary>
    [Fact]
    public void AnEmptyInitializerGoesEvenThoughItsTypeIsInUse()
    {
        using var context = Cleanable(initializer: [OpCodes.Nop, OpCodes.Ret]);
        Declare(context);

        var result = new RuntimeCleanupPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Null(Type(context).FindStaticConstructor());
        Assert.Contains(Type(context).Methods, method => method.Name == "Used");
    }

    [Fact]
    public void AnEmptyInitializerStaysWhenNothingRecoveryDidExplainsIt()
    {
        using var context = Cleanable(initializer: [OpCodes.Nop, OpCodes.Ret]);

        var result = new RuntimeCleanupPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.NotNull(Type(context).FindStaticConstructor());
    }

    [Fact]
    public void AnInitializerReactorOnlyPrependedToStaysWithTheProgramsCodeInIt()
    {
        using var context = Cleanable(
            initializer: [OpCodes.Nop, OpCodes.Ldc_I4_1, OpCodes.Pop, OpCodes.Ret]);
        Declare(context);

        var result = new RuntimeCleanupPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.NotNull(Type(context).FindStaticConstructor());
    }

    /// <summary>
    /// A module whose only interesting member is a live type carrying the given initializer.
    /// </summary>
    private static ArtifactContext Cleanable(OpCode[] initializer)
    {
        var context = SyntheticContext.Build(module => Host(module, initializer));
        context.SetFact("options.removeRuntime", true);
        context.SetFact("method-protection.complete", true);
        return context;
    }

    private static void Declare(ArtifactContext context) =>
        RecoveryOrphans.Declare(context, Initializer(context));

    private static void Host(ModuleDefUser module, OpCode[] initializer)
    {
        var host = new TypeDefUser("Synthetic", "Host", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Class
        };
        module.Types.Add(host);

        // Public, so reachability roots it and the type counts as in use. That is what makes the
        // initializer reachable and so the case worth testing.
        var used = new MethodDefUser(
            "Used",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        used.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        host.Methods.Add(used);

        var cctor = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig |
            MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        foreach (var opCode in initializer)
            cctor.Body.Instructions.Add(opCode.ToInstruction());
        host.Methods.Add(cctor);
    }

    private static TypeDef Type(ArtifactContext context) =>
        context.Module.GetTypes().Single(type => type.Name == "Host");

    private static MethodDef Initializer(ArtifactContext context) =>
        Type(context).FindStaticConstructor();
}
