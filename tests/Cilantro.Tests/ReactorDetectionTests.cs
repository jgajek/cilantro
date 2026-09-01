using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Tests;

/// <summary>
/// Covers the confidence score that decides whether a module is treated as .NET Reactor's work.
/// </summary>
/// <remarks>
/// The score is the gate in front of everything else. Passes that interpret a Reactor loader ask
/// whether the module is Reactor before they run, so a module that scores under the gate is not
/// merely labelled differently: its loader is never interpreted, the state that would prove its
/// resolver offsets is never captured, and the run ends with no cleaned copy. That makes the
/// boundary itself worth pinning, in both directions, rather than only the comfortable cases well
/// above it.
/// </remarks>
public sealed class ReactorDetectionTests
{
    /// <summary>
    /// The weights were chosen so that a protected-string resolver, the dispatchers that come with
    /// it and an encrypted resource add up to exactly the gate. A real sample landed on that sum and
    /// was rejected, because adding the weights as binary fractions came out a hair under the figure
    /// they were written as. The sum has to be the one the weights read as.
    /// </summary>
    [Fact]
    public void AResolverWithDispatchersAndEncryptedResourcesLandsExactlyOnTheGate()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Protected");
            type.Methods.Add(Dispatcher(module, "FirstDispatcher"));
            type.Methods.Add(Dispatcher(module, "SecondDispatcher"));
            type.Methods.Add(StringResolver(module, "Resolve"));
            module.Resources.Add(Encrypted("alpha", seed: 1));
            module.Resources.Add(Encrypted("beta", seed: 2));
        });

        var facts = ReactorStructureDetector.Analyze(context.Module);

        Assert.Equal(0.55, facts.Confidence);
        Assert.True(facts.IsReactor);
        Assert.Contains("protected-strings", facts.CapabilityNames);
        Assert.Contains("dispatcher-control-flow", facts.CapabilityNames);
        Assert.Contains("resource-container", facts.CapabilityNames);

        // No stubs, no proxies and no reference to the JIT, so there is nothing to say which of
        // Reactor's generations built this. Being unable to name the generation is not a reason to
        // doubt the protector.
        Assert.Equal("unknown", facts.Generation);
    }

    /// <summary>
    /// The other side of the same boundary, so that a later reader cannot make the case above pass
    /// by lowering the gate instead of by fixing the arithmetic.
    /// </summary>
    [Fact]
    public void AResolverAndItsDispatchersAloneStayUnderTheGate()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Protected");
            type.Methods.Add(Dispatcher(module, "FirstDispatcher"));
            type.Methods.Add(Dispatcher(module, "SecondDispatcher"));
            type.Methods.Add(StringResolver(module, "Resolve"));
        });

        var facts = ReactorStructureDetector.Analyze(context.Module);

        Assert.Equal(0.45, facts.Confidence);
        Assert.False(facts.IsReactor);
    }

    /// <summary>
    /// A switch over three or more arms, which is what the detector counts as a dispatcher.
    /// </summary>
    private static MethodDefUser Dispatcher(ModuleDefUser module, string name)
    {
        var method = new MethodDefUser(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };

        var first = Instruction.Create(OpCodes.Nop);
        var second = Instruction.Create(OpCodes.Nop);
        var third = Instruction.Create(OpCodes.Ret);
        var instructions = method.Body.Instructions;
        instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        instructions.Add(Instruction.Create(OpCodes.Switch, new[] { first, second, third }));
        instructions.Add(first);
        instructions.Add(second);
        instructions.Add(third);
        return method;
    }

    /// <summary>
    /// Reactor's protected-string resolver shape: a string taken from a manifest resource by number.
    /// </summary>
    private static MethodDefUser StringResolver(ModuleDefUser module, string name)
    {
        var assembly = new TypeRefUser(
            module, "System.Reflection", "Assembly", module.CorLibTypes.AssemblyRef);
        var stream = new MemberRefUser(
            module,
            "GetManifestResourceStream",
            MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.String),
            assembly);
        var method = new MethodDefUser(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Int32),
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };

        var instructions = method.Body.Instructions;
        instructions.Add(Instruction.Create(OpCodes.Ldnull));
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "table"));
        instructions.Add(Instruction.Create(OpCodes.Callvirt, stream));
        instructions.Add(Instruction.Create(OpCodes.Pop));
        instructions.Add(Instruction.Create(OpCodes.Ldnull));
        instructions.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    /// <summary>
    /// Bytes with no structure left in them, which is what an encrypted bundle looks like from
    /// outside. Seeded so the entropy is the same on every run.
    /// </summary>
    private static EmbeddedResource Encrypted(string name, int seed)
    {
        var data = new byte[4096];
        new Random(seed).NextBytes(data);
        return new EmbeddedResource(name, data, ManifestResourceAttributes.Public);
    }
}
