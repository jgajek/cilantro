using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class LoaderBodyElisionTests
{
    [Theory]
    [InlineData(false, false, false, true)]
    [InlineData(true, false, false, false)]
    [InlineData(false, true, false, false)]
    [InlineData(false, false, true, false)]
    public void BodyRemovalPreservesRequiredInitialization(bool writesLiveState, bool beforeFieldInit,
        bool throws, bool emptied)
    {
        using var context = Fixture(writesLiveState, beforeFieldInit, throws);
        var boot = Find(context, "Boot");
        var read = Find(context, "Read");
        var first = new StaticMachine(modelTypeInitialization: true);
        var second = new StaticMachine(modelTypeInitialization: true);
        first.Execute(boot);
        second.Execute(boot);
        var evidence = first.State.LoaderEvidence;
        Assert.True(evidence.Agrees(second.State.LoaderEvidence));
        context.SetFact("bootstrap.evidence", evidence);
        context.SetFact("method-protection.complete", true);
        ReadingMarker.Add(context.Module).Mark(read);
        context.SetFact(VirtualizationRebuildPass.AddedTypesFact, 1);
        context.SetFact(VirtualizationRebuildPass.AddedMethodsFact, ReadingMarker.AddedMethodCount);
        var initializer = boot.DeclaringType.FindStaticConstructor();
        var original = Cilantro.Core.Verification.MethodBodySnapshot.Capture(initializer);

        var result = new LoaderCallRecheckPass().Run(context);

        Assert.True(result.Status == PassStatus.Success, string.Join("; ", result.Diagnostics));
        Assert.Equal(emptied, EmptyMethodBodies.DoesNothing(boot));
        Assert.True(original.StructurallyEquals(initializer));
        Assert.Contains(context.Module.GlobalType.FindStaticConstructor().Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.ResolveMethodDef() == boot);
        if (emptied)
        {
            var after = new StaticMachine(modelTypeInitialization: true);
            Assert.True(after.Execute(boot).Succeeded);
            Assert.Equal(7, after.Execute(read).Value.AsInt32());
            Assert.Contains(result.Diagnostics, note => note.Contains("preserving their calls"));
        }
    }

    [Fact]
    public void ReconstructedBodiesRemainAvailableForAnalysis()
    {
        using var context = Fixture(false, false, false);
        var boot = Find(context, "Boot");
        var machine = new StaticMachine(modelTypeInitialization: true);
        Assert.True(machine.Execute(boot).Succeeded);
        context.SetFact("bootstrap.evidence", machine.State.LoaderEvidence);
        context.SetFact("method-protection.complete", true);
        var marker = ReadingMarker.Add(context.Module);
        marker.Mark(boot);
        marker.Mark(Find(context, "Read"));
        context.SetFact(VirtualizationRebuildPass.AddedTypesFact, 1);
        context.SetFact(VirtualizationRebuildPass.AddedMethodsFact, ReadingMarker.AddedMethodCount);

        var result = new LoaderCallRecheckPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.False(EmptyMethodBodies.DoesNothing(boot));
    }

    [Fact]
    public void CalleeInitializationStillBelongsToTheCallersBody()
    {
        using var context = Fixture(false, false, false);
        var boot = Find(context, "Boot");
        var caller = context.Module.GlobalType.FindStaticConstructor();
        var machine = new StaticMachine(modelTypeInitialization: true);
        Assert.True(machine.Execute(caller).Succeeded);
        var evidence = machine.State.LoaderEvidence;
        var state = "System.Int32 Synthetic.Runtime::State";
        Assert.Contains(state, evidence.EffectsOf(boot.MDToken.Raw).StaticFieldsWritten);
        Assert.DoesNotContain(state, evidence.EffectsOf(boot.MDToken.Raw).BodyStaticFieldsWritten!);
        Assert.Contains(state, evidence.EffectsOf(caller.MDToken.Raw).BodyStaticFieldsWritten!);
        Assert.True(evidence.EffectsOf(boot.MDToken.Raw).AllInvocationsCompleted);
    }

    [Fact]
    public void FailureBeforeAnyEffectIsNotForgottenByALaterSuccessfulCall()
    {
        using var context = Fixture(false, false, false);
        var boot = Find(context, "Boot");
        var machine = new StaticMachine();
        var original = boot.Body;
        boot.Body = new CilBody();
        boot.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
        boot.Body.Instructions.Add(OpCodes.Throw.ToInstruction());
        Assert.False(machine.Execute(boot).Succeeded);
        boot.Body = original;
        Assert.True(machine.Execute(boot).Succeeded);
        Assert.False(machine.State.LoaderEvidence.EffectsOf(boot.MDToken.Raw).AllInvocationsCompleted);
    }

    private static MethodDef Find(ArtifactContext context, string name) =>
        context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == name);

    private static ArtifactContext Fixture(bool writesLiveState, bool beforeFieldInit, bool throws) =>
        SyntheticContext.Build(module =>
        {
            var runtime = SyntheticContext.AddType(module, "Runtime");
            runtime.IsBeforeFieldInit = beforeFieldInit;
            var state = new FieldDefUser("State", new FieldSig(module.CorLibTypes.Int32),
                FieldAttributes.Static | FieldAttributes.Assembly);
            var unused = new FieldDefUser("Unused", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            runtime.Fields.Add(state);
            runtime.Fields.Add(unused);
            var initialize = Method(".cctor", module.CorLibTypes.Void);
            initialize.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
            initialize.Body.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction());
            initialize.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(state));
            initialize.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            runtime.Methods.Add(initialize);
            var boot = Method("Boot", module.CorLibTypes.Void);
            boot.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
            boot.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(writesLiveState ? state : unused));
            if (throws) boot.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            boot.Body.Instructions.Add((throws ? OpCodes.Throw : OpCodes.Ret).ToInstruction());
            runtime.Methods.Add(boot);
            var read = Method("Read", module.CorLibTypes.Int32);
            read.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(state));
            read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            runtime.Methods.Add(read);
            var entry = Method(".cctor", module.CorLibTypes.Void);
            entry.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
            entry.Body.Instructions.Add(OpCodes.Call.ToInstruction(boot));
            entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            module.GlobalType.Methods.Add(entry);
        });

    private static MethodDefUser Method(string name, TypeSig result) => new(name, MethodSig.CreateStatic(result),
        MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.Assembly) { Body = new CilBody() };
}
