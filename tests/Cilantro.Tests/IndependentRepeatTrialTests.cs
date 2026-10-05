using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class IndependentRepeatTrialTests
{
    [Fact]
    public void RepeatComparisonRetainsEscapedFirstCallArguments()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var state = new FieldDefUser("State", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            host.Fields.Add(state);
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void,
                new SZArraySig(module.CorLibTypes.Byte)), MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            var done = OpCodes.Ret.ToInstruction();
            foreach (var instruction in new[] { OpCodes.Ldsfld.ToInstruction(state), OpCodes.Brtrue.ToInstruction(done),
                OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(state),
                OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(),
                OpCodes.Stelem_I1.ToInstruction(), done }) method.Body.Instructions.Add(instruction);
            host.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Run");
        var rebuilt = new CilBody();
        foreach (var instruction in method.Body.Instructions)
            rebuilt.Instructions.Add(new Instruction(instruction.OpCode, instruction.Operand));
        rebuilt.Instructions[1].Operand = rebuilt.Instructions[^1];
        rebuilt.Instructions[6].OpCode = OpCodes.Ldc_I4_2;
        var result = RebuiltMethodTrial.Compare(context, method, rebuilt, 2, warmSelected: true);
        Assert.Equal(DevirtualizationCheck.Disagreed, result.Verdict);
        Assert.Equal("first-call argument 0", Assert.Single(result.DifferingRoots!));
    }

    [Fact]
    public void OriginalWarmupCannotSubstituteForIndependentlyEvolvedState()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var state = new FieldDefUser("State", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            host.Fields.Add(state);
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            var done = OpCodes.Ret.ToInstruction();
            foreach (var instruction in new[] { OpCodes.Ldsfld.ToInstruction(state), OpCodes.Brtrue.ToInstruction(done),
                OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(state), done })
                method.Body.Instructions.Add(instruction);
            host.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Run");
        var original = method.Body;
        var rebuilt = new CilBody();
        var done = OpCodes.Ret.ToInstruction();
        foreach (var instruction in new[] { OpCodes.Ldsfld.ToInstruction((IField)original.Instructions[0].Operand),
            OpCodes.Brtrue.ToInstruction(done), OpCodes.Ldc_I4_2.ToInstruction(),
            OpCodes.Stsfld.ToInstruction((IField)original.Instructions[3].Operand), done })
            rebuilt.Instructions.Add(instruction);
        Assert.Equal(DevirtualizationCheck.Agreed,
            RebuiltMethodTrial.Compare(context, method, rebuilt, 0, warmOriginal: true).Verdict);
        Assert.Equal(DevirtualizationCheck.Disagreed,
            RebuiltMethodTrial.Compare(context, method, rebuilt, 0, warmSelected: true).Verdict);
        Assert.Same(original, method.Body);
        Assert.Throws<ArgumentException>(() => RebuiltMethodTrial.Compare(context, method, rebuilt, 0,
            warmOriginal: true, warmSelected: true));
    }

    [Fact]
    public void FailedSelectedPreludeCannotBecomeAMatchingRepeat()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            host.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Run");
        var original = method.Body;
        var rebuilt = new CilBody();
        rebuilt.Instructions.Add(OpCodes.Ldnull.ToInstruction());
        rebuilt.Instructions.Add(OpCodes.Throw.ToInstruction());
        var result = RebuiltMethodTrial.Compare(context, method, rebuilt, 0, warmSelected: true);
        Assert.Equal(DevirtualizationCheck.NotMade, result.Verdict);
        Assert.Contains("selected-body warm-up did not complete", result.Detail);
        Assert.Same(original, method.Body);
    }
}
