using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class NativeArrayIndexTests
{
    [Theory]
    [InlineData(4, false)]
    [InlineData(8, false)]
    [InlineData(4, true)]
    [InlineData(8, true)]
    public void NativeLengthsAndIndicesReachTheCorrectElement(int pointerSize, bool address)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody() };
            module.GlobalType.Methods.Add(method);
            var il = method.Body.Instructions;
            il.Add(OpCodes.Ldc_I4_2.ToInstruction());
            il.Add(OpCodes.Conv_I.ToInstruction());
            il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
            il.Add(OpCodes.Dup.ToInstruction());
            il.Add(OpCodes.Ldc_I4_1.ToInstruction());
            il.Add(OpCodes.Conv_Ovf_I.ToInstruction());
            il.Add(OpCodes.Ldc_I4.ToInstruction(37));
            il.Add(OpCodes.Stelem_I4.ToInstruction());
            il.Add(OpCodes.Ldc_I4_1.ToInstruction());
            il.Add(OpCodes.Conv_I.ToInstruction());
            if (address)
            {
                il.Add(OpCodes.Ldelema.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
                il.Add(OpCodes.Ldind_I4.ToInstruction());
            }
            else il.Add(OpCodes.Ldelem_I4.ToInstruction());
            il.Add(OpCodes.Ret.ToInstruction());
        });
        var machine = new StaticMachine();
        machine.State.RegisterPointerSize(pointerSize);
        var result = machine.Execute(context.Module.GlobalType.Methods.Single(method => method.Name == "Read"));
        Assert.True(result.Succeeded, result.Diagnostic);
        Assert.Equal(37, result.Value.AsInt32());
    }

    [Theory]
    [InlineData(4294967296L)]
    [InlineData(-4294967296L)]
    public void LargeNativeIndicesCannotAliasElementZero(long index)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody() };
            module.GlobalType.Methods.Add(method);
            method.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
            method.Body.Instructions.Add(OpCodes.Ldc_I8.ToInstruction(index));
            method.Body.Instructions.Add(OpCodes.Conv_I.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ldelem_I4.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var result = new StaticMachine().Execute(context.Module.GlobalType.Methods.Single(method => method.Name == "Read"));
        Assert.False(result.Succeeded);
        Assert.Contains("bounded integer range", result.Diagnostic);
    }
}
