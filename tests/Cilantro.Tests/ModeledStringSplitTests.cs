using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ModeledStringSplitTests
{
    [Theory]
    [InlineData("System.Runtime", 8, "b03f5f7f11d50a3a", false, 0, "a,,b,", "a||b|")]
    [InlineData("System.Runtime", 10, "b03f5f7f11d50a3a", false, 1, "a,,b,", "a|b")]
    [InlineData("System.Private.CoreLib", 10, "7cec85d7bea7798e", false, 2, " , a ,, ", "|a||")]
    [InlineData("System.Runtime", 8, "b03f5f7f11d50a3a", false, 3, " , a ,, ", "a")]
    [InlineData("mscorlib", 4, "b77a5c561934e089", true, 0, "a,,b,", "a||b|")]
    [InlineData("mscorlib", 4, "b77a5c561934e089", true, 1, "a,,b,", "a|b")]
    [InlineData("System.Runtime", 8, "b03f5f7f11d50a3a", true, 3, " , a ,, ", "a")]
    public void ExactCharacterOptionsOverloadsPreserveEmptyAndTrimBehavior(string name, int version, string token, bool array,
        int options, string input, string expected)
    {
        using var module = Build(name, version, token, array);
        var machine = new StaticMachine(); machine.State.RegisterModuleMetadata(module);
        Assert.True(machine.State.Heap.TryAllocateString(input, out var text));
        var first = machine.Execute(module.GlobalType.Methods[0], [text, StaticValue.FromInt32(options)]);
        var second = machine.Execute(module.GlobalType.Methods[0], [text, StaticValue.FromInt32(options)]);
        Assert.True(first.Succeeded, first.Diagnostic); Assert.True(second.Succeeded, second.Diagnostic);
        Assert.NotEqual(first.Value, second.Value);
        Assert.True(machine.State.Heap.TryGetLength(first.Value, out var length));
        var parts = Enumerable.Range(0, length).Select(index =>
        {
            Assert.True(machine.State.Heap.TryReadArray(first.Value, index, out var part));
            Assert.True(machine.State.Heap.TryGetString(part, out var value)); return value;
        });
        Assert.Equal(expected, string.Join('|', parts));
    }

    [Theory]
    [InlineData("System.Runtime", 8, "b03f5f7f11d50a3a", false, 4, false, false)]
    [InlineData("System.Runtime", 8, "b03f5f7f11d50a3a", false, -1, false, false)]
    [InlineData("mscorlib", 4, "b77a5c561934e089", true, 2, false, false)]
    [InlineData("mscorlib", 4, "b77a5c561934e089", false, 0, false, false)]
    [InlineData("System.Runtime", 8, "null", false, 0, false, false)]
    [InlineData("System.Runtime", 8, "b03f5f7f11d50a3a", false, 0, true, false)]
    [InlineData("System.Runtime", 8, "b03f5f7f11d50a3a", false, 1, false, true)]
    public void InvalidFlagsForgedScopesAndCountSignaturesAreRefused(string name, int version, string token, bool array,
        int options, bool foreignEnum, bool count)
    {
        using var module = Build(name, version, token, array, foreignEnum, count);
        var machine = new StaticMachine(); machine.State.RegisterModuleMetadata(module);
        Assert.True(machine.State.Heap.TryAllocateString("a,b", out var text));
        var result = machine.Execute(module.GlobalType.Methods[0], [text, StaticValue.FromInt32(options)]);
        Assert.False(result.Succeeded);
    }

    [Fact]
    public void AnUnchangedWholeStringRetainsItsInputIdentity()
    {
        using var module = Build("System.Runtime", 8, "b03f5f7f11d50a3a", false);
        var machine = new StaticMachine(); machine.State.RegisterModuleMetadata(module);
        Assert.True(machine.State.Heap.TryAllocateString("alpha", out var input));
        var result = machine.Execute(module.GlobalType.Methods[0], [input, StaticValue.FromInt32(0)]);
        Assert.True(result.Succeeded, result.Diagnostic);
        Assert.True(machine.State.Heap.TryReadArray(result.Value, 0, out var part));
        Assert.Equal(input, part);
    }

    [Fact]
    public void UnknownOptionsAreNotInterpretedAsZero()
    {
        using var module = Build("System.Runtime", 8, "b03f5f7f11d50a3a", false);
        var machine = new StaticMachine(); machine.State.RegisterModuleMetadata(module);
        Assert.True(machine.State.Heap.TryAllocateString("a,b", out var text));
        Assert.False(machine.Execute(module.GlobalType.Methods[0], [text, StaticValue.Unknown]).Succeeded);
    }

    private static ModuleDefUser Build(string name, int version, string token, bool array, bool foreignEnum = false, bool count = false)
    {
        var core = new AssemblyRefUser(new AssemblyNameInfo($"{name}, Version={version}.0.0.0, Culture=neutral, PublicKeyToken={token}"));
        var module = new ModuleDefUser("Split.dll", Guid.NewGuid(), core);
        new AssemblyDefUser("Split", new Version(1, 0)).Modules.Add(module);
        var method = new MethodDefUser("Split", MethodSig.CreateStatic(new SZArraySig(module.CorLibTypes.String), module.CorLibTypes.String, module.CorLibTypes.Int32),
            MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody() };
        module.GlobalType.Methods.Add(method);
        var il = method.Body.Instructions; il.Add(OpCodes.Ldarg_0.ToInstruction());
        if (array)
        {
            il.Add(OpCodes.Ldc_I4_1.ToInstruction()); il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Char.TypeDefOrRef));
            il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ldc_I4.ToInstruction(44)); il.Add(OpCodes.Stelem_I2.ToInstruction());
        }
        else il.Add(OpCodes.Ldc_I4.ToInstruction(44));
        il.Add(OpCodes.Ldarg_1.ToInstruction());
        var options = new ValueTypeSig(new TypeRefUser(module, "System", "StringSplitOptions", foreignEnum ? new AssemblyRefUser("Foreign") : core));
        il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Split", MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.String),
            array ? new SZArraySig(module.CorLibTypes.Char) : module.CorLibTypes.Char, count ? module.CorLibTypes.Int32 : options), module.CorLibTypes.String.TypeDefOrRef)));
        il.Add(OpCodes.Ret.ToInstruction());
        return module;
    }
}
