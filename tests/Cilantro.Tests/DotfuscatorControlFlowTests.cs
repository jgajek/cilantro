using Cilantro.Core;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorControlFlowTests
{
    [Theory]
    [InlineData(0, 0)]
    [InlineData(65535, -1)]
    [InlineData(32768, -32768)]
    [InlineData(int.MinValue, 0)]
    [InlineData(1592202677, 5557)]
    public void ShortStorageTruncationMatchesTheClr(int value, int expected)
    {
        using var context = Fixture(value);
        var method = Find(context);
        Assert.Equal(expected, Invoke(context));
        Assert.Equal(1, DotfuscatorControlFlowPass.Rewrite(method));
        Assert.Equal(expected, Invoke(context));
        Assert.Contains(method.Body.Instructions, i => i.IsStloc());
    }

    [Fact]
    public void DivisionAndAnAlternateEntryAreNotConfusedWithAConstantStore()
    {
        using var context = Fixture(123456);
        var method = Find(context);
        method.Body.Instructions.Insert(1, OpCodes.Ldc_I4_1.ToInstruction());
        method.Body.Instructions.Insert(2, OpCodes.Div.ToInstruction());
        var before = Invoke(context);
        Assert.Equal(1, DotfuscatorControlFlowPass.Rewrite(method));
        Assert.Equal(before, Invoke(context));

        using var alternate = Fixture(123456);
        var target = Find(alternate);
        // Two paths supply different stack values to the same store. The adjacent
        // literal is insufficient evidence for the value arriving on the branch.
        var store = target.Body.Instructions[1];
        target.Body.Instructions.Insert(0, OpCodes.Ldc_I4_2.ToInstruction());
        target.Body.Instructions.Insert(1, OpCodes.Br.ToInstruction(store));
        Assert.Equal(0, DotfuscatorControlFlowPass.Rewrite(target));
        Assert.Equal(2, Invoke(alternate));
    }

    [Fact]
    public void WiderLocalsAndAnAddressEnteredSeparatelyRemainUntouched()
    {
        using var context = Fixture(123456);
        var method = Find(context);
        method.Body.Variables[0].Type = context.Module.CorLibTypes.Int32;
        Assert.Equal(0, DotfuscatorControlFlowPass.Rewrite(method));
        method.Body.Variables[0].Type = context.Module.CorLibTypes.Int16;
        method.Body.Instructions.Insert(2, OpCodes.Br.ToInstruction(method.Body.Instructions[2]));
        Assert.Equal(0, DotfuscatorControlFlowPass.Rewrite(method));
    }

    private static ArtifactContext Fixture(int value) => SyntheticContext.Build(module =>
    {
        var type = SyntheticContext.AddType(module, "ShortReads");
        type.Attributes = TypeAttributes.Public;
        var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static)
            { Body = new CilBody { InitLocals = true } };
        type.Methods.Add(method);
        var local = new Local(module.CorLibTypes.Int16);
        method.Body.Variables.Add(local);
        foreach (var instruction in new[] { OpCodes.Ldc_I4.ToInstruction(value), OpCodes.Stloc.ToInstruction(local),
                     OpCodes.Ldloca.ToInstruction(local), OpCodes.Ldind_I2.ToInstruction(), OpCodes.Ret.ToInstruction() })
            method.Body.Instructions.Add(instruction);
    });

    private static MethodDef Find(ArtifactContext context) => context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read");

    private static int Invoke(ArtifactContext context)
    {
        // Execute only this benign synthetic ground truth.
        using var stream = new MemoryStream();
        context.Module.Write(stream);
        stream.Position = 0;
        var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), true);
        try { return (int)loader.LoadFromStream(stream).GetType("Synthetic.ShortReads")!.GetMethod("Read")!.Invoke(null, null)!; }
        finally { loader.Unload(); }
    }
}
