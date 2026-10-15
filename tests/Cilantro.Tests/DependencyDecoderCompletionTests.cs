using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DependencyDecoderCompletionTests
{
    [Fact]
    public void AddedDataFieldsRequireExactDeclarationAccounting()
    {
        using var context = SyntheticContext.Build(module => SyntheticContext.AddType(module, "Holder"));
        var owner = context.Module.GetTypes().Single(t => t.Name == "Holder");
        owner.Fields.Add(new FieldDefUser("Data", new FieldSig(context.Module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Private));
        Assert.False(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed);
        var allowance = new RewriteAllowance(AddedFieldCount: 1);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, allowance).Passed);
        owner.Fields.Add(new FieldDefUser("Undeclared", new FieldSig(context.Module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Private));
        Assert.False(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, allowance).Passed);
    }

    [Fact]
    public void LargeBenignDataHolderRunsOnClr()
    {
        // Only this generated, benign fixture is CLR-executed. Corpus samples are
        // validated through static analysis and the bounded interpreter.
        var bytes = Enumerable.Range(0, 288256).Select(i => (byte)i).ToArray();
        using var context = SyntheticContext.Build(module => module.Types.Add(DependencyDecoderCompletionPass.BuildHolder(module,
            new ClosedDependencyDecoder.Result(bytes, [], new HashSet<MethodDef>(), 0))));
        var loader = new System.Runtime.Loader.AssemblyLoadContext("BenignDependencyHolder", isCollectible: true);
        try
        {
            using var image = new MemoryStream(context.OriginalBytes);
            var assembly = loader.LoadFromStream(image);
            var method = assembly.GetType("Cilantro.Recovered.RecoveredDependency")!.GetMethod("Open",
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!;
            using var stream = (MemoryStream)method.Invoke(null, [null])!;
            Assert.Equal(bytes, stream.ToArray());
        }
        finally { loader.Unload(); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4096)]
    public void SerializedReplacementReturnsFreshExactBytes(int length)
    {
        var bytes = Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
        using var context = SyntheticContext.Build(module =>
        {
            var shared = SyntheticContext.AddType(module, "SharedLookup");
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Assembly);
            shared.Fields.Add(field);
            var ctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            shared.Methods.Add(ctor);
            foreach (var i in new[] { OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Stsfld.ToInstruction(field), OpCodes.Ret.ToInstruction() }) ctor.Body.Instructions.Add(i);
            module.Types.Add(DependencyDecoderCompletionPass.BuildHolder(module,
                new ClosedDependencyDecoder.Result(bytes, [shared], new HashSet<MethodDef>(), 0)));
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Open");
        Assert.True(AssemblyVerifier.Verify(context.Module).Passed);
        var machine = new StaticMachine(BootstrapMachine.Limits(10000), StaticIntrinsicRegistry.CreateDefault(), modelTypeInitialization: true);
        var first = machine.Execute(method, [StaticValue.Null]);
        Assert.True(first.Succeeded, first.Diagnostic);
        Assert.Equal(7, machine.State.ReadStaticField(context.Module.GetTypes().Single(t => t.Name == "SharedLookup").Fields.Single()).AsInt32());
        Assert.True(machine.State.Heap.TryGetModelValue<StaticValue>(first.Value, "Buffer", out var firstBuffer));
        var actual = new byte[bytes.Length];
        Assert.True(machine.State.Heap.TryReadBytes(firstBuffer, 0, actual));
        Assert.Equal(bytes, actual);
        var second = machine.Execute(method, [StaticValue.Null]);
        Assert.True(second.Succeeded, second.Diagnostic);
        Assert.True(machine.State.Heap.TryGetModelValue<StaticValue>(second.Value, "Buffer", out var secondBuffer));
        Assert.NotEqual(firstBuffer, secondBuffer);
        Assert.True(machine.State.Heap.TryReadBytes(secondBuffer, 0, actual));
        Assert.Equal(bytes, actual);
    }

    [Theory]
    [InlineData("direct", true)]
    [InlineData("duplicate-cast", true)]
    [InlineData("position", false)]
    [InlineData("stored", false)]
    [InlineData("entry", false)]
    [InlineData("foreign", false)]
    public void OnlyPermitsImmediateScopedToArrayConsumption(string variant, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Caller");
            var stream = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
            var memory = variant == "foreign" ? new TypeRefUser(module, "System.IO", "MemoryStream", new AssemblyRefUser("Foreign"))
                : module.CorLibTypes.GetTypeRef("System.IO", "MemoryStream");
            var decode = new MethodDefUser("Decode", MethodSig.CreateStatic(stream.ToTypeSig()))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
            decode.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); decode.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); owner.Methods.Add(decode);
            var caller = new MethodDefUser("Call", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(caller);
            var call = OpCodes.Call.ToInstruction(decode);
            var cast = OpCodes.Castclass.ToInstruction(memory);
            var il = caller.Body.Instructions;
            if (variant == "entry") { il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Br.ToInstruction(cast)); }
            il.Add(call);
            if (variant == "stored")
            {
                var local = new Local(stream.ToTypeSig()); caller.Body.Variables.Add(local);
                il.Add(OpCodes.Stloc.ToInstruction(local)); il.Add(OpCodes.Ldloc.ToInstruction(local));
            }
            il.Add(cast);
            if (variant == "duplicate-cast") { il.Add(OpCodes.Nop.ToInstruction()); il.Add(OpCodes.Castclass.ToInstruction(memory)); }
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, variant == "position" ? "get_Position" : "ToArray",
                MethodSig.CreateInstance(variant == "position" ? module.CorLibTypes.Int64 : new SZArraySig(module.CorLibTypes.Byte)), memory)));
            il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        var caller = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Call");
        var call = caller.Body.Instructions.Single(i => i.OpCode.Code == Code.Call);
        Assert.Equal(expected, DependencyDecoderCompletionPass.OnlyToArray(caller, call));
    }
}
