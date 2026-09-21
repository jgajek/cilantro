using Cilantro.Core;
using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Recovery;
using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

public sealed class ReconstructionCoverageTests
{
    [Fact]
    public void NestedSnapshotsAreBoundedAndIndependentOfHeapAllocationIds()
    {
        using var module = new ModuleDefUser("Test");
        static StaticValue Nested(StaticHeap heap, TypeSig element, bool padding)
        {
            if (padding) Assert.True(heap.TryAllocateString("unused", out _));
            Assert.True(heap.TryAllocateString("quoted \"text\"", out var value));
            for (var depth = 0; depth < 48; depth++)
            {
                Assert.True(heap.TryAllocateArray(element, 1, out var array));
                Assert.True(heap.TryWriteArray(array, 0, value));
                value = array;
            }
            return value;
        }
        var left = new StaticHeap(new StaticMachineLimits());
        var right = new StaticHeap(new StaticMachineLimits());
        var a = new RebuiltMethodTrial.Snapshot(left).Read(Nested(left, module.CorLibTypes.Object, false));
        var b = new RebuiltMethodTrial.Snapshot(right).Read(Nested(right, module.CorLibTypes.Object, true));
        Assert.NotNull(a);
        Assert.True(a.Length < 200);
        Assert.Equal(a, b);
    }

    [Fact]
    public void SnapshotKeepsAliasStructureAndFloatingPointModelBits()
    {
        using var module = new ModuleDefUser("Test");
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateObject("Model", out var value));
        Assert.True(heap.TrySetModelValue(value, "Number", double.NaN));
        Assert.NotNull(new RebuiltMethodTrial.Snapshot(heap).Read(value));
        Assert.True(heap.TryAllocateArray(module.CorLibTypes.Object, 1, out var cycle));
        Assert.True(heap.TryWriteArray(cycle, 0, cycle));
        Assert.NotNull(new RebuiltMethodTrial.Snapshot(heap).Read(cycle));
        Assert.True(heap.TryAllocateString("\uD800", out var first));
        Assert.True(heap.TryAllocateString("\uD801", out var second));
        Assert.NotEqual(new RebuiltMethodTrial.Snapshot(heap).Read(first), new RebuiltMethodTrial.Snapshot(heap).Read(second));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DirectTrialChecksStaticWritesEvenWhenReturnValuesMatch(bool different)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var field = new FieldDefUser("State", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            owner.Fields.Add(field);
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            foreach (var i in new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(field),
                OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Ret.ToInstruction() }) method.Body.Instructions.Add(i);
            owner.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var original = method.Body;
        var rebuilt = new CilBody();
        foreach (var i in original.Instructions) rebuilt.Instructions.Add(new Instruction(i.OpCode, i.Operand));
        if (different) rebuilt.Instructions[0].OpCode = OpCodes.Ldc_I4_2;
        var result = RebuiltMethodTrial.Compare(context, method, rebuilt, 0);
        Assert.Equal(different ? DevirtualizationCheck.Disagreed : DevirtualizationCheck.Agreed, result.Verdict);
        Assert.Same(original, method.Body);
    }

    [Fact]
    public void DirectTrialComparesExceptionMessagesAndDoesNotTreatUnsupportedAsAgreement()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                module.CorLibTypes.GetTypeRef("System", "Exception"));
            foreach (var i in new[] { OpCodes.Ldstr.ToInstruction("first"), OpCodes.Newobj.ToInstruction(ctor), OpCodes.Throw.ToInstruction() })
                method.Body.Instructions.Add(i);
            owner.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        Assert.Equal(DevirtualizationCheck.Agreed, RebuiltMethodTrial.Compare(context, method, method.Body, 0).Verdict);
        var other = new CilBody();
        foreach (var i in method.Body.Instructions) other.Instructions.Add(new Instruction(i.OpCode, i.Operand));
        other.Instructions[0].Operand = "second";
        Assert.Equal(DevirtualizationCheck.Disagreed, RebuiltMethodTrial.Compare(context, method, other, 0).Verdict);
        other.Instructions.Clear(); other.Instructions.Add(OpCodes.Jmp.ToInstruction(method));
        Assert.Equal(DevirtualizationCheck.NotMade, RebuiltMethodTrial.Compare(context, method, other, 0).Verdict);
    }

    [Fact]
    public void LiftedHelperIsSubstitutedIntoTheComparisonCopyAndGetsAWatchableIdentity()
    {
        static ArtifactContext Make() => SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var entry = new MethodDefUser("Engine", MethodSig.CreateStatic(module.CorLibTypes.Object,
                module.CorLibTypes.Int32, module.CorLibTypes.Object, module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Static | MethodAttributes.Assembly, Body = new CilBody() };
            entry.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            owner.Methods.Add(entry);
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static | MethodAttributes.Assembly, Body = new CilBody() };
            foreach (var i in new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(),
                OpCodes.Call.ToInstruction(entry), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction() }) caller.Body.Instructions.Add(i);
            owner.Methods.Add(caller);
        });
        using var original = Make(); using var copy = Make();
        var host = original.Module.GetTypes().Single(t => t.Name == "Host");
        var caller = host.Methods.Single(m => m.Name == "Caller"); var entry = host.Methods.Single(m => m.Name == "Engine");
        var program = new VirtualProgram(new VirtualizedMethod(caller, entry, 1, 0), "Instruction",
            [new(0, 1, new VirtualOperand.Number(7)), new(1, 2, new VirtualOperand.None())])
        {
            Operations = new Dictionary<int, VirtualOperation>
                { [1] = new(1, 0, 1, "pushes its operand"), [2] = new(2, 1, 0, "returns the value it takes") }
        };
        original.SetFact<IReadOnlyList<VirtualizationRebuildPass.LiftedRecipe>>(VirtualizationRebuildPass.LiftedRecipesFact,
            [new(program, caller.MDToken.Raw, entry.MDToken.Raw, caller)]);
        var installed = VirtualizationRebuildPass.InstallLiftedCopies(original, copy);
        var token = Assert.Single(installed);
        var helper = Assert.Single(copy.Module.GetTypes().SelectMany(t => t.Methods), m => m.MDToken.Raw == token);
        Assert.Equal("LiftedProgram1", helper.Name.String);
        var redirected = copy.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Caller");
        Assert.Contains(redirected.Body.Instructions, i => i.Operand == helper);
        Assert.DoesNotContain(redirected.Body.Instructions, i => i.Operand is IMethod m && m.Name == "Engine");
    }

    [Fact]
    public void EnteringOneBodyDoesNotValidateAnUnexercisedBody()
    {
        var result = DevirtualizedRun.Coverage(["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"], new HashSet<uint> { 1, 2 }, new HashSet<uint> { 1, 2 }, new HashSet<uint> { 1 }, 0);
        Assert.Equal(DevirtualizationCheck.NotMade, result.Verdict);
        Assert.Contains("1 of 2", Assert.Single(result.Said), StringComparison.Ordinal);
    }

    [Fact]
    public void MissingSubstitutionCannotBeHiddenByAHitOnTheOriginalStub()
    {
        var result = DevirtualizedRun.Coverage(["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"], new HashSet<uint> { 1, 2 }, new HashSet<uint> { 1 }, new HashSet<uint> { 1, 2 }, 0);
        Assert.Equal(DevirtualizationCheck.NotMade, result.Verdict);
    }

    [Fact]
    public void LiftedHelpersMustNotBeSilentlyExcludedFromCoverage()
    {
        var result = DevirtualizedRun.Coverage(["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"], new HashSet<uint> { 1 }, new HashSet<uint> { 1 }, new HashSet<uint> { 1 }, 1);
        Assert.Equal(DevirtualizationCheck.NotMade, result.Verdict);
        Assert.Contains("1 lifted helper", Assert.Single(result.Said), StringComparison.Ordinal);
    }

    [Fact]
    public void AllInstalledBodiesMustBeEnteredWithANonemptyPayloadComparison()
    {
        var methods = new HashSet<uint> { 1, 2 };
        Assert.Equal(DevirtualizationCheck.Agreed, DevirtualizedRun.Coverage(["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"], methods, methods, methods, 0).Verdict);
        Assert.Equal(DevirtualizationCheck.NotMade, DevirtualizedRun.Coverage([], methods, methods, methods, 0).Verdict);
        Assert.Equal(DevirtualizationCheck.NotMade, DevirtualizedRun.Coverage(["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"], new HashSet<uint>(), new HashSet<uint>(), new HashSet<uint>(), 0).Verdict);
    }
}
