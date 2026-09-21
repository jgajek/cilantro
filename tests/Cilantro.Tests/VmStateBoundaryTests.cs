using Cilantro.Core.Recovery;
using Cilantro.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

public sealed class VmStateBoundaryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ObjectSharingFollowsNestedReferencesRatherThanEqualContents(bool shared)
    {
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateObject("Container", out var vm));
        Assert.True(heap.TryAllocateObject("Container", out var app));
        Assert.True(heap.TryAllocateByteArray([1, 2], out var bytes));
        Assert.True(heap.TryAllocateByteArray([1, 2], out var equalBytes));
        heap.TrySetModelValue(vm, "Child", bytes);
        heap.TrySetModelValue(app, "Child", shared ? bytes : equalBytes);
        var left = new RebuiltMethodTrial.Snapshot(heap);
        var right = new RebuiltMethodTrial.Snapshot(heap);
        Assert.NotNull(left.Read(vm)); Assert.NotNull(right.Read(app));
        Assert.Equal(shared, left.SharesCapturedObjectsWith(right));
    }

    [Fact]
    public void SharedModelCollectionsAreDetectedAndDifferentHeapsCannotBeCompared()
    {
        var heap = new StaticHeap(new StaticMachineLimits());
        heap.TryAllocateObject("Container", out var vm);
        heap.TryAllocateObject("Container", out var app);
        var shared = new List<StaticValue> { StaticValue.FromInt32(1) };
        heap.TrySetModelValue(vm, "Items", shared);
        heap.TrySetModelValue(app, "Items", shared);
        var left = new RebuiltMethodTrial.Snapshot(heap);
        var right = new RebuiltMethodTrial.Snapshot(heap);
        Assert.NotNull(left.Read(vm)); Assert.NotNull(right.Read(app));
        Assert.True(left.SharesCapturedObjectsWith(right));
        Assert.Throws<ArgumentException>(() => left.SharesCapturedObjectsWith(
            new RebuiltMethodTrial.Snapshot(new StaticHeap(new StaticMachineLimits()))));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SeparateSnapshotIgnoresVmNumberingButPreservesApplicationAliases(bool changeAlias)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var engine = SyntheticContext.AddType(module, "AEngine");
            var host = SyntheticContext.AddType(module, "ZHost");
            var cache = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static);
            var a = new FieldDefUser("A", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static);
            var b = new FieldDefUser("B", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static);
            engine.Fields.Add(cache); host.Fields.Add(a); host.Fields.Add(b);
            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef);
            var entry = new MethodDefUser("Engine", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            foreach (var i in new[] { OpCodes.Newobj.ToInstruction(ctor), OpCodes.Stsfld.ToInstruction(cache), OpCodes.Ret.ToInstruction() }) entry.Body.Instructions.Add(i);
            engine.Methods.Add(entry);
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            foreach (var i in new[] { OpCodes.Call.ToInstruction(entry), OpCodes.Newobj.ToInstruction(ctor), OpCodes.Stsfld.ToInstruction(a), OpCodes.Ldsfld.ToInstruction(a), OpCodes.Stsfld.ToInstruction(b), OpCodes.Ret.ToInstruction() }) run.Body.Instructions.Add(i);
            host.Methods.Add(run);
        });
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var run = methods.Single(m => m.Name == "Run");
        var entry = methods.Single(m => m.Name == "Engine");
        var rebuilt = new CilBody();
        foreach (var i in run.Body.Instructions.Skip(1)) rebuilt.Instructions.Add(new Instruction(i.OpCode, i.Operand));
        if (changeAlias) rebuilt.Instructions[2] = new Instruction(OpCodes.Newobj, rebuilt.Instructions[0].Operand);
        var result = RebuiltMethodTrial.Compare(context, run, rebuilt, 0, entry.MDToken.Raw);
        Assert.Equal(DevirtualizationCheck.Disagreed, result.Verdict);
        Assert.Equal(!changeAlias, result.NonVmStateMatched);
        Assert.False(result.VmStateShared);
        Assert.Equal(!changeAlias, result.Detail.Contains("A separate snapshot excluding VM-owned static roots matched"));
    }

    [Fact]
    public void BoundarySummaryDoesNotHideOtherDisagreementsOrCountInconclusiveTrials()
    {
        var detail = DevirtualizedRun.DescribeStateDifferences([
            new(DevirtualizationCheck.Disagreed, "cache", true, false),
            new(DevirtualizationCheck.Disagreed, "shared cache", true, true),
            new(DevirtualizationCheck.Disagreed, "terminal outcome"),
            new(DevirtualizationCheck.NotMade, "unsupported"),
            new(DevirtualizationCheck.Agreed, "repeat")]);
        Assert.Contains("2 of 3 differing method trials", detail);
        Assert.Contains("In 1 of those trials", detail);
        Assert.Contains("Differing trials not explained by that boundary: 1", detail);
        Assert.Contains("Full-state disagreement remains", detail);
        Assert.Null(DevirtualizedRun.DescribeStateDifferences([new(DevirtualizationCheck.Agreed, "repeat")]));
        Assert.Null(DevirtualizedRun.DescribeStateDifferences([new(DevirtualizationCheck.Disagreed, "outcome")]));
    }

    [Fact]
    public void VmOnlyDifferencesAreLocalizedWithoutDeclaringEquivalence()
    {
        var detail = RebuiltMethodTrial.DescribeVmBoundary([2, 4], new HashSet<int> { 2, 4, 5 });
        Assert.Contains("All 2 differing snapshot root(s)", detail);
        Assert.Contains("does not prove", detail);
        Assert.Contains("disagreement is retained", detail);
    }

    [Fact]
    public void AnyDifferenceOutsideTheVmPreventsTheVmOnlyExplanation()
    {
        Assert.Empty(RebuiltMethodTrial.DescribeVmBoundary([0, 2], new HashSet<int> { 2 }));
        Assert.Empty(RebuiltMethodTrial.DescribeVmBoundary([2, 9], new HashSet<int> { 2 }));
        Assert.Empty(RebuiltMethodTrial.DescribeVmBoundary([], new HashSet<int> { 2 }));
        Assert.Empty(RebuiltMethodTrial.DescribeVmBoundary([2], null));
    }
}
