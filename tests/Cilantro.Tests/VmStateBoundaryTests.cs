using Cilantro.Core.Recovery;
using Cilantro.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

public sealed class VmStateBoundaryTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void DebuggerGateAttributionStillChecksEarlierApplicationEffects(bool changesApplication, bool continuesApplication)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var importer = new Importer(module);
            var engine = SyntheticContext.AddType(module, "Engine");
            var cache = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            engine.Fields.Add(cache);
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            foreach (var instruction in new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(cache), OpCodes.Ret.ToInstruction() }) entry.Body.Instructions.Add(instruction);
            engine.Methods.Add(entry);
            var host = SyntheticContext.AddType(module, "Host");
            var state = new FieldDefUser("State", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            host.Fields.Add(state);
            var gate = new MethodDefUser("Gate", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            host.Methods.Add(gate);
            var done = OpCodes.Ret.ToInstruction();
            foreach (var instruction in new[] { OpCodes.Call.ToInstruction(importer.Import(typeof(System.Diagnostics.Debugger).GetProperty(nameof(System.Diagnostics.Debugger.IsAttached))!.GetMethod!)),
                OpCodes.Brfalse.ToInstruction(done), OpCodes.Ldstr.ToInstruction("Debugger Detected"),
                OpCodes.Newobj.ToInstruction(importer.Import(typeof(Exception).GetConstructor([typeof(string)])!)), OpCodes.Throw.ToInstruction(), done }) gate.Body.Instructions.Add(instruction);
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            host.Methods.Add(run);
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(entry));
            if (changesApplication)
            {
                run.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
                run.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(state));
            }
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(gate));
            if (continuesApplication)
            {
                run.Body.Instructions.Add(OpCodes.Ldc_I4_2.ToInstruction());
                run.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(state));
            }
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var methods = context.Module.GetTypes().SelectMany(type => type.Methods).ToArray();
        var rebuilt = new CilBody();
        if (continuesApplication)
        {
            rebuilt.Instructions.Add(OpCodes.Ldc_I4_2.ToInstruction());
            rebuilt.Instructions.Add(OpCodes.Stsfld.ToInstruction(context.Module.GetTypes().Single(type => type.Name == "Host").Fields.Single()));
        }
        rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction());
        var result = RebuiltMethodTrial.Compare(context, methods.Single(method => method.Name == "Run"), rebuilt, 4,
            methods.Single(method => method.Name == "Entry").MDToken.Raw);
        Assert.Equal(DevirtualizationCheck.Disagreed, result.Verdict);
        Assert.Equal(!changesApplication, result.ProtectorGateToken is not null);
        Assert.True(RebuiltMethodTrial.IsIsolatedDebuggerGate(methods.Single(method => method.Name == "Gate")));
        if (continuesApplication) Assert.Contains("Separate trial with only that guard neutralized", result.Detail);
    }

    [Fact]
    public void EscapedVmMethodHandleIsNotHiddenByHeapIsolation()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var engine = SyntheticContext.AddType(module, "Engine");
            var cache = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            engine.Fields.Add(cache);
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            foreach (var instruction in new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(cache), OpCodes.Ret.ToInstruction() })
                entry.Body.Instructions.Add(instruction);
            engine.Methods.Add(entry);
            var host = SyntheticContext.AddType(module, "Host");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeMethodHandle"))),
                MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            foreach (var instruction in new[] { OpCodes.Call.ToInstruction(entry), OpCodes.Ldtoken.ToInstruction(entry), OpCodes.Ret.ToInstruction() })
                run.Body.Instructions.Add(instruction);
            host.Methods.Add(run);
        });
        var entry = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Entry");
        var run = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Run");
        var rebuilt = new CilBody();
        rebuilt.Instructions.Add(OpCodes.Ldtoken.ToInstruction(entry));
        rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction());
        var result = RebuiltMethodTrial.Compare(context, run, rebuilt, 0, entry.MDToken.Raw);
        Assert.Equal(DevirtualizationCheck.Disagreed, result.Verdict);
        Assert.True(result.NonVmStateMatched);
        Assert.False(result.VmStateShared);
        Assert.True(result.VmMetadataEscaped);
    }

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
        Assert.Contains(result.DifferingRoots!, name => name.EndsWith("AEngine::Cache", StringComparison.Ordinal));
        Assert.NotNull(result.NonVmDifferingRoots);
        Assert.NotNull(result.VmDifferingRoots);
        Assert.Contains(result.VmDifferingRoots, name => name.EndsWith("AEngine::Cache", StringComparison.Ordinal));
        Assert.DoesNotContain(result.VmDifferingRoots, name => name.Contains("ZHost::", StringComparison.Ordinal));
        if (changeAlias)
        {
            Assert.Contains(result.NonVmDifferingRoots, name => name.EndsWith("ZHost::B", StringComparison.Ordinal));
            Assert.Contains("modeled native memory", result.NonVmDifferingRoots);
            Assert.True(result.NativeMemoryMatched);
            Assert.Contains("independent native-memory snapshot matched", result.Detail);
            Assert.Contains("including aliases", result.Detail);
        }
        else Assert.Empty(result.NonVmDifferingRoots);
    }

    [Fact]
    public void NonVmDiagnosticsIncludeEveryDifferingApplicationRoot()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var engine = SyntheticContext.AddType(module, "Engine");
            var host = SyntheticContext.AddType(module, "Host");
            var cache = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            var a = new FieldDefUser("A", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            var b = new FieldDefUser("B", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            engine.Fields.Add(cache); host.Fields.Add(a); host.Fields.Add(b);
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            foreach (var instruction in new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(cache), OpCodes.Ret.ToInstruction() })
                entry.Body.Instructions.Add(instruction);
            engine.Methods.Add(entry);
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            foreach (var instruction in new[] { OpCodes.Call.ToInstruction(entry), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(a), OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Stsfld.ToInstruction(b), OpCodes.Ret.ToInstruction() })
                run.Body.Instructions.Add(instruction);
            host.Methods.Add(run);
        });
        var methods = context.Module.GetTypes().SelectMany(type => type.Methods).ToArray();
        var run = methods.Single(method => method.Name == "Run");
        var entry = methods.Single(method => method.Name == "Entry");
        var rebuilt = new CilBody();
        foreach (var instruction in run.Body.Instructions.Skip(1))
            rebuilt.Instructions.Add(new Instruction(instruction.OpCode, instruction.Operand));
        rebuilt.Instructions[0].OpCode = OpCodes.Ldc_I4_3;
        rebuilt.Instructions[2].OpCode = OpCodes.Ldc_I4_4;
        var result = RebuiltMethodTrial.Compare(context, run, rebuilt, 0, entry.MDToken.Raw);
        Assert.Equal(DevirtualizationCheck.Disagreed, result.Verdict);
        Assert.Equal(3, result.DifferingRoots!.Count);
        Assert.Equal(2, result.NonVmDifferingRoots!.Count);
        Assert.Contains(result.NonVmDifferingRoots, name => name.EndsWith("Host::A", StringComparison.Ordinal));
        Assert.Contains(result.NonVmDifferingRoots, name => name.EndsWith("Host::B", StringComparison.Ordinal));
        Assert.DoesNotContain(result.NonVmDifferingRoots, name => name.Contains("Engine::Cache", StringComparison.Ordinal));
        Assert.True(result.NativeMemoryMatched);
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
