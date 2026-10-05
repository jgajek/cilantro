using Cilantro.Core;
using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Recovery;
using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

public sealed class ReconstructionCoverageTests
{
    [Theory]
    [InlineData("list")]
    [InlineData("pairs")]
    [InlineData("map")]
    public void CollectionSnapshotsCompareContentsWithoutHeapIdDependence(string kind)
    {
        static string? Capture(string kind, bool padding, int number)
        {
            var heap = new StaticHeap(new StaticMachineLimits());
            if (padding) Assert.True(heap.TryAllocateString("unused", out _));
            Assert.True(heap.TryAllocateObject("Collection", out var root));
            Assert.True(heap.TryAllocateString("key", out var key));
            var value = StaticValue.FromInt32(number);
            object model = kind switch
            {
                "list" => new List<StaticValue> { key, value, root },
                "pairs" => new List<KeyValuePair<StaticValue, StaticValue>> { new(key, value), new(value, root) },
                _ => new Dictionary<StaticValue, StaticValue> { [key] = value, [value] = root }
            };
            Assert.True(heap.TrySetModelValue(root, "Contents", model));
            return new RebuiltMethodTrial.Snapshot(heap).Read(root);
        }
        var expected = Capture(kind, false, 7);
        Assert.NotNull(expected);
        Assert.Equal(expected, Capture(kind, true, 7));
        Assert.NotEqual(expected, Capture(kind, false, 8));
    }

    [Fact]
    public void MetadataSnapshotsRequireSharedIdentitiesAndDoNotConflateSameNamedModules()
    {
        using var first = new ModuleDefUser("SameName");
        using var second = new ModuleDefUser("SameName");
        var left = new StaticHeap(new StaticMachineLimits());
        var right = new StaticHeap(new StaticMachineLimits());
        Assert.True(left.TryAllocateMetadataHandle(first, out var a));
        Assert.True(right.TryAllocateString("padding", out _));
        Assert.True(right.TryAllocateMetadataHandle(first, out var b));
        Assert.True(right.TryAllocateMetadataHandle(second, out var c));
        Assert.Null(new RebuiltMethodTrial.Snapshot(left).Read(a));
        var metadata = new Dictionary<object, int>(ReferenceEqualityComparer.Instance);
        var expected = new RebuiltMethodTrial.Snapshot(left, metadata).Read(a);
        Assert.NotNull(expected);
        Assert.Equal(expected, new RebuiltMethodTrial.Snapshot(right, metadata).Read(b));
        Assert.NotEqual(expected, new RebuiltMethodTrial.Snapshot(right, metadata).Read(c));
    }

    [Fact]
    public void CollectionSnapshotsPreserveStorageAliasesAndRefuseOversizedModels()
    {
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateObject("Collection", out var root));
        var list = new List<StaticValue> { StaticValue.FromInt32(7) };
        Assert.True(heap.TrySetModelValue(root, "First", list));
        Assert.True(heap.TrySetModelValue(root, "Second", list));
        var shared = new RebuiltMethodTrial.Snapshot(heap).Read(root);
        Assert.NotNull(shared);
        Assert.True(heap.TrySetModelValue(root, "Second", new List<StaticValue>(list)));
        Assert.NotEqual(shared, new RebuiltMethodTrial.Snapshot(heap).Read(root));
        Assert.True(heap.TrySetModelValue(root, "First", Enumerable.Repeat(StaticValue.Null, RebuiltMethodTrial.Snapshot.MaximumNodes).ToList()));
        var bounded = new RebuiltMethodTrial.Snapshot(heap);
        Assert.Null(bounded.Read(root));
        Assert.Equal("collection exceeds remaining node budget", bounded.Failure);
    }

    [Fact]
    public void SnapshotComparesLargeGraphsAndStillIncludesTheirTail()
    {
        using var module = new ModuleDefUser("LargeGraph");
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateArray(module.CorLibTypes.Int32, 20000, out var values));
        var before = new RebuiltMethodTrial.Snapshot(heap).Read(values);
        Assert.NotNull(before);
        Assert.True(heap.TryWriteArray(values, 19999, StaticValue.FromInt32(1)));
        var after = new RebuiltMethodTrial.Snapshot(heap).Read(values);
        Assert.NotNull(after);
        Assert.NotEqual(before, after);
    }

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
        if (different) Assert.Contains("Synthetic.Host::State", result.Detail, StringComparison.Ordinal);
        if (different) Assert.Contains("argument snapshots matched", result.Detail, StringComparison.Ordinal);
        Assert.Same(original, method.Body);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ConfiguredTrialsUseExplicitHostFactsOnIndependentStrictMachines(bool warm)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.String))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            var getter = new MemberRefUser(module, "get_MachineName", MethodSig.CreateStatic(module.CorLibTypes.String),
                module.CorLibTypes.GetTypeRef("System", "Environment"));
            method.Body.Instructions.Add(OpCodes.Call.ToInstruction(getter));
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            owner.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var original = method.Body;
        var rebuilt = new CilBody();
        rebuilt.Instructions.Add(OpCodes.Ldstr.ToInstruction("analysis-host"));
        rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction());
        var profile = HostProfile.Parse("""{"facts":{"env:MachineName":"analysis-host"}}""", "fixture");
        var world = new RunEnvironment(new HostEnvironment(profile), strict: false);
        context.SetFact("run.environment", world);
        Assert.Equal(DevirtualizationCheck.NotMade,
            RebuiltMethodTrial.Compare(context, method, rebuilt, 3, warmOriginal: warm).Verdict);
        Assert.Equal(DevirtualizationCheck.Agreed,
            RebuiltMethodTrial.Compare(context, method, rebuilt, 3, warmOriginal: warm, hostProfile: profile).Verdict);
        rebuilt.Instructions[0].Operand = "other-host";
        Assert.Equal(DevirtualizationCheck.Disagreed,
            RebuiltMethodTrial.Compare(context, method, rebuilt, 3, warmOriginal: warm, hostProfile: profile).Verdict);
        Assert.Empty(world.Host.Questions);
        Assert.Same(original, method.Body);
        // An unmodeled external call must not inherit the surrounding run's permissive policy.
        ((MemberRef)original.Instructions[0].Operand).Name = "UnknownHostCall";
        Assert.Equal(DevirtualizationCheck.NotMade,
            RebuiltMethodTrial.Compare(context, method, rebuilt, 3, warmOriginal: warm, hostProfile: profile).Verdict);
        Assert.Same(original, method.Body);
    }

    [Fact]
    public void DeclaredTrialBudgetReachesLongBodiesAndRemainsSharedWithWarmup()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            var counter = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(counter);
            var loop = OpCodes.Ldloc.ToInstruction(counter);
            foreach (var i in new[] { OpCodes.Ldc_I4.ToInstruction(700_000), OpCodes.Stloc.ToInstruction(counter),
                         loop, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Sub.ToInstruction(), OpCodes.Dup.ToInstruction(),
                         OpCodes.Stloc.ToInstruction(counter), OpCodes.Brtrue.ToInstruction(loop),
                         OpCodes.Ldloc.ToInstruction(counter), OpCodes.Ret.ToInstruction() }) method.Body.Instructions.Add(i);
            owner.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var original = method.Body;
        var rebuilt = new CilBody();
        rebuilt.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
        rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction());
        Assert.Equal(DevirtualizationCheck.NotMade, RebuiltMethodTrial.Compare(context, method, rebuilt, 0).Verdict);
        context.SetFact(BootstrapMachine.RunEnvironmentFact, new RunEnvironment(declarations:
            RunDeclarations.Parse("""{"budgets":{"steps":5000000}}""", "long-trial")));
        Assert.Equal(DevirtualizationCheck.Agreed, RebuiltMethodTrial.Compare(context, method, rebuilt, 0).Verdict);
        var warm = RebuiltMethodTrial.Compare(context, method, rebuilt, 0, warmOriginal: true);
        Assert.Equal(DevirtualizationCheck.NotMade, warm.Verdict);
        Assert.Contains("5000000-step budget", warm.Detail, StringComparison.Ordinal);
        Assert.Same(original, method.Body);
    }

    [Fact]
    public void RepeatCallAgreementDoesNotEraseColdStartStaticDifferences()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var field = new FieldDefUser("Initialized", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            owner.Fields.Add(field);
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            foreach (var i in new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(field), OpCodes.Ret.ToInstruction() })
                method.Body.Instructions.Add(i);
            owner.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var shipped = method.Body;
        var rebuilt = new CilBody();
        rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction());
        Assert.Equal(DevirtualizationCheck.Disagreed, RebuiltMethodTrial.Compare(context, method, rebuilt, 0).Verdict);
        Assert.Equal(DevirtualizationCheck.Agreed, RebuiltMethodTrial.Compare(context, method, rebuilt, 0, warmOriginal: true).Verdict);
        Assert.Same(shipped, method.Body);
        Assert.Equal(DevirtualizationCheck.Disagreed, RebuiltMethodTrial.Compare(context, method, rebuilt, 0).Verdict);
        var field = method.DeclaringType.Fields.Single();
        rebuilt.Instructions.Insert(0, OpCodes.Stsfld.ToInstruction(field));
        rebuilt.Instructions.Insert(0, OpCodes.Ldc_I4_2.ToInstruction());
        Assert.Equal(DevirtualizationCheck.Disagreed, RebuiltMethodTrial.Compare(context, method, rebuilt, 0, warmOriginal: true).Verdict);
        Assert.Same(shipped, method.Body);
    }

    [Fact]
    public void WarmupCannotSatisfyMeasuredEngineCoverage()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var flag = new FieldDefUser("Initialized", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            owner.Fields.Add(flag);
            var engine = new MethodDefUser("Engine", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            engine.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            owner.Methods.Add(engine);
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            var end = OpCodes.Ret.ToInstruction();
            foreach (var i in new[] { OpCodes.Ldsfld.ToInstruction(flag), OpCodes.Brtrue.ToInstruction(end),
                         OpCodes.Call.ToInstruction(engine), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(flag), end })
                method.Body.Instructions.Add(i);
            owner.Methods.Add(method);
        });
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var method = methods.Single(m => m.Name == "Run");
        var rebuilt = new CilBody();
        rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction());
        var result = RebuiltMethodTrial.Compare(context, method, rebuilt, 0,
            methods.Single(m => m.Name == "Engine").MDToken.Raw, warmOriginal: true);
        Assert.Equal(DevirtualizationCheck.NotMade, result.Verdict);
        Assert.Contains("engine was not exercised", result.Detail, StringComparison.Ordinal);
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
        other.Instructions.Clear(); other.Instructions.Add(OpCodes.Ret.ToInstruction());
        var terminal = RebuiltMethodTrial.Compare(context, method, other, 0);
        Assert.Equal(DevirtualizationCheck.Disagreed, terminal.Verdict);
        Assert.Contains("Run()", terminal.Detail, StringComparison.Ordinal);
        var warm = RebuiltMethodTrial.Compare(context, method, other, 0, warmOriginal: true);
        Assert.Equal(DevirtualizationCheck.NotMade, warm.Verdict);
        Assert.Contains("warm-up did not complete", warm.Detail, StringComparison.Ordinal);
        other.Instructions.Clear(); other.Instructions.Add(OpCodes.Jmp.ToInstruction(method));
        Assert.Equal(DevirtualizationCheck.NotMade, RebuiltMethodTrial.Compare(context, method, other, 0).Verdict);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LiftedHelperIsSubstitutedIntoTheComparisonCopyAndGetsAWatchableIdentity(bool nops)
    {
        ArtifactContext Make() => SyntheticContext.Build(module =>
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
            if (nops)
            {
                caller.Body.Instructions.Insert(3, OpCodes.Nop.ToInstruction());
                caller.Body.Instructions.Insert(1, OpCodes.Nop.ToInstruction());
            }
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
        var originalBodies = copy.Module.GetTypes().SelectMany(t => t.Methods)
            .Where(m => m.HasBody).ToDictionary(m => m.MDToken.Raw,
                m => MethodBodyRecoveryInfrastructure.CloneBody(m, m, copy.Module));
        var installed = VirtualizationRebuildPass.InstallLiftedCopies(original, copy);
        var token = Assert.Single(installed);
        var helper = Assert.Single(copy.Module.GetTypes().SelectMany(t => t.Methods), m => m.MDToken.Raw == token);
        Assert.Equal("LiftedProgram1", helper.Name.String);
        var redirected = copy.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Caller");
        Assert.Contains(redirected.Body.Instructions, i => i.Operand == helper);
        Assert.DoesNotContain(redirected.Body.Instructions, i => i.Operand is IMethod m && m.Name == "Engine");
        var checkedCalls = DevirtualizedRun.CompareLiftedCallers(copy, copy, originalBodies);
        Assert.Equal(3, checkedCalls.Count);
        Assert.All(checkedCalls, trial => Assert.Equal(DevirtualizationCheck.Agreed, trial.Verdict));
        var helperCall = redirected.Body.Instructions.Single(i => i.Operand == helper);
        helperCall.OpCode = OpCodes.Nop;
        helperCall.Operand = null;
        Assert.All(DevirtualizedRun.CompareLiftedCallers(copy, copy, originalBodies),
            trial => Assert.Equal(DevirtualizationCheck.NotMade, trial.Verdict));
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
