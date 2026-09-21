using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class NativeTrialSnapshotTests
{
    [Fact]
    public void LargeByteBuffersCompareTheirTailWithoutSpendingOneGraphNodePerByte()
    {
        var heap = new StaticHeap(new StaticMachineLimits());
        var buffer = new byte[RebuiltMethodTrial.Snapshot.MaximumNodes + 8];
        Assert.True(heap.TryAllocateByteArray(buffer, out var value));
        var before = new RebuiltMethodTrial.Snapshot(heap).Read(value);
        Assert.NotNull(before);
        Assert.True(heap.TryWriteArray(value, buffer.Length - 1, StaticValue.FromInt32(1)));
        var after = new RebuiltMethodTrial.Snapshot(heap).Read(value);
        Assert.NotNull(after);
        Assert.NotEqual(before, after);
        var snapshot = new RebuiltMethodTrial.Snapshot(heap);
        Assert.NotNull(snapshot.Read(value));
        Assert.Equal("ref:0", snapshot.Read(value));
    }

    [Fact]
    public void MatchingRegistrationDescriptionsDoNotEstablishAgreement()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var domain = module.CorLibTypes.GetTypeRef("System", "AppDomain");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            var current = new MemberRefUser(module, "get_CurrentDomain", MethodSig.CreateStatic(domain.ToTypeSig()), domain);
            var subscribe = new MemberRefUser(module, "add_AssemblyResolve",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object), domain);
            foreach (var i in new[] { OpCodes.Call.ToInstruction(current), OpCodes.Ldnull.ToInstruction(),
                         OpCodes.Callvirt.ToInstruction(subscribe), OpCodes.Ret.ToInstruction() }) method.Body.Instructions.Add(i);
            owner.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var result = RebuiltMethodTrial.Compare(context, method, method.Body, 0);
        Assert.Equal(DevirtualizationCheck.NotMade, result.Verdict);
        Assert.Contains("registrations are outside", result.Detail);
    }

    [Fact]
    public void NativeStateIgnoresHeapIdsButPreservesAddressesWritesAndProtections()
    {
        static StaticMachineState Make(bool padding, bool extraWrite, uint protection = 4, ulong address = 0x400000)
        {
            var state = new StaticMachineState(new StaticMachineLimits());
            if (padding) Assert.True(state.Heap.TryAllocateString("padding", out _));
            Assert.True(state.TryRegisterImage(new byte[16], address, [new(0, 16, 4)]));
            Assert.True(state.Heap.TryGetNativePointer(state.ImageRegion, 4, out var pointer));
            if (extraWrite) Assert.True(state.Heap.TryWriteBytes(pointer, 0, [9]));
            Assert.True(state.Heap.TryWriteBytes(pointer, 0, [1]));
            state.ApplyImageProtection(0, 16, protection);
            return state;
        }
        static string? Read(StaticMachineState state) => new RebuiltMethodTrial.Snapshot(state.Heap).ReadNativeState(state);
        var baseline = Read(Make(false, false));
        Assert.NotNull(baseline);
        Assert.Equal(baseline, Read(Make(true, false)));
        Assert.NotEqual(baseline, Read(Make(false, true))); // same final bytes, different write history
        Assert.NotEqual(baseline, Read(Make(false, false, 0x40)));
        Assert.NotEqual(baseline, Read(Make(false, false, address: 0x500000)));
    }

    [Fact]
    public void NativePointersPreserveOffsetsAndRegionAliases()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.TryRegisterImage(new byte[16], 0x400000));
        Assert.True(state.Heap.TryGetNativePointer(state.ImageRegion, 3, out var first));
        Assert.True(state.Heap.TryGetNativePointer(state.ImageRegion, 4, out var second));
        Assert.NotEqual(new RebuiltMethodTrial.Snapshot(state.Heap).Read(first),
            new RebuiltMethodTrial.Snapshot(state.Heap).Read(second));
        var snapshot = new RebuiltMethodTrial.Snapshot(state.Heap);
        Assert.NotNull(snapshot.Read(first));
        Assert.Equal("pointer:4:ref:0", snapshot.Read(second));
        Assert.NotNull(snapshot.ReadNativeState(state));
    }

    [Fact]
    public void UnreferencedScratchWritesAreIncluded()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateRegion(8, out var region));
        var before = new RebuiltMethodTrial.Snapshot(state.Heap).ReadNativeState(state);
        Assert.True(state.Heap.TryWriteBytes(region, 7, [42]));
        Assert.NotEqual(before, new RebuiltMethodTrial.Snapshot(state.Heap).ReadNativeState(state));
    }

    [Fact]
    public void ExhaustedNativeBoundsAndTruncatedProtectionHistoryRemainInconclusive()
    {
        var state = new StaticMachineState(new StaticMachineLimits(
            MaximumAllocatedBytes: 64 * 1024 * 1024, MaximumArrayLength: 64 * 1024 * 1024));
        Assert.True(state.Heap.TryAllocateRegion(RebuiltMethodTrial.Snapshot.MaximumBinaryBytes + 1, out _));
        var snapshot = new RebuiltMethodTrial.Snapshot(state.Heap);
        Assert.Null(snapshot.ReadNativeState(state));
        Assert.Contains("binary byte budget", snapshot.Failure);
        var protectedState = new StaticMachineState(new StaticMachineLimits());
        Assert.True(protectedState.TryRegisterImage(new byte[16], 0x400000, [new(0, 16, 4)]));
        for (var index = 0; index < 256; index++) protectedState.ApplyImageProtection(0, 16, 4);
        Assert.Null(new RebuiltMethodTrial.Snapshot(protectedState.Heap).ReadNativeState(protectedState));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MethodTrialsCompareNativeWritesEvenWithoutManagedRoots(bool changed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            var marshal = module.CorLibTypes.GetTypeRef("System.Runtime.InteropServices", "Marshal");
            var allocate = new MemberRefUser(module, "AllocHGlobal",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, module.CorLibTypes.Int32), marshal);
            var write = new MemberRefUser(module, "WriteInt32",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.IntPtr, module.CorLibTypes.Int32), marshal);
            foreach (var i in new[] { OpCodes.Ldc_I4_4.ToInstruction(), OpCodes.Call.ToInstruction(allocate),
                         OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Call.ToInstruction(write), OpCodes.Ret.ToInstruction() })
                method.Body.Instructions.Add(i);
            owner.Methods.Add(method);
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var original = method.Body;
        var rebuilt = new CilBody();
        foreach (var i in original.Instructions) rebuilt.Instructions.Add(new Instruction(i.OpCode, i.Operand));
        if (changed) rebuilt.Instructions[2].OpCode = OpCodes.Ldc_I4_2;
        var result = RebuiltMethodTrial.Compare(context, method, rebuilt, 0);
        Assert.Equal(changed ? DevirtualizationCheck.Disagreed : DevirtualizationCheck.Agreed, result.Verdict);
        Assert.Contains("modeled native memory", result.Detail);
        Assert.Same(original, method.Body);
    }
}
