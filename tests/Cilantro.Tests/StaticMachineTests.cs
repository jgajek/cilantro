using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

public sealed class StaticMachineTests
{
    [Fact]
    public void ProvenanceDoesNotAffectStaticValueEqualityOrHashing()
    {
        var left = StaticValue.FromInt32(42).WithProvenance(1);
        var right = StaticValue.FromInt32(42).WithProvenance(99);

        Assert.Equal(left, right);
        Assert.Equal(left.GetHashCode(), right.GetHashCode());
    }

    [Fact]
    public void ProvenanceGraphDeduplicatesAndBoundsNodes()
    {
        var graph = new ProvenanceGraph(3, 2, 8);
        var first = graph.Origin(
            StaticValue.FromInt32(1), ProvenanceKind.Literal, "M/IL_0000", "1");
        var duplicate = graph.Origin(
            StaticValue.FromInt32(1), ProvenanceKind.Literal, "M/IL_0000", "1");
        var second = graph.Operation(
            StaticValue.FromInt32(2), ProvenanceKind.Unary, "M/IL_0001", "inc", first);
        var bounded = graph.Operation(
            StaticValue.FromInt32(3), ProvenanceKind.Unary, "M/IL_0002", "inc", second);

        Assert.Equal(first.ProvenanceId, duplicate.ProvenanceId);
        Assert.Contains("Budget", graph.Render(bounded.ProvenanceId));
        Assert.True(graph.Count <= 3);
    }

    /// <summary>
    /// A caller that asks whether the graph is full before describing anything to it gets the same
    /// value it would have got by describing it, which is the whole reason it is allowed to skip
    /// composing the description.
    /// </summary>
    [Fact]
    public void AFullGraphMarksAValueTheSameWayWhetherOrNotItWasDescribed()
    {
        var graph = new ProvenanceGraph(2, 8, 8);
        Assert.False(graph.Saturated);
        graph.Origin(StaticValue.FromInt32(1), ProvenanceKind.Literal, "M/IL_0000", "1");
        Assert.True(graph.Saturated);

        var described = graph.Origin(
            StaticValue.FromInt32(7), ProvenanceKind.Argument, "M/arg0", "System.Void M::N()");
        var undescribed = graph.Unrecorded(StaticValue.FromInt32(7));

        Assert.Equal(described.ProvenanceId, undescribed.ProvenanceId);
        Assert.Contains("Budget", graph.Render(undescribed.ProvenanceId));
    }

    [Fact]
    public void ArithmeticProvenanceRendersItsLiteralInputs()
    {
        using var module = NewModule();
        var method = NewMethod(
            module,
            "TrackedAdd",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            OpCodes.Ldc_I4_2,
            OpCodes.Ldc_I4_3,
            OpCodes.Add,
            OpCodes.Ret);
        var machine = new StaticMachine();

        var result = machine.Execute(method);
        var rendered = machine.State.Provenance.Render(result.Value.ProvenanceId);

        Assert.Equal(5, result.Value.AsInt32());
        Assert.Contains("Binary", rendered);
        Assert.Contains("Literal", rendered);
    }

    [Fact]
    public void ExecutesArithmeticBranchesAndInternalCalls()
    {
        using var module = NewModule();
        var add = NewMethod(
            module,
            "Add",
            MethodSig.CreateStatic(
                module.CorLibTypes.Int32,
                module.CorLibTypes.Int32,
                module.CorLibTypes.Int32),
            OpCodes.Ldarg_0,
            OpCodes.Ldarg_1,
            OpCodes.Add,
            OpCodes.Ret);
        var caller = NewMethod(
            module,
            "Caller",
            MethodSig.CreateStatic(module.CorLibTypes.Int32));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 20));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 22));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Call, add));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(caller);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(42, result.Value.AsInt32());
        Assert.Equal(8, result.Steps);
    }

    [Fact]
    public void ConvertsUnsignedIntegersToFloatingPointWithoutSignExtension()
    {
        using var module = NewModule();
        var method = NewMethod(
            module,
            "UnsignedFloat",
            MethodSig.CreateStatic(module.CorLibTypes.Double),
            OpCodes.Ldc_I4_M1,
            OpCodes.Conv_R_Un,
            OpCodes.Ret);

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(4294967295d, result.Value.AsFloat64());
    }

    [Fact]
    public void IntegerConversionsDoNotRoundThroughFloatingPoint()
    {
        using var module = NewModule();
        var method = NewMethod(
            module,
            "IntegerPrecision",
            MethodSig.CreateStatic(module.CorLibTypes.Int64));
        method.Body.Instructions.Add(
            Instruction.Create(OpCodes.Ldc_I8, 9_007_199_254_740_993L));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_I8));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(9_007_199_254_740_993L, result.Value.AsInt64());
    }

    [Fact]
    public void UnsignedWideningUsesTheSourceStackWidth()
    {
        using var module = NewModule();
        var method = NewMethod(
            module,
            "UnsignedWiden",
            MethodSig.CreateStatic(module.CorLibTypes.UInt64),
            OpCodes.Ldc_I4_M1,
            OpCodes.Conv_U8,
            OpCodes.Ret);

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(4_294_967_295L, result.Value.AsInt64());
    }

    [Fact]
    public void NativeUnsignedConversionUsesRegisteredPointerWidth()
    {
        using var module = NewModule();
        var method = NewMethod(
            module,
            "NativeUnsigned",
            MethodSig.CreateStatic(module.CorLibTypes.UIntPtr),
            OpCodes.Ldc_I4_M1,
            OpCodes.Conv_U,
            OpCodes.Ret);
        var machine64 = new StaticMachine();
        machine64.State.RegisterPointerSize(8);
        var machine32 = new StaticMachine();
        machine32.State.RegisterPointerSize(4);

        var result64 = machine64.Execute(method);
        var result32 = machine32.Execute(method);

        Assert.Equal(StaticValueKind.Int64, result64.Value.Kind);
        Assert.Equal(4_294_967_295L, result64.Value.AsInt64());
        Assert.Equal(StaticValueKind.Int32, result32.Value.Kind);
        Assert.Equal(-1, result32.Value.AsInt32());
    }

    [Fact]
    public void FloatingToIntegerConversionTruncatesRepresentableFractions()
    {
        using var module = NewModule();
        var method = NewMethod(
            module,
            "FractionalUnsigned",
            MethodSig.CreateStatic(module.CorLibTypes.UInt32));
        method.Body.Instructions.Add(
            Instruction.Create(OpCodes.Ldc_R8, 4_294_967_295.75d));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_U4));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(-1, result.Value.AsInt32());
    }

#pragma warning disable CA5351
    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(4_294_967_296d)]
    [InlineData(-1d)]
    public void FloatingToIntegerConversionRejectsUnspecifiedOverflow(double value)
    {
        using var module = NewModule();
        var method = NewMethod(
            module,
            "UnspecifiedUnsigned",
            MethodSig.CreateStatic(module.CorLibTypes.UInt32));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_R8, value));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_U4));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.InvalidProgram, result.Status);
        Assert.Contains("implementation-dependent ECMA-335", result.Diagnostic);
    }

    [Fact]
    public void ModelsArraysWithoutUsingTheRuntime()
    {
        using var module = NewModule();
        var method = NewMethod(
            module,
            "Array",
            MethodSig.CreateStatic(module.CorLibTypes.Int32));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_2));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Int32.TypeDefOrRef));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Dup));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 37));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I4));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldelem_I4));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(37, result.Value.AsInt32());
        Assert.Equal(8, result.AllocatedBytes);
    }

    [Fact]
    public void InitializesPrimitiveArraysFromFieldRvaByteLayout()
    {
        using var module = NewModule();
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateArray(module.CorLibTypes.Int32, 2, out var array));
        var origin = state.Provenance.Origin(
            StaticValue.FromInt32(8), ProvenanceKind.Metadata, "field", "rva");

        Assert.True(state.Heap.TryInitializePrimitiveArray(
            array,
            [0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x90],
            origin.ProvenanceId));
        Assert.True(state.Heap.TryReadArray(array, 0, out var first));
        Assert.True(state.Heap.TryReadArray(array, 1, out var second));
        Assert.Equal(0x12345678, first.AsInt32());
        Assert.Equal(unchecked((int)0x90ABCDEF), second.AsInt32());
        Assert.Equal(origin.ProvenanceId, second.ProvenanceId);
    }

    [Fact]
    public void ArrayStoresNormalizeIntegerAndFloatingElementWidths()
    {
        using var module = NewModule();
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateArray(module.CorLibTypes.Byte, 1, out var bytes));
        Assert.True(heap.TryAllocateArray(module.CorLibTypes.Int64, 1, out var longs));
        Assert.True(heap.TryAllocateArray(module.CorLibTypes.Single, 1, out var singles));

        Assert.True(heap.TryWriteArray(bytes, 0, StaticValue.FromInt64(0x1234)));
        Assert.True(heap.TryWriteArray(longs, 0, StaticValue.FromInt32(-1)));
        Assert.True(heap.TryWriteArray(singles, 0, StaticValue.FromFloat64(0.1d)));
        Assert.True(heap.TryReadArray(bytes, 0, out var byteValue));
        Assert.True(heap.TryReadArray(longs, 0, out var longValue));
        Assert.True(heap.TryReadArray(singles, 0, out var singleValue));

        Assert.Equal(0x34, byteValue.AsInt32());
        Assert.Equal(StaticValueKind.Int64, longValue.Kind);
        Assert.Equal(-1L, longValue.AsInt64());
        Assert.Equal(StaticValueKind.Float32, singleValue.Kind);
        Assert.Equal((double)0.1f, singleValue.AsFloat64());
    }

    [Fact]
    public void PrimitiveArrayByteAccessUsesLittleEndianByteOffsets()
    {
        using var module = NewModule();
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateArray(module.CorLibTypes.Int32, 2, out var integers));
        Assert.True(heap.TryAllocateArray(module.CorLibTypes.Int64, 1, out var longs));
        Assert.True(heap.TryAllocateArray(module.CorLibTypes.Single, 1, out var singles));
        Assert.True(heap.TryWriteArray(integers, 0, StaticValue.FromInt32(0x11223344)));
        Assert.True(heap.TryWriteArray(integers, 1, StaticValue.FromInt32(0x55667788)));
        Assert.True(heap.TryWriteArray(
            longs,
            0,
            StaticValue.FromInt64(0x0102030405060708)));
        Assert.True(heap.TryWriteArray(singles, 0, StaticValue.FromFloat32(1.0f)));

        var integerBytes = new byte[8];
        var longBytes = new byte[8];
        var singleBytes = new byte[4];
        Assert.True(heap.TryReadBytes(integers, 0, integerBytes));
        Assert.True(heap.TryReadBytes(longs, 0, longBytes));
        Assert.True(heap.TryReadBytes(singles, 0, singleBytes));
        Assert.Equal([0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55], integerBytes);
        Assert.Equal([8, 7, 6, 5, 4, 3, 2, 1], longBytes);
        Assert.Equal([0, 0, 0x80, 0x3F], singleBytes);

        Assert.True(heap.TryGetArrayElementReference(integers, 1, out var interior));
        Assert.True(heap.TryWriteBytes(interior, 1, [0xAA]));
        Assert.True(heap.TryReadArray(integers, 1, out var modified));
        Assert.Equal(0x5566AA88, modified.AsInt32());
    }

    [Fact]
    public void ArrayCopyUsesElementIndicesAndMemmoveOverlap()
    {
        using var module = NewModule();
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateArray(module.CorLibTypes.Int32, 4, out var array));
        for (var index = 0; index < 4; index++)
            Assert.True(state.Heap.TryWriteArray(array, index, StaticValue.FromInt32(index + 1)));
        var arrayType = new TypeRefUser(
            module,
            "System",
            "Array",
            module.CorLibTypes.AssemblyRef);
        var copy = new MemberRefUser(
            module,
            "Copy",
            MethodSig.CreateStatic(
                module.CorLibTypes.Void,
                module.CorLibTypes.Object,
                module.CorLibTypes.Int32,
                module.CorLibTypes.Object,
                module.CorLibTypes.Int32,
                module.CorLibTypes.Int32),
            arrayType);

        var result = new ArrayIntrinsic().Invoke(
            new IntrinsicContext(state),
            copy,
            [array, StaticValue.FromInt32(0), array, StaticValue.FromInt32(1),
                StaticValue.FromInt32(3)]);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var values = new int[4];
        for (var index = 0; index < values.Length; index++)
        {
            Assert.True(state.Heap.TryReadArray(array, index, out var value));
            values[index] = value.AsInt32();
        }
        Assert.Equal([1, 1, 2, 3], values);
    }

    [Fact]
    public void MarshalCopyUsesTypedArrayElementCounts()
    {
        using var module = NewModule();
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateArray(module.CorLibTypes.Int32, 2, out var array));
        Assert.True(state.Heap.TryWriteArray(array, 0, StaticValue.FromInt32(0x11223344)));
        Assert.True(state.Heap.TryWriteArray(array, 1, StaticValue.FromInt32(0x55667788)));
        Assert.True(state.Heap.TryAllocateRegion(8, out var region));
        var marshal = new TypeRefUser(
            module,
            "System.Runtime.InteropServices",
            "Marshal",
            module.CorLibTypes.AssemblyRef);
        var copy = new MemberRefUser(
            module,
            "Copy",
            MethodSig.CreateStatic(
                module.CorLibTypes.Void,
                new SZArraySig(module.CorLibTypes.Int32),
                module.CorLibTypes.Int32,
                module.CorLibTypes.IntPtr,
                module.CorLibTypes.Int32),
            marshal);

        var result = new VirtualRegionIntrinsic().Invoke(
            new IntrinsicContext(state),
            copy,
            [array, StaticValue.FromInt32(0), region, StaticValue.FromInt32(2)]);
        var bytes = new byte[8];

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(state.Heap.TryReadBytes(region, 0, bytes));
        Assert.Equal([0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55], bytes);
    }

    [Fact]
    public void MemoryStreamSegmentsAliasBuffersAndKeepIndependentPositions()
    {
        using var module = NewModule();
        var streamType = new TypeRefUser(
            module, "System.IO", "MemoryStream", module.CorLibTypes.AssemblyRef);
        var segmentConstructor = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(
                module.CorLibTypes.Void,
                new SZArraySig(module.CorLibTypes.Byte),
                module.CorLibTypes.Int32,
                module.CorLibTypes.Int32),
            streamType);
        var arrayConstructor = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(
                module.CorLibTypes.Void,
                new SZArraySig(module.CorLibTypes.Byte)),
            streamType);
        var readByte = new MemberRefUser(
            module,
            "ReadByte",
            MethodSig.CreateInstance(module.CorLibTypes.Int32),
            streamType);
        var writeByte = new MemberRefUser(
            module,
            "WriteByte",
            MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Byte),
            streamType);
        var seek = new MemberRefUser(
            module,
            "Seek",
            MethodSig.CreateInstance(
                module.CorLibTypes.Int64,
                module.CorLibTypes.Int64,
                module.CorLibTypes.Int32),
            streamType);
        var toArray = new MemberRefUser(
            module,
            "ToArray",
            MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Byte)),
            streamType);
        var state = new StaticMachineState(new StaticMachineLimits());
        var intrinsic = new LoaderFrameworkIntrinsic();
        Assert.True(state.Heap.TryAllocateByteArray([0, 1, 2, 3, 4, 5], out var buffer));
        Assert.True(state.Heap.TryAllocateObject("System.IO.MemoryStream", out var segment));
        Assert.True(state.Heap.TryAllocateObject("System.IO.MemoryStream", out var whole));

        Assert.Equal(
            StaticExecutionStatus.Completed,
            intrinsic.Invoke(
                new IntrinsicContext(state),
                segmentConstructor,
                [segment, buffer, StaticValue.FromInt32(2), StaticValue.FromInt32(3)]).Status);
        Assert.Equal(
            StaticExecutionStatus.Completed,
            intrinsic.Invoke(
                new IntrinsicContext(state),
                arrayConstructor,
                [whole, buffer]).Status);
        Assert.Equal(
            2,
            intrinsic.Invoke(new IntrinsicContext(state), readByte, [segment]).Value.AsInt32());
        intrinsic.Invoke(
            new IntrinsicContext(state),
            seek,
            [whole, StaticValue.FromInt64(3), StaticValue.FromInt32(0)]);
        Assert.Equal(
            StaticExecutionStatus.Completed,
            intrinsic.Invoke(
                new IntrinsicContext(state),
                writeByte,
                [whole, StaticValue.FromInt32(9)]).Status);
        Assert.Equal(
            9,
            intrinsic.Invoke(new IntrinsicContext(state), readByte, [segment]).Value.AsInt32());
        Assert.Equal(
            4,
            intrinsic.Invoke(new IntrinsicContext(state), readByte, [whole]).Value.AsInt32());
        Assert.Equal([0, 1, 2, 9, 4, 5], state.Heap.GetBytesSnapshot(buffer));
        var segmentCopy = intrinsic.Invoke(
            new IntrinsicContext(state),
            toArray,
            [segment]);
        Assert.Equal([2, 9, 4], state.Heap.GetBytesSnapshot(segmentCopy.Value));
        Assert.True(state.Heap.TryGetModelValue(segment, "Position", out long segmentPosition));
        Assert.True(state.Heap.TryGetModelValue(whole, "Position", out long wholePosition));
        Assert.Equal(2, segmentPosition);
        Assert.Equal(5, wholePosition);
    }

    [Fact]
    public void BinaryReadersShareStreamPositionAndReadBytesMayReturnPartialData()
    {
        using var module = NewModule();
        var streamType = new TypeRefUser(
            module, "System.IO", "MemoryStream", module.CorLibTypes.AssemblyRef);
        var readerType = new TypeRefUser(
            module, "System.IO", "BinaryReader", module.CorLibTypes.AssemblyRef);
        var streamConstructor = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(
                module.CorLibTypes.Void,
                new SZArraySig(module.CorLibTypes.Byte)),
            streamType);
        var readerConstructor = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, streamType.ToTypeSig()),
            readerType);
        var readBytes = new MemberRefUser(
            module,
            "ReadBytes",
            MethodSig.CreateInstance(
                new SZArraySig(module.CorLibTypes.Byte),
                module.CorLibTypes.Int32),
            readerType);
        var readByte = new MemberRefUser(
            module,
            "ReadByte",
            MethodSig.CreateInstance(module.CorLibTypes.Byte),
            readerType);
        var state = new StaticMachineState(new StaticMachineLimits());
        var intrinsic = new LoaderFrameworkIntrinsic();
        Assert.True(state.Heap.TryAllocateByteArray([10, 20, 30], out var buffer));
        Assert.True(state.Heap.TryAllocateObject("System.IO.MemoryStream", out var stream));
        Assert.True(state.Heap.TryAllocateObject("System.IO.BinaryReader", out var first));
        Assert.True(state.Heap.TryAllocateObject("System.IO.BinaryReader", out var second));
        intrinsic.Invoke(new IntrinsicContext(state), streamConstructor, [stream, buffer]);
        intrinsic.Invoke(new IntrinsicContext(state), readerConstructor, [first, stream]);
        intrinsic.Invoke(new IntrinsicContext(state), readerConstructor, [second, stream]);

        Assert.Equal(
            10,
            intrinsic.Invoke(new IntrinsicContext(state), readByte, [first]).Value.AsInt32());
        var partial = intrinsic.Invoke(
            new IntrinsicContext(state),
            readBytes,
            [second, StaticValue.FromInt32(10)]);

        Assert.Equal(StaticExecutionStatus.Completed, partial.Status);
        Assert.Equal([20, 30], state.Heap.GetBytesSnapshot(partial.Value));
        Assert.True(state.Heap.TryGetModelValue(stream, "Position", out long position));
        Assert.Equal(3, position);
    }

    [Fact]
    public void RejectsExternalCallsThatAreNotAllowlisted()
    {
        using var module = NewModule();
        var console = new TypeRefUser(
            module,
            "System",
            "Console",
            module.CorLibTypes.AssemblyRef);
        var external = new MemberRefUser(
            module,
            "Read",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            console);
        var method = NewMethod(
            module,
            "External",
            MethodSig.CreateStatic(module.CorLibTypes.Int32));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, external));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.Unsupported, result.Status);
        Assert.Contains("not allowlisted", result.Diagnostic);
    }

    [Fact]
    public void UsesClrDefaultsForUninitializedStaticFields()
    {
        using var module = NewModule();
        var field = new FieldDefUser(
            "Unknown",
            new FieldSig(module.CorLibTypes.Int32),
            FieldAttributes.Static);
        var type = new TypeDefUser("Tests", "Holder", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        type.Fields.Add(field);
        var method = NewMethod(
            module,
            "UnknownBranch",
            MethodSig.CreateStatic(module.CorLibTypes.Int32));
        var falseValue = Instruction.Create(OpCodes.Ldc_I4_2);
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldsfld, field));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Brfalse_S, falseValue));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        method.Body.Instructions.Add(falseValue);
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(2, result.Value.AsInt32());
    }

    [Fact]
    public void RunsDeclaringTypeInitializerBeforeStaticMethod()
    {
        using var module = NewModule();
        var type = new TypeDefUser("Tests", "Initialized", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var field = new FieldDefUser(
            "Seed",
            new FieldSig(module.CorLibTypes.Int32),
            FieldAttributes.Static);
        type.Fields.Add(field);
        var initializer = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 42));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, field));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(initializer);
        var read = new MethodDefUser(
            "Read",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        read.Body.Instructions.Add(Instruction.Create(OpCodes.Ldsfld, field));
        read.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(read);

        var machine = new StaticMachine(modelTypeInitialization: true);
        var result = machine.Execute(read);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(42, result.Value.AsInt32());
        Assert.Equal(
            [TypeInitializationStatus.Initializing, TypeInitializationStatus.Initialized],
            machine.State.TypeInitializationEvents.Select(item => item.Status).ToArray());
    }

    [Fact]
    public void BeforeFieldInitDelaysInitializationUntilStaticFieldAccess()
    {
        using var module = NewModule();
        var type = new TypeDefUser("Tests", "Relaxed", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.BeforeFieldInit
        };
        module.Types.Add(type);
        var field = new FieldDefUser(
            "Value",
            new FieldSig(module.CorLibTypes.Int32),
            FieldAttributes.Static);
        type.Fields.Add(field);
        var initializer = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_7));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, field));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(initializer);
        var noop = new MethodDefUser(
            "Noop",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        noop.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        noop.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(noop);
        var read = new MethodDefUser(
            "Read",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        read.Body.Instructions.Add(Instruction.Create(OpCodes.Ldsfld, field));
        read.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(read);
        var machine = new StaticMachine(modelTypeInitialization: true);

        Assert.Equal(1, machine.Execute(noop).Value.AsInt32());
        Assert.Empty(machine.State.TypeInitializationEvents);
        Assert.Equal(7, machine.Execute(read).Value.AsInt32());
        Assert.Equal(7, machine.Execute(read).Value.AsInt32());
        Assert.Equal(2, machine.State.TypeInitializationEvents.Count);
    }

    [Fact]
    public void TypeInitializationDoesNotImplicitlyRunBaseInitializer()
    {
        using var module = NewModule();
        var baseType = new TypeDefUser("Tests", "Base", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(baseType);
        var baseField = new FieldDefUser(
            "Value",
            new FieldSig(module.CorLibTypes.Int32),
            FieldAttributes.Static);
        baseType.Fields.Add(baseField);
        var baseInitializer = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        baseInitializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        baseInitializer.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, baseField));
        baseInitializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        baseType.Methods.Add(baseInitializer);
        var derived = new TypeDefUser("Tests", "Derived", baseType);
        module.Types.Add(derived);
        var derivedField = new FieldDefUser(
            "Value",
            new FieldSig(module.CorLibTypes.Int32),
            FieldAttributes.Static);
        derived.Fields.Add(derivedField);
        var derivedInitializer = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        derivedInitializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_2));
        derivedInitializer.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, derivedField));
        derivedInitializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        derived.Methods.Add(derivedInitializer);
        var read = new MethodDefUser(
            "Read",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        read.Body.Instructions.Add(Instruction.Create(OpCodes.Ldsfld, derivedField));
        read.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        derived.Methods.Add(read);
        var machine = new StaticMachine(modelTypeInitialization: true);

        Assert.Equal(2, machine.Execute(read).Value.AsInt32());
        Assert.DoesNotContain(
            machine.State.TypeInitializationEvents,
            item => item.Type == baseType.FullName);
    }

    [Fact]
    public void InstanceMethodEntryDoesNotTriggerTypeInitialization()
    {
        using var module = NewModule();
        var type = new TypeDefUser("Tests", "Instance", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var initializer = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(initializer);
        var instanceMethod = new MethodDefUser(
            "Invoke",
            MethodSig.CreateInstance(module.CorLibTypes.Int32),
            MethodAttributes.Public)
        {
            Body = new CilBody()
        };
        instanceMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        instanceMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(instanceMethod);
        var machine = new StaticMachine(modelTypeInitialization: true);
        Assert.True(machine.State.Heap.TryAllocateObject(type.FullName, out var instance));

        var result = machine.Execute(instanceMethod, [instance]);

        Assert.Equal(1, result.Value.AsInt32());
        Assert.Empty(machine.State.TypeInitializationEvents);
    }

    [Fact]
    public void InstanceConstructorTriggersPreciseTypeInitialization()
    {
        using var module = NewModule();
        var type = new TypeDefUser("Tests", "Constructed", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var initializer = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(initializer);
        var constructor = new MethodDefUser(
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodAttributes.Public | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        constructor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(constructor);
        var machine = new StaticMachine(modelTypeInitialization: true);
        Assert.True(machine.State.Heap.TryAllocateObject(type.FullName, out var instance));

        var result = machine.Execute(constructor, [instance]);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(
            [TypeInitializationStatus.Initializing, TypeInitializationStatus.Initialized],
            machine.State.TypeInitializationEvents.Select(item => item.Status).ToArray());
    }

    [Fact]
    public void FailedTypeInitializerIsSticky()
    {
        using var module = NewModule();
        var type = new TypeDefUser("Tests", "Failed", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var initializer = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Div));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(initializer);
        var invoke = new MethodDefUser(
            "Invoke",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        invoke.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(invoke);
        var machine = new StaticMachine(modelTypeInitialization: true);

        var first = machine.Execute(invoke);
        var second = machine.Execute(invoke);

        Assert.Equal(StaticExecutionStatus.InvalidProgram, first.Status);
        Assert.Equal(StaticExecutionStatus.InvalidProgram, second.Status);
        Assert.Contains("previously failed", second.Diagnostic);
        Assert.Equal(
            [TypeInitializationStatus.Initializing, TypeInitializationStatus.Failed],
            machine.State.TypeInitializationEvents.Select(item => item.Status).ToArray());
    }

    [Fact]
    public void EnforcesSharedStepRecursionAndAllocationLimits()
    {
        using var module = NewModule();
        var loop = NewMethod(
            module,
            "Loop",
            MethodSig.CreateStatic(module.CorLibTypes.Void));
        var branch = Instruction.Create(OpCodes.Br_S, Instruction.Create(OpCodes.Nop));
        branch.Operand = branch;
        loop.Body.Instructions.Add(branch);

        var recursive = NewMethod(
            module,
            "Recursive",
            MethodSig.CreateStatic(module.CorLibTypes.Int32));
        recursive.Body.Instructions.Add(Instruction.Create(OpCodes.Call, recursive));
        recursive.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var allocate = NewMethod(
            module,
            "Allocate",
            MethodSig.CreateStatic(module.CorLibTypes.Void));
        allocate.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_2));
        allocate.Body.Instructions.Add(Instruction.Create(
            OpCodes.Newarr,
            module.CorLibTypes.Int32.TypeDefOrRef));
        allocate.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
        allocate.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        Assert.Equal(
            StaticExecutionStatus.StepLimitExceeded,
            new StaticMachine(new StaticMachineLimits(MaximumSteps: 3)).Execute(loop).Status);
        Assert.Equal(
            StaticExecutionStatus.RecursionLimitExceeded,
            new StaticMachine(new StaticMachineLimits(MaximumRecursionDepth: 2))
                .Execute(recursive).Status);
        Assert.Equal(
            StaticExecutionStatus.AllocationLimitExceeded,
            new StaticMachine(new StaticMachineLimits(MaximumAllocatedBytes: 4))
                .Execute(allocate).Status);
    }

    [Fact]
    public void DefaultIntrinsicsProvideDeterministicBitConverterAndRegionModels()
    {
        using var module = NewModule();
        var bitConverter = new TypeRefUser(
            module,
            "System",
            "BitConverter",
            module.CorLibTypes.AssemblyRef);
        var getBytes = new MemberRefUser(
            module,
            "GetBytes",
            MethodSig.CreateStatic(new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.Int32),
            bitConverter);
        var method = NewMethod(
            module,
            "Bytes",
            MethodSig.CreateStatic(new SZArraySig(module.CorLibTypes.Byte)));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x12345678));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getBytes));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        var machine = new StaticMachine();

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal([0x78, 0x56, 0x34, 0x12], machine.State.Heap.GetBytesSnapshot(result.Value));

        var marshal = new TypeRefUser(
            module,
            "System.Runtime.InteropServices",
            "Marshal",
            module.CorLibTypes.AssemblyRef);
        var allocate = new MemberRefUser(
            module,
            "AllocHGlobal",
            MethodSig.CreateStatic(module.CorLibTypes.IntPtr, module.CorLibTypes.Int32),
            marshal);
        var write = new MemberRefUser(
            module,
            "WriteInt32",
            MethodSig.CreateStatic(
                module.CorLibTypes.Void,
                module.CorLibTypes.IntPtr,
                module.CorLibTypes.Int32,
                module.CorLibTypes.Int32),
            marshal);
        var regionMethod = NewMethod(
            module,
            "Region",
            MethodSig.CreateStatic(module.CorLibTypes.IntPtr));
        regionMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_8));
        regionMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, allocate));
        regionMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Dup));
        regionMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_2));
        regionMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x12345678));
        regionMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, write));
        regionMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var regionResult = machine.Execute(regionMethod);

        Assert.Equal(StaticExecutionStatus.Completed, regionResult.Status);
        Assert.Equal(
            [0, 0, 0x78, 0x56, 0x34, 0x12, 0, 0],
            machine.State.Heap.GetBytesSnapshot(regionResult.Value));
        Assert.Contains(machine.State.Heap.ImageWrites,
            write => write.Offset == 2 && write.Bytes.SequenceEqual(
                new byte[] { 0x78, 0x56, 0x34, 0x12 }));
    }

    [Fact]
    public void ModelsStringsEncodingAndHashesWithoutRuntimeLoading()
    {
        using var module = NewModule();
        var encodingType = new TypeRefUser(
            module, "System.Text", "Encoding", module.CorLibTypes.AssemblyRef);
        var utf8 = new MemberRefUser(
            module,
            "get_UTF8",
            MethodSig.CreateStatic(new ClassSig(encodingType)),
            encodingType);
        var getBytes = new MemberRefUser(
            module,
            "GetBytes",
            MethodSig.CreateInstance(
                new SZArraySig(module.CorLibTypes.Byte),
                module.CorLibTypes.String),
            encodingType);
        var shaType = new TypeRefUser(
            module,
            "System.Security.Cryptography",
            "SHA256",
            module.CorLibTypes.AssemblyRef);
        var create = new MemberRefUser(
            module,
            "Create",
            MethodSig.CreateStatic(new ClassSig(shaType)),
            shaType);
        var computeHash = new MemberRefUser(
            module,
            "ComputeHash",
            MethodSig.CreateInstance(
                new SZArraySig(module.CorLibTypes.Byte),
                new SZArraySig(module.CorLibTypes.Byte)),
            shaType);
        var method = NewMethod(
            module,
            "HashText",
            MethodSig.CreateStatic(new SZArraySig(module.CorLibTypes.Byte)));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, create));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, utf8));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "reactor"));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getBytes));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, computeHash));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        var machine = new StaticMachine();

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes("reactor")),
            machine.State.Heap.GetBytesSnapshot(result.Value));
    }

    [Theory]
    [InlineData("System.Security.Cryptography.MD5", "", "D41D8CD98F00B204E9800998ECF8427E")]
    [InlineData("System.Security.Cryptography.MD5", "abc", "900150983CD24FB0D6963F7D28E17F72")]
    [InlineData(
        "System.Security.Cryptography.SHA256",
        "",
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")]
    [InlineData(
        "System.Security.Cryptography.SHA256",
        "abc",
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
    public void HashIntrinsicsMatchKnownAnswers(
        string typeName,
        string text,
        string expectedHex)
    {
        using var module = NewModule();
        var state = new StaticMachineState(new StaticMachineLimits());
        var separator = typeName.LastIndexOf('.');
        var hashType = new TypeRefUser(
            module,
            typeName[..separator],
            typeName[(separator + 1)..],
            module.CorLibTypes.AssemblyRef);
        var create = new MemberRefUser(
            module,
            "Create",
            MethodSig.CreateStatic(new ClassSig(hashType)),
            hashType);
        var computeHash = new MemberRefUser(
            module,
            "ComputeHash",
            MethodSig.CreateInstance(
                new SZArraySig(module.CorLibTypes.Byte),
                new SZArraySig(module.CorLibTypes.Byte)),
            hashType);
        var intrinsic = new LoaderFrameworkIntrinsic();
        var created = intrinsic.Invoke(new IntrinsicContext(state), create, []);
        Assert.True(state.Heap.TryAllocateByteArray(
            System.Text.Encoding.ASCII.GetBytes(text),
            out var input));

        var result = intrinsic.Invoke(
            new IntrinsicContext(state),
            computeHash,
            [created.Value, input]);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(
            Convert.FromHexString(expectedHex),
            state.Heap.GetBytesSnapshot(result.Value));
    }

    [Fact]
    public void HashIntrinsicsMatchBoundaryLengthReferences()
    {
        using var module = NewModule();
        var intrinsic = new LoaderFrameworkIntrinsic();
        foreach (var length in new[] { 55, 56, 63, 64, 65, 127, 128 })
        {
            var bytes = Enumerable.Range(0, length)
                .Select(index => unchecked((byte)(index * 37 + 11)))
                .ToArray();
            foreach (var typeName in new[]
                     {
                         "System.Security.Cryptography.MD5",
                         "System.Security.Cryptography.SHA256"
                     })
            {
                var state = new StaticMachineState(new StaticMachineLimits());
                var separator = typeName.LastIndexOf('.');
                var hashType = new TypeRefUser(
                    module,
                    typeName[..separator],
                    typeName[(separator + 1)..],
                    module.CorLibTypes.AssemblyRef);
                var create = new MemberRefUser(
                    module,
                    "Create",
                    MethodSig.CreateStatic(new ClassSig(hashType)),
                    hashType);
                var computeHash = new MemberRefUser(
                    module,
                    "ComputeHash",
                    MethodSig.CreateInstance(
                        new SZArraySig(module.CorLibTypes.Byte),
                        new SZArraySig(module.CorLibTypes.Byte)),
                    hashType);
                var created = intrinsic.Invoke(new IntrinsicContext(state), create, []);
                Assert.True(state.Heap.TryAllocateByteArray(bytes, out var input));
                var result = intrinsic.Invoke(
                    new IntrinsicContext(state),
                    computeHash,
                    [created.Value, input]);
                var expected = typeName.EndsWith("MD5", StringComparison.Ordinal)
                    ? System.Security.Cryptography.MD5.HashData(bytes)
                    : System.Security.Cryptography.SHA256.HashData(bytes);

                Assert.Equal(expected, state.Heap.GetBytesSnapshot(result.Value));
            }
        }
    }
#pragma warning restore CA5351

    [Fact]
    public void ModelsNewobjInstanceFieldsAndManagedLocalReferences()
    {
        using var module = NewModule();
        var holder = new TypeDefUser("Tests", "Instance", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(holder);
        var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32));
        holder.Fields.Add(field);
        var constructor = new MethodDefUser(
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodAttributes.Public | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        holder.Methods.Add(constructor);
        constructor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        constructor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 41));
        constructor.Body.Instructions.Add(Instruction.Create(OpCodes.Stfld, field));
        constructor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var objectMethod = NewMethod(
            module,
            "Object",
            MethodSig.CreateStatic(module.CorLibTypes.Int32));
        objectMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, constructor));
        objectMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldfld, field));
        objectMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var referenceMethod = NewMethod(
            module,
            "Reference",
            MethodSig.CreateStatic(module.CorLibTypes.Int32));
        referenceMethod.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
        referenceMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        referenceMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));
        referenceMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S,
            referenceMethod.Body.Variables[0]));
        referenceMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 42));
        referenceMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));
        referenceMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
        referenceMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        Assert.Equal(41, new StaticMachine().Execute(objectMethod).Value.AsInt32());
        Assert.Equal(42, new StaticMachine().Execute(referenceMethod).Value.AsInt32());
    }

    [Fact]
    public void ResourceModelsRequireExplicitRegistration()
    {
        var machine = new StaticMachine();

        Assert.False(machine.State.TryOpenResource("payload", out _));
        machine.State.RegisterResource("payload", [1, 2, 3]);

        Assert.True(machine.State.TryOpenResource("payload", out var stream));
        Assert.True(machine.State.Heap.TryGetModelValue(stream, "Buffer", out StaticValue buffer));
        Assert.Equal([1, 2, 3], machine.State.Heap.GetBytesSnapshot(buffer));
    }

    [Fact]
    public void NativeAddressesRoundTripThroughBoundedRegions()
    {
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateRegion(
            new byte[32],
            "MappedImage",
            0x0040_0000,
            out var image));
        Assert.True(heap.TryGetNativePointer(image, 12, out var pointer));
        Assert.True(heap.TryGetNativeAddress(pointer, out var address));
        Assert.Equal(0x0040_000C, address);
        Assert.True(heap.TryResolveNativeAddress(address, out var resolved));
        Assert.Equal(pointer, resolved);
        Assert.False(heap.TryResolveNativeAddress(0x0040_0021, out _));
    }

    [Fact]
    public void OpenProcessDelegateReturnsOnlyModeledCurrentProcessHandles()
    {
        using var module = NewModule();
        var delegateType = new TypeDefUser(
            "Tests",
            "OpenProcessDelegate",
            module.CorLibTypes.Object.TypeDefOrRef)
        {
            BaseType = module.CorLibTypes.GetTypeRef("System", "MulticastDelegate")
        };
        module.Types.Add(delegateType);
        var invoke = new MethodDefUser(
            "Invoke",
            MethodSig.CreateInstance(
                module.CorLibTypes.IntPtr,
                module.CorLibTypes.UInt32,
                module.CorLibTypes.Boolean,
                module.CorLibTypes.UInt32));
        delegateType.Methods.Add(invoke);
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateObject("System.Delegate", out var receiver));
        Assert.True(state.Heap.TrySetModelValue(receiver, "NativeName", "OpenProcess"));
        var intrinsic = new NativeDelegateIntrinsic();

        var opened = intrinsic.Invoke(
            new IntrinsicContext(state),
            invoke,
            [receiver, StaticValue.FromInt32(56), StaticValue.FromInt32(1), StaticValue.FromInt32(1)]);
        var denied = intrinsic.Invoke(
            new IntrinsicContext(state),
            invoke,
            [receiver, StaticValue.FromInt32(56), StaticValue.FromInt32(1), StaticValue.FromInt32(2)]);

        Assert.Equal(StaticExecutionStatus.Completed, opened.Status);
        Assert.True(state.Heap.TryGetModelValue(opened.Value, "ProcessId", out int processId));
        Assert.Equal(1, processId);
        Assert.Equal(StaticExecutionStatus.InvalidProgram, denied.Status);
    }

    /// <summary>
    /// A loader can reach its own image either by walking <c>Process.Modules</c> or by asking for
    /// <c>MainModule</c>. Both have to describe the analysed image, and the path it names has to be
    /// the one file this machine will open, or a loader that reads its own bytes is refused.
    /// </summary>
    [Fact]
    public void MainModuleDescribesTheAnalysedImageAndItsRegisteredPath()
    {
        using var module = NewModule();
        var process = new TypeRefUser(
            module,
            "System.Diagnostics",
            "Process",
            module.CorLibTypes.AssemblyRef);
        var processModule = new TypeRefUser(
            module,
            "System.Diagnostics",
            "ProcessModule",
            module.CorLibTypes.AssemblyRef);
        var mainModule = new MemberRefUser(
            module,
            "get_MainModule",
            MethodSig.CreateInstance(processModule.ToTypeSig()),
            process);
        var baseAddress = new MemberRefUser(
            module,
            "get_BaseAddress",
            MethodSig.CreateInstance(module.CorLibTypes.IntPtr),
            processModule);
        var fileName = new MemberRefUser(
            module,
            "get_FileName",
            MethodSig.CreateInstance(module.CorLibTypes.String),
            processModule);
        var state = new StaticMachineState(new StaticMachineLimits());
        state.RegisterAssemblyIdentity("subject", []);
        state.RegisterModuleFile("/samples/subject.exe", new byte[64]);
        Assert.True(state.TryRegisterImage(new byte[4096], 0x0040_0000));
        Assert.True(state.Heap.TryAllocateObject("System.Diagnostics.Process", out var receiver));
        var intrinsic = new LoaderFrameworkIntrinsic();
        var context = new IntrinsicContext(state);

        var main = intrinsic.Invoke(context, mainModule, [receiver]);
        Assert.Equal(StaticExecutionStatus.Completed, main.Status);
        var located = intrinsic.Invoke(context, baseAddress, [main.Value]);
        var named = intrinsic.Invoke(context, fileName, [main.Value]);

        Assert.True(state.Heap.TryGetNativeAddress(located.Value, out var address));
        Assert.Equal(0x0040_0000, address);
        Assert.True(state.Heap.TryGetString(named.Value, out var path));
        Assert.Equal("/samples/subject.exe", path);
    }

    /// <summary>
    /// Without a registered image there is no main module to describe, and saying so is the honest
    /// answer rather than handing back the runtime's own module.
    /// </summary>
    [Fact]
    public void MainModuleIsRefusedBeforeTheImageIsRegistered()
    {
        using var module = NewModule();
        var process = new TypeRefUser(
            module,
            "System.Diagnostics",
            "Process",
            module.CorLibTypes.AssemblyRef);
        var processModule = new TypeRefUser(
            module,
            "System.Diagnostics",
            "ProcessModule",
            module.CorLibTypes.AssemblyRef);
        var mainModule = new MemberRefUser(
            module,
            "get_MainModule",
            MethodSig.CreateInstance(processModule.ToTypeSig()),
            process);
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateObject("System.Diagnostics.Process", out var receiver));

        var refused = new LoaderFrameworkIntrinsic()
            .Invoke(new IntrinsicContext(state), mainModule, [receiver]);

        Assert.Equal(StaticExecutionStatus.InvalidProgram, refused.Status);
    }

    /// <summary>
    /// A type named by metadata token is the type that token names, and says so afterwards.
    /// </summary>
    /// <remarks>
    /// Turning a token into a handle and the handle into a type is how Reactor's runtime names types it
    /// never mentions by reference. A token means nothing outside the module it was read from, so if it
    /// is handed on as the number it arrived as, what comes back describes a type with no name — and a
    /// type with no name cannot be asked which assembly declares it. The run then stops on a question
    /// about the assembly it is already reading, several thousand frames from the token.
    /// </remarks>
    [Fact]
    public void ATypeNamedByMetadataTokenIsTheTypeItNames()
    {
        using var module = ModuleDefMD.Load(typeof(StaticMachineTests).Module);
        var declared = module.Find("Cilantro.Tests.StaticMachineTests", false);
        Assert.NotNull(declared);
        var handleType = new TypeRefUser(
            module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef);
        var typeType = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
        var fromToken = new MemberRefUser(
            module,
            "GetRuntimeTypeHandleFromMetadataToken",
            MethodSig.CreateInstance(handleType.ToTypeSig(), module.CorLibTypes.Int32),
            new TypeRefUser(module, "System", "ModuleHandle", module.CorLibTypes.AssemblyRef));
        var fromHandle = new MemberRefUser(
            module,
            "GetTypeFromHandle",
            MethodSig.CreateStatic(typeType.ToTypeSig(), handleType.ToTypeSig()),
            typeType);
        var declaringAssembly = new MemberRefUser(
            module,
            "get_Assembly",
            MethodSig.CreateInstance(
                new TypeRefUser(
                    module,
                    "System.Reflection",
                    "Assembly",
                    module.CorLibTypes.AssemblyRef).ToTypeSig()),
            typeType);
        var spelling = new MemberRefUser(
            module, "get_FullName", MethodSig.CreateInstance(module.CorLibTypes.String), typeType);
        var state = new StaticMachineState(new StaticMachineLimits());
        state.RegisterModuleMetadata(module);
        Assert.True(state.Heap.TryAllocateObject("System.ModuleHandle", out var owning));
        var intrinsic = new LoaderFrameworkIntrinsic();
        var context = new IntrinsicContext(state);

        var handed = intrinsic.Invoke(
            context,
            fromToken,
            [owning, StaticValue.FromInt32((int)declared.MDToken.Raw)]);
        Assert.Equal(StaticExecutionStatus.Completed, handed.Status);
        var described = intrinsic.Invoke(context, fromHandle, [handed.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, described.Status);

        var named = intrinsic.Invoke(context, spelling, [described.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, named.Status);
        Assert.True(state.Heap.TryGetString(named.Value, out var spelled));
        Assert.Equal("Cilantro.Tests.StaticMachineTests", spelled);

        // And because the type is known, so is the file that declares it.
        var owner = intrinsic.Invoke(context, declaringAssembly, [described.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, owner.Status);
        Assert.True(state.Heap.TryGetModelValue<bool>(
            owner.Value, LoaderFrameworkIntrinsic.HomeModuleMark, out var home));
        Assert.True(home);
    }

    /// <summary>
    /// The sequence a loader uses to fetch a payload it hid in its own <c>RT_RCDATA</c>, end to end.
    /// What comes back has to be the resource's real bytes: the point of modelling this API is that
    /// the payload is readable, not that the calls return something.
    /// </summary>
    [Fact]
    public void ResourceApiHandsBackTheImagesOwnResourceBytes()
    {
        byte[] payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22];
        var image = ArchitectureTests.ImageWithRcdataResource("PAYLOAD", payload);
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.TryRegisterImage(image, 0x0040_0000));
        var heap = state.Heap;
        Assert.True(heap.TryGetNativePointer(state.ImageRegion, 0, out var imageBase));
        Assert.True(heap.TryAllocateString("PAYLOAD", out var name));
        using var module = NewModule();
        var invoke = NativeDelegateInvoke(module);
        var intrinsic = new NativeDelegateIntrinsic();
        var context = new IntrinsicContext(state);

        StaticValue Call(string nativeName, params StaticValue[] arguments)
        {
            Assert.True(heap.TryAllocateObject("System.Delegate", out var target));
            Assert.True(heap.TrySetModelValue(target, "NativeName", nativeName));
            var result = intrinsic.Invoke(context, invoke, [target, .. arguments]);
            Assert.Equal(StaticExecutionStatus.Completed, result.Status);
            return result.Value;
        }

        var found = Call(
            "FindResourceA",
            imageBase,
            name,
            StaticValue.FromInt32(ArchitectureTests.RcdataType));
        var size = Call("SizeofResource", imageBase, found);
        var loaded = Call("LoadResource", imageBase, found);
        var locked = Call("LockResource", loaded);

        Assert.Equal(payload.Length, size.AsInt32());
        // FindResource yields a pointer to the resource entry, as it does on Windows, and the entry
        // is at the RVA the directory said.
        Assert.True(heap.TryGetNativeAddress(found, out var entryAddress));
        Assert.Equal(0x0040_0000 + 0x1048, entryAddress);
        Assert.True(heap.TryGetNativeAddress(locked, out var payloadAddress));
        Assert.Equal(0x0040_0000 + ArchitectureTests.PayloadRva, (ulong)payloadAddress);
        var read = new byte[payload.Length];
        Assert.True(heap.TryReadBytes(locked, 0, read));
        Assert.Equal(payload, read);
    }

    /// <summary>
    /// A resource the image does not carry is a null handle rather than a refusal, because a loader
    /// may probe for one and branch on the answer.
    /// </summary>
    [Fact]
    public void ResourceApiReportsAnAbsentResourceAsNull()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.TryRegisterImage(
            ArchitectureTests.ImageWithRcdataResource("PAYLOAD", [1, 2, 3]),
            0x0040_0000));
        var heap = state.Heap;
        Assert.True(heap.TryGetNativePointer(state.ImageRegion, 0, out var imageBase));
        Assert.True(heap.TryAllocateString("ABSENT", out var name));
        using var module = NewModule();
        Assert.True(heap.TryAllocateObject("System.Delegate", out var target));
        Assert.True(heap.TrySetModelValue(target, "NativeName", "FindResourceA"));

        var result = new NativeDelegateIntrinsic().Invoke(
            new IntrinsicContext(state),
            NativeDelegateInvoke(module),
            [target, imageBase, name, StaticValue.FromInt32(ArchitectureTests.RcdataType)]);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(0, result.Value.AsInt64());
    }

    /// <summary>
    /// The resources of some other module are not this machine's to read, and a handle that does not
    /// name the analysed image is refused rather than quietly treated as if it did.
    /// </summary>
    [Fact]
    public void ResourceApiRefusesAModuleThatIsNotTheAnalysedImage()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.TryRegisterImage(
            ArchitectureTests.ImageWithRcdataResource("PAYLOAD", [1, 2, 3]),
            0x0040_0000));
        var heap = state.Heap;
        Assert.True(heap.TryAllocateRegion(4096, "RuntimeModule", out var otherModule));
        Assert.True(heap.TryAllocateString("PAYLOAD", out var name));
        using var module = NewModule();
        Assert.True(heap.TryAllocateObject("System.Delegate", out var target));
        Assert.True(heap.TrySetModelValue(target, "NativeName", "FindResourceA"));

        var result = new NativeDelegateIntrinsic().Invoke(
            new IntrinsicContext(state),
            NativeDelegateInvoke(module),
            [target, otherModule, name, StaticValue.FromInt32(ArchitectureTests.RcdataType)]);

        Assert.Equal(StaticExecutionStatus.InvalidProgram, result.Status);
    }

    private static MethodDefUser NativeDelegateInvoke(ModuleDef module)
    {
        var delegateType = new TypeDefUser(
            "Tests",
            "NativeDelegate",
            module.CorLibTypes.Object.TypeDefOrRef)
        {
            BaseType = module.CorLibTypes.GetTypeRef("System", "MulticastDelegate")
        };
        module.Types.Add(delegateType);
        var invoke = new MethodDefUser(
            "Invoke",
            MethodSig.CreateInstance(module.CorLibTypes.IntPtr));
        delegateType.Methods.Add(invoke);
        return invoke;
    }

    [Fact]
    public void ProcessModuleBaseAddressHasStableSyntheticIdentity()
    {
        using var module = NewModule();
        var processModule = new TypeRefUser(
            module,
            "System.Diagnostics",
            "ProcessModule",
            module.CorLibTypes.AssemblyRef);
        var getter = new MemberRefUser(
            module,
            "get_BaseAddress",
            MethodSig.CreateInstance(module.CorLibTypes.IntPtr),
            processModule);
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateObject("System.Diagnostics.ProcessModule", out var receiver));
        var intrinsic = new LoaderFrameworkIntrinsic();

        var first = intrinsic.Invoke(new IntrinsicContext(state), getter, [receiver]);
        var second = intrinsic.Invoke(new IntrinsicContext(state), getter, [receiver]);

        Assert.Equal(StaticExecutionStatus.Completed, first.Status);
        Assert.Equal(first.Value, second.Value);
        Assert.False(state.Heap.TryReadBytes(first.Value, 0, new byte[4]));
    }

    [Fact]
    public void ManagedInteriorPointersProvideBoundedByteAccess()
    {
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateByteArray([1, 2, 3, 4], out var array));
        Assert.True(heap.TryGetArrayElementReference(array, 1, out var interior));
        Span<byte> read = stackalloc byte[2];
        Assert.True(heap.TryReadBytes(interior, 0, read));
        Assert.Equal([2, 3], read.ToArray());
        Assert.True(heap.TryWriteBytes(interior, 1, [9, 8]));
        Assert.Equal([1, 2, 9, 8], heap.GetBytesSnapshot(array));
        Assert.False(heap.TryWriteBytes(interior, 3, [7]));
    }

    [Fact]
    public void ManagedIndirectStoresTruncateToOpcodeWidth()
    {
        using var module = NewModule();
        var method = NewMethod(
            module,
            "TruncateIndirect",
            MethodSig.CreateStatic(module.CorLibTypes.Int32));
        method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, method.Body.Variables[0]));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I8, 0x1122334455667788L));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(0x55667788, result.Value.AsInt32());
    }

    [Fact]
    public void StaticFieldAddressesAliasTheirBackingStorage()
    {
        using var module = NewModule();
        var field = new FieldDefUser(
            "Value",
            new FieldSig(module.CorLibTypes.Int32),
            FieldAttributes.Static);
        module.Types.Single(type => type.Name == "<Module>").Fields.Add(field);
        var state = new StaticMachineState(new StaticMachineLimits());

        var first = state.GetStaticFieldReference(field);
        var second = state.GetStaticFieldReference(field);
        Assert.Equal(first, second);
        var tracked = state.Provenance.Origin(
            StaticValue.FromInt32(41), ProvenanceKind.Literal, "test", "alias");
        Assert.True(state.Heap.TryWriteManaged(first, tracked));
        Assert.Equal(41, state.ReadStaticField(field).AsInt32());
        Assert.Equal(tracked.ProvenanceId, state.ReadStaticField(field).ProvenanceId);
        state.WriteStaticField(field, StaticValue.FromInt32(42));
        Assert.True(state.Heap.TryReadManaged(second, out var referenced));
        Assert.Equal(42, referenced.AsInt32());
    }

    [Fact]
    public void IntPtrConstructorsWriteThroughManagedLocalAddresses()
    {
        using var module = NewModule();
        var intPtr = new TypeRefUser(
            module,
            "System",
            "IntPtr",
            module.CorLibTypes.AssemblyRef);
        var constructor = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int64),
            intPtr);
        var toInt64 = new MemberRefUser(
            module,
            "ToInt64",
            MethodSig.CreateInstance(module.CorLibTypes.Int64),
            intPtr);
        var method = NewMethod(
            module,
            "PointerLocal",
            MethodSig.CreateStatic(module.CorLibTypes.Int64));
        method.Body.Variables.Add(new Local(module.CorLibTypes.IntPtr));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, method.Body.Variables[0]));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I8, 0x1234_5678_9ABC));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, constructor));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, method.Body.Variables[0]));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, toInt64));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(0x1234_5678_9ABC, result.Value.AsInt64());
    }

    [Fact]
    public void ExecutesDeterministicLeaveThroughFinally()
    {
        using var module = NewModule();
        var method = NewMethod(
            module,
            "Finally",
            MethodSig.CreateStatic(module.CorLibTypes.Int32));
        method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
        var tryStart = Instruction.Create(OpCodes.Ldc_I4_1);
        var tryEnd = Instruction.Create(OpCodes.Ldc_I4_2);
        var handlerEnd = Instruction.Create(OpCodes.Ldloc_0);
        method.Body.Instructions.Add(tryStart);
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Leave_S, handlerEnd));
        method.Body.Instructions.Add(tryEnd);
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Endfinally));
        method.Body.Instructions.Add(handlerEnd);
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
        {
            TryStart = tryStart,
            TryEnd = tryEnd,
            HandlerStart = tryEnd,
            HandlerEnd = handlerEnd
        });

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(2, result.Value.AsInt32());
    }

    [Fact]
    public void AReferenceComparedAsAnUnsignedNumberIsReadAsATestForNull()
    {
        using var module = NewModule();
        var absent = NewMethod(
            module,
            "NothingIsNotSomething",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            OpCodes.Ldnull,
            OpCodes.Ldnull,
            OpCodes.Cgt_Un,
            OpCodes.Ret);
        var present = new MethodDefUser(
            "SomethingIsNotNothing",
            MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        module.Types.First(type => type.Name == "Program").Methods.Add(present);
        present.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        present.Body.Instructions.Add(Instruction.Create(
            OpCodes.Newarr, module.CorLibTypes.Int32.ToTypeDefOrRef()));
        present.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
        present.Body.Instructions.Add(Instruction.Create(OpCodes.Cgt_Un));
        present.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var nothing = new StaticMachine().Execute(absent);
        var something = new StaticMachine().Execute(
            present, [StaticValue.FromInt32(1)]);

        Assert.Equal(StaticExecutionStatus.Completed, nothing.Status);
        Assert.Equal(0, nothing.Value.AsInt32());
        Assert.True(something.Status == StaticExecutionStatus.Completed, something.Diagnostic);
        Assert.Equal(1, something.Value.AsInt32());
    }

    [Fact]
    public void AskingWhetherADebuggerIsAttachedIsAnsweredNoAndSaidOutLoud()
    {
        using var module = NewModule();
        var state = new StaticMachineState(new StaticMachineLimits());
        var debugger = new TypeRefUser(
            module, "System.Diagnostics", "Debugger", module.CorLibTypes.AssemblyRef);
        var asked = new MemberRefUser(
            module,
            "get_IsAttached",
            MethodSig.CreateStatic(module.CorLibTypes.Boolean),
            debugger);
        var intrinsic = new DebuggerIntrinsic();

        var answered = intrinsic.Invoke(new IntrinsicContext(state), asked, []);

        Assert.True(intrinsic.Matches(asked));
        Assert.Equal(StaticExecutionStatus.Completed, answered.Status);
        Assert.Equal(0, answered.Value.AsInt32());
        Assert.Contains(
            state.LoaderEvidence.Observations,
            observation => observation.Kind == LoaderObservationKind.DebuggerProbe);
    }

    /// <summary>
    /// The shape of Reactor's per-string decoders: a literal taken apart, altered in place, and put
    /// back together. Every step of it has to work for the string to come out.
    /// </summary>
    [Fact]
    public void AStringTakenApartIntoCharactersAndPutBackTogetherSurvivesTheTrip()
    {
        using var module = NewModule();
        var text = new TypeRefUser(module, "System", "String", module.CorLibTypes.AssemblyRef);
        var characters = new SZArraySig(module.CorLibTypes.Char);
        var apart = new MemberRefUser(
            module, "ToCharArray", MethodSig.CreateInstance(characters), text);
        var together = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, characters),
            text);
        var method = NewMethod(
            module, "Decode", MethodSig.CreateStatic(module.CorLibTypes.String));
        var body = method.Body.Instructions;
        method.Body.Variables.Add(new Local(characters));
        body.Add(Instruction.Create(OpCodes.Ldstr, "ZA^"));
        body.Add(Instruction.Create(OpCodes.Call, apart));
        body.Add(Instruction.Create(OpCodes.Stloc_0));
        for (var index = 0; index < 3; index++)
        {
            body.Add(Instruction.Create(OpCodes.Ldloc_0));
            body.Add(Instruction.Create(OpCodes.Ldc_I4, index));
            body.Add(Instruction.Create(OpCodes.Ldloc_0));
            body.Add(Instruction.Create(OpCodes.Ldc_I4, index));
            body.Add(Instruction.Create(OpCodes.Ldelem_U2));
            body.Add(Instruction.Create(OpCodes.Ldc_I4, 0x2E));
            body.Add(Instruction.Create(OpCodes.Xor));
            body.Add(Instruction.Create(OpCodes.Conv_U2));
            body.Add(Instruction.Create(OpCodes.Stelem_I2));
        }
        body.Add(Instruction.Create(OpCodes.Ldloc_0));
        body.Add(Instruction.Create(OpCodes.Newobj, together));
        body.Add(Instruction.Create(OpCodes.Ret));

        var machine = new StaticMachine();
        var answered = machine.Execute(method);

        Assert.True(answered.Status == StaticExecutionStatus.Completed, answered.Diagnostic);
        Assert.True(machine.State.Heap.TryGetString(answered.Value, out var read));
        Assert.Equal("top", read);
    }

    [Fact]
    public void AnArrayThatCannotHoldWhatIsStoredInItSaysSoRatherThanBlamingTheIndex()
    {
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateArray(null, 4, out var untyped));

        var stored = heap.TryWriteArray(untyped, 1, StaticValue.FromInt32(7), out var inBounds);
        var past = heap.TryWriteArray(untyped, 9, StaticValue.FromInt32(7), out var beyond);

        // An array with no element type coerces to nothing, so it keeps what it is handed.
        Assert.True(stored);
        Assert.True(inBounds);
        Assert.False(past);
        Assert.False(beyond);
    }

    /// <summary>
    /// An array of an enum holds the numbers the enum is written on, both ways round.
    /// </summary>
    /// <remarks>
    /// The IL that fills one stores an int and reads an int back, so refusing the store because the
    /// enum's own name is not a primitive leaves the array holding the zeroes it was made with — and
    /// nothing downstream that reads it can tell that from a table of zeroes the program meant.
    /// </remarks>
    [Fact]
    public void AnArrayOfAnEnumHoldsTheNumbersItIsWrittenOn()
    {
        using var module = NewModule();
        var enumerated = new TypeDefUser(
            "Tests", "Sized", module.CorLibTypes.GetTypeRef("System", "Enum"));
        enumerated.Fields.Add(new FieldDefUser(
            "value__",
            new FieldSig(module.CorLibTypes.Byte),
            FieldAttributes.Public | FieldAttributes.SpecialName | FieldAttributes.RTSpecialName));
        module.Types.Add(enumerated);
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateArray(enumerated.ToTypeSig(), 2, out var values));

        Assert.True(heap.TryWriteArray(values, 0, StaticValue.FromInt32(3)));
        // The store is coerced by the underlying byte, not by the name the metadata gives it.
        Assert.True(heap.TryWriteArray(values, 1, StaticValue.FromInt32(0x0102)));

        Assert.True(heap.TryReadArray(values, 0, out var first));
        Assert.Equal(3, first.AsInt32());
        Assert.True(heap.TryReadArray(values, 1, out var second));
        Assert.Equal(2, second.AsInt32());
        // What it says it holds is still the enum, so everything comparing element names is unmoved.
        Assert.True(heap.TryGetArrayElementType(values, out var named));
        Assert.Equal("Tests.Sized", named);
    }

    /// <summary>A value type whose width is genuinely unknown is still refused.</summary>
    [Fact]
    public void AnArrayOfAnUnresolvableValueTypeStillRefusesANumber()
    {
        using var module = NewModule();
        var unresolved = new TypeRefUser(module, "Absent", "Shape", module.CorLibTypes.AssemblyRef);
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateArray(new ValueTypeSig(unresolved), 1, out var values));

        Assert.False(heap.TryWriteArray(values, 0, StaticValue.FromInt32(3), out var inBounds));
        Assert.True(inBounds);
    }

    /// <summary>
    /// An enum the module only refers to is sized by the instruction storing into it.
    /// </summary>
    [Fact]
    public void AnArrayOfAnEnumFromAnAbsentCorlibIsSizedByTheStore()
    {
        using var module = NewModule();
        // Nothing hands this reader a corlib, so the element type resolves to nothing at all, which
        // is exactly the position the pipeline is in on a framework enum.
        var referenced = new TypeRefUser(
            module, "Microsoft.Win32", "RegistryView", module.CorLibTypes.AssemblyRef);
        Assert.Null(referenced.ResolveTypeDef());
        var heap = new StaticHeap(new StaticMachineLimits());
        // A class rather than a value type, which is what dnlib makes of a reference it cannot
        // resolve however the type it names is declared, and so is what a newarr operand arrives as.
        Assert.Equal(ElementType.Class, referenced.ToTypeSig().ElementType);
        Assert.True(heap.TryAllocateArray(referenced.ToTypeSig(), 2, out var views));

        Assert.True(
            heap.TryWriteArray(views, 0, StaticValue.FromInt32(0x200), "System.Int32", out var wide));
        Assert.True(wide);
        Assert.True(heap.TryReadArray(views, 0, out var held));
        Assert.Equal(0x200, held.AsInt32());

        // A narrower store is coerced to what it says it stores, not widened to what it was given.
        Assert.True(heap.TryWriteArray(views, 1, StaticValue.FromInt32(0x0102), "System.Byte", out _));
        Assert.True(heap.TryReadArray(views, 1, out var narrow));
        Assert.Equal(2, narrow.AsInt32());

        // An array of something this reader can read keeps its own answer, whether the elements are
        // references or a type the file declares.
        Assert.True(heap.TryAllocateArray(module.CorLibTypes.String, 1, out var names));
        Assert.False(
            heap.TryWriteArray(names, 0, StaticValue.FromInt32(3), "System.Int32", out var inBounds));
        Assert.True(inBounds);
        var declared = new TypeDefUser("Tests", "Shape", module.CorLibTypes.Object.ToTypeDefOrRef());
        module.Types.Add(declared);
        Assert.True(heap.TryAllocateArray(declared.ToTypeSig(), 1, out var shapes));
        Assert.False(heap.TryWriteArray(shapes, 0, StaticValue.FromInt32(3), "System.Int32", out _));
    }

    private static ModuleDefUser NewModule()
    {
        var module = new ModuleDefUser("static-machine.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("static-machine", new Version(1, 0));
        assembly.Modules.Add(module);
        return module;
    }

    private static MethodDefUser NewMethod(
        ModuleDef module,
        string name,
        MethodSig signature,
        params OpCode[] opCodes)
    {
        var method = new MethodDefUser(name, signature)
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        var type = module.Types.FirstOrDefault(item => item.Name == "Program");
        if (type is null)
        {
            type = new TypeDefUser("Tests", "Program", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);
        }
        type.Methods.Add(method);
        foreach (var opCode in opCodes)
            method.Body.Instructions.Add(Instruction.Create(opCode));
        return method;
    }
}
