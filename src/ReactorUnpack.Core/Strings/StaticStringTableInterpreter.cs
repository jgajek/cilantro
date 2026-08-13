using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Codec;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Core.Strings;

public sealed record StaticStringTableCapture(
    string Source,
    byte[] Bytes,
    IReadOnlyList<DecodedStringRecord> Records,
    IReadOnlyDictionary<uint, int> IntegerFields,
    int Steps,
    string FrontEnd);

public static class StaticStringTableInterpreter
{
    private sealed record VmInstruction(byte OpCode, object? Operand);
    private sealed record VmMethod(IReadOnlyList<VmInstruction> Instructions, int LocalCount);

    private static readonly StaticMachineLimits Limits = new(
        MaximumSteps: 4_000_000,
        MaximumRecursionDepth: 96,
        MaximumAllocatedBytes: 64 * 1024 * 1024,
        MaximumArrayLength: 16 * 1024 * 1024);

    public static bool TryCapture(
        ModuleDefMD module,
        PeImageView image,
        MethodDef resolver,
        out StaticStringTableCapture? capture,
        out string diagnostic,
        RunEnvironment? environment = null)
    {
        capture = null;
        var resourceName = FindResourceName(resolver);
        var initializer = FindInitializer(resolver);
        if (resourceName is null || initializer is null)
        {
            diagnostic = "The resolver's resource-backed static initializer was not structurally identified.";
            return false;
        }

        if (module.Resources.OfType<EmbeddedResource>()
                .SingleOrDefault(resource => resource.Name == resourceName) is not { } resource)
        {
            diagnostic = $"The initializer resource '{resourceName}' is missing or ambiguous.";
            return false;
        }

        var runs = new List<(byte[] Bytes, IReadOnlyList<DecodedStringRecord> Records,
            IReadOnlyDictionary<uint, int> IntegerFields, int Steps, string FrontEnd)>();
        foreach (var offset in new[] { 0, 1 })
        {
            if (!TryRun(module, image, initializer, resourceName,
                    resource.CreateReader().ToArray(), offset, environment, out var run,
                    out diagnostic))
                return false;
            runs.Add(run);
        }
        if (!runs[0].Bytes.AsSpan().SequenceEqual(runs[1].Bytes))
        {
            diagnostic =
                "The pristine table depended on the resolver offset in two bounded interpretations.";
            return false;
        }
        if (runs[0].IntegerFields.Count != runs[1].IntegerFields.Count ||
            runs[0].IntegerFields.Any(field =>
                !runs[1].IntegerFields.TryGetValue(field.Key, out var value) ||
                value != field.Value))
        {
            diagnostic =
                "VM-initialized integer fields depended on the resolver offset.";
            return false;
        }

        var frontEnd = IsVmBridge(initializer) ? "reactor-vm-method-0/1" : "managed-cil";
        capture = new StaticStringTableCapture(
            $"{initializer.MDToken} {initializer.FullName}",
            runs[0].Bytes,
            runs[0].Records,
            runs[0].IntegerFields,
            runs[0].Steps,
            frontEnd);
        diagnostic =
            $"Bounded {frontEnd} interpretation captured one offset-independent table.";
        return true;
    }

    private static bool TryRun(
        ModuleDefMD module,
        PeImageView image,
        MethodDef initializer,
        string resourceName,
        byte[] resourceBytes,
        int offset,
        RunEnvironment? environment,
        out (byte[] Bytes, IReadOnlyList<DecodedStringRecord> Records,
            IReadOnlyDictionary<uint, int> IntegerFields, int Steps, string FrontEnd) run,
        out string diagnostic)
    {
        run = default;
        environment ??= new RunEnvironment();
        var machine = new StaticMachine(
            environment.Declarations.Budgets.Over(Limits),
            ProxyIntrinsicRegistry.Create(module));
        machine.State.RegisterRunEnvironment(environment);
        foreach (var resource in module.Resources.OfType<EmbeddedResource>())
            machine.State.RegisterResource(resource.Name, resource.CreateReader().ToArray());
        machine.State.RegisterAssemblyIdentity(
            module.Assembly?.Name ?? module.Name,
            module.Assembly?.PublicKeyToken?.Data ?? []);
        machine.State.RegisterPointerSize(image.IsPe32Plus ? 8 : 4);

        if (!machine.State.TryOpenResource(resourceName, out var stream))
        {
            diagnostic = $"Could not model resource stream '{resourceName}'.";
            return false;
        }
        var arguments = BuildArguments(machine, initializer, stream, offset);
        if (arguments is null)
        {
            diagnostic =
                $"Initializer {initializer.MDToken} does not have the supported (stream, int32) contract.";
            return false;
        }

        if (IsVmBridge(initializer))
        {
            if (!TryParseVmMethod(module, machine, initializer, 0, out var vmMethod,
                    out var vmDiagnostic))
            {
                diagnostic = vmDiagnostic;
                return false;
            }
            var evaluation = EvaluateVmMethodZero(module, machine, vmMethod, arguments);
            if (!evaluation.Success)
            {
                diagnostic = evaluation.Diagnostic;
                return false;
            }
            if (!TryParseVmMethod(module, machine, initializer, 1, out var vmMethodOne,
                    out var vmMethodOneDiagnostic))
            {
                diagnostic = vmMethodOneDiagnostic;
                return false;
            }
            var methodOneEvaluation = EvaluateVmMethodZero(
                module, machine, vmMethodOne, []);
            if (!methodOneEvaluation.Success)
            {
                diagnostic = $"Serialized VM ID 1: {methodOneEvaluation.Diagnostic}";
                return false;
            }
            var vmCandidates = CaptureFramedTables(machine);
            if (vmCandidates.Length != 1)
            {
                diagnostic = vmCandidates.Length == 0
                    ? $"VM ID 0 completed after {evaluation.Steps} steps but exposed no strictly framed UTF-16 table."
                    : $"VM ID 0 exposed {vmCandidates.Length} distinct strictly framed tables.";
                return false;
            }
            run = (vmCandidates[0].Bytes, vmCandidates[0].Records,
                CaptureIntegerFields(module, machine), evaluation.Steps,
                "reactor-vm-method-0-serialized");
            diagnostic = string.Empty;
            return true;
        }

        var result = machine.Execute(initializer, arguments);
        if (!result.Succeeded)
        {
            diagnostic =
                $"Bounded initializer {initializer.MDToken} stopped as {result.Status} " +
                $"after {result.Steps} steps: {result.Diagnostic}";
            return false;
        }

        var candidates = CaptureFramedTables(machine);
        if (candidates.Length != 1)
        {
            diagnostic = candidates.Length == 0
                ? $"Initializer {initializer.MDToken} completed but exposed no strictly framed UTF-16 table."
                : $"Initializer {initializer.MDToken} exposed {candidates.Length} distinct strictly framed tables.";
            return false;
        }

        run = (candidates[0].Bytes, candidates[0].Records,
            CaptureIntegerFields(module, machine), result.Steps, "managed-cil");
        diagnostic = string.Empty;
        return true;
    }

    private static (byte[] Bytes, IReadOnlyList<DecodedStringRecord> Records)[] CaptureFramedTables(
        StaticMachine machine) =>
        machine.State.StaticFields
            .Where(field => field.Value.Kind == StaticValueKind.HeapReference)
            .Select(field => (field.Key, Bytes: machine.State.Heap.GetBytesSnapshot(field.Value)))
            .Where(item => item.Bytes is { Length: > 0 })
            .Select(item => (item.Key, Bytes: item.Bytes!,
                Valid: StrictStringTable.TryDecodeComplete(item.Bytes!, out var records),
                Records: records))
            .Where(item => item.Valid)
            .GroupBy(item => Convert.ToHexString(item.Bytes), StringComparer.Ordinal)
            .Select(group => (group.First().Bytes, group.First().Records))
            .ToArray();

    private static Dictionary<uint, int> CaptureIntegerFields(
        ModuleDefMD module,
        StaticMachine machine) =>
        InitializedFieldCapture.CaptureInstanceIntegers(module, machine.State);

    private static bool TryParseVmMethod(
        ModuleDefMD module,
        StaticMachine machine,
        MethodDef initializer,
        int methodId,
        out VmMethod method,
        out string diagnostic)
    {
        method = new VmMethod([], 0);
        var bridge = initializer.Body.Instructions
            .Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef())
            .SingleOrDefault(method => method?.MethodSig?.Params.Count == 3 &&
                method.MethodSig.RetType is SZArraySig
                    { Next: { ElementType: ElementType.Object } });
        if (bridge is null)
        {
            diagnostic = "No unique VM bridge was found.";
            return false;
        }

        var loaders = bridge.DeclaringType.Methods.Where(method =>
            method.HasBody && method.IsStatic &&
            method.MethodSig?.Params.Count == 0 &&
            method.ReturnType.ElementType == ElementType.Void &&
            method.Body.Instructions.Any(instruction =>
                instruction.OpCode.Code == Code.Ldstr &&
                instruction.Operand is string name &&
                module.Resources.OfType<EmbeddedResource>().Any(resource => resource.Name == name)) &&
            method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called &&
                called.DeclaringType.FullName == "System.IO.BinaryReader" &&
                called.Name == ".ctor")).ToArray();
        if (loaders.Length != 1)
        {
            diagnostic = $"Expected one VM resource loader, found {loaders.Length}.";
            return false;
        }
        var loader = loaders[0];
        var resourceNames = loader.Body.Instructions
            .Where(instruction => instruction.OpCode.Code == Code.Ldstr)
            .Select(instruction => instruction.Operand as string)
            .Where(name => name is not null && module.Resources.OfType<EmbeddedResource>()
                .Any(resource => resource.Name == name))
            .Cast<string>()
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var parsers = loader.Body.Instructions
            .Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef())
            .Where(method => method?.DeclaringType == bridge.DeclaringType &&
                method.IsStatic &&
                method.ReturnType.ElementType == ElementType.Void &&
                method.MethodSig?.Params.Count == 1)
            .Distinct()
            .Cast<MethodDef>()
            .ToArray();
        if (resourceNames.Length != 1 || parsers.Length != 1 ||
            module.Resources.OfType<EmbeddedResource>()
                .SingleOrDefault(resource => resource.Name == resourceNames[0]) is not { } resource)
        {
            diagnostic = resourceNames.Length != 1
                ? $"Its loader names {resourceNames.Length} embedded resource(s), not one."
                : $"Its loader calls {parsers.Length} method(s) shaped like the one that parses " +
                    "the table, not one.";
            return false;
        }

        var serialized = resource.CreateReader().ToArray();
        if (!machine.State.Heap.TryAllocateByteArray(serialized, out var serializedArray))
        {
            diagnostic = "VM serialized IR exceeded the allocation budget.";
            return false;
        }
        var parseResult = machine.Execute(parsers[0], [serializedArray]);
        if (!parseResult.Succeeded)
        {
            diagnostic =
                $"VM IR loader stopped as {parseResult.Status} after {parseResult.Steps} steps: " +
                parseResult.Diagnostic;
            return false;
        }

        var readers = machine.State.StaticFields.Values
            .Where(value => value.Kind == StaticValueKind.HeapReference &&
                machine.State.Heap.TryGetRuntimeTypeName(value, out var typeName) &&
                typeName == "System.IO.BinaryReader" &&
                machine.State.Heap.TryGetModelValue(value, "Stream", out StaticValue stream) &&
                stream.Kind == StaticValueKind.HeapReference &&
                machine.State.Heap.TryGetModelValue(stream, "Buffer", out StaticValue buffer) &&
                buffer.Kind == StaticValueKind.HeapReference)
            .Select(value =>
            {
                machine.State.Heap.TryGetModelValue(value, "Stream", out StaticValue stream);
                machine.State.Heap.TryGetModelValue(stream, "Buffer", out StaticValue buffer);
                return machine.State.Heap.GetBytesSnapshot(buffer);
            })
            .Where(bytes => bytes is { Length: > 0 })
            .Cast<byte[]>()
            .Distinct(ByteArrayComparer.Instance)
            .ToArray();
        if (readers.Length != 1)
        {
            diagnostic = $"VM IR loader exposed {readers.Length} distinct reader buffers.";
            return false;
        }
        var bufferBytes = readers[0];

        var arrays = machine.State.StaticFields.Values
            .Where(value => value.Kind == StaticValueKind.HeapReference)
            .Select(value => machine.State.Heap.GetArraySnapshot(value))
            .Where(values => values is { Count: > 0 })
            .Cast<IReadOnlyList<StaticValue>>()
            .ToArray();
        var operandKinds = arrays
            .Where(values => values.Count > 32 &&
                values.All(value => value.IsInteger && (uint)value.AsInt32() <= 5))
            .Select(values => values.Select(value => checked((byte)value.AsInt32())).ToArray())
            .Distinct(ByteArrayComparer.Instance)
            .ToArray();
        var offsets = arrays
            .Where(values => values.Count >= 2 &&
                values.All(value => value.IsInteger &&
                    (uint)value.AsInt32() < (uint)bufferBytes.Length))
            .Select(values => values.Select(value => value.AsInt32()).ToArray())
            .Where(values => values.Distinct().Count() == values.Length)
            .ToArray();
        if (operandKinds.Length != 1 || offsets.Length != 1)
        {
            diagnostic =
                $"VM IR metadata was ambiguous ({operandKinds.Length} operand maps, {offsets.Length} offset maps).";
            return false;
        }

        try
        {
            if ((uint)methodId >= (uint)offsets[0].Length)
                throw new InvalidDataException($"VM method ID {methodId} has no offset.");
            var cursor = offsets[0][methodId];
            _ = ReadVmInteger(bufferBytes, ref cursor);
            var localCount = ReadVmInteger(bufferBytes, ref cursor);
            var exceptionCount = ReadVmInteger(bufferBytes, ref cursor);
            var instructionCount = ReadVmInteger(bufferBytes, ref cursor);
            if (localCount < 0 || exceptionCount < 0 || instructionCount <= 0 ||
                instructionCount > 1_000_000)
                throw new InvalidDataException("VM method header counts are outside bounds.");
            for (var index = 0; index < localCount; index++)
                _ = ReadVmInteger(bufferBytes, ref cursor);
            for (var index = 0; index < exceptionCount; index++)
            {
                for (var field = 0; field < 6; field++)
                    _ = ReadVmInteger(bufferBytes, ref cursor);
            }

            var decoded = new List<VmInstruction>(instructionCount);
            for (var index = 0; index < instructionCount; index++)
            {
                if ((uint)cursor >= (uint)bufferBytes.Length)
                    throw new EndOfStreamException();
                var opcode = bufferBytes[cursor++];
                if ((uint)opcode >= (uint)operandKinds[0].Length)
                    throw new InvalidDataException($"VM opcode {opcode} exceeds its operand map.");
                object? operand = operandKinds[0][opcode] switch
                {
                    0 => null,
                    1 => ReadVmInteger(bufferBytes, ref cursor),
                    2 => ReadFixedInt64(bufferBytes, ref cursor),
                    3 => BitConverter.Int32BitsToSingle(
                        checked((int)ReadFixedUInt32(bufferBytes, ref cursor))),
                    4 => BitConverter.Int64BitsToDouble(ReadFixedInt64(bufferBytes, ref cursor)),
                    5 => ReadVmIntegerArray(bufferBytes, ref cursor),
                    _ => throw new InvalidDataException("Unsupported VM operand kind.")
                };
                decoded.Add(new VmInstruction(opcode, operand));
            }
            method = new VmMethod(decoded, localCount);
            diagnostic =
                $"Loader={loader.MDToken}; parser={parsers[0].MDToken}; " +
                $"buffer={bufferBytes.Length}; methodId={methodId}; " +
                $"methodOffset={offsets[0][methodId]}.";
            return true;
        }
        catch (Exception exception) when (
            exception is InvalidDataException or EndOfStreamException or
                OverflowException or ArgumentOutOfRangeException)
        {
            diagnostic = $"Serialized VM method-ID {methodId} framing failed: {exception.Message}";
            return false;
        }
    }

    private static (bool Success, int Steps, string Diagnostic) EvaluateVmMethodZero(
        ModuleDefMD module,
        StaticMachine machine,
        VmMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var steps = 0;
        var locals = Enumerable.Repeat(StaticValue.Unknown, method.LocalCount).ToArray();
        var stack = new List<StaticValue>();
        var trail = new Queue<int>();
        var pc = 0;
        const int maximumSteps = 1_000_000;
        while ((uint)pc < (uint)method.Instructions.Count && steps++ < maximumSteps)
        {
            var instruction = method.Instructions[pc];
            trail.Enqueue(pc);
            if (trail.Count > 24)
                trail.Dequeue();
            var next = pc + 1;
            bool Pop(out StaticValue value)
            {
                value = StaticValue.Unknown;
                if (stack.Count == 0)
                    return false;
                value = stack[^1];
                stack.RemoveAt(stack.Count - 1);
                return true;
            }
            bool Target(object? operand, out int target)
            {
                target = operand is int value ? value : -1;
                return (uint)target < (uint)method.Instructions.Count;
            }

            switch (instruction.OpCode)
            {
                case 79:
                    if (instruction.Operand is not int constant)
                        return VmFailure("ldc.i4 operand is not an integer.");
                    stack.Add(StaticValue.FromInt32(constant));
                    break;
                case 53:
                    stack.Add(StaticValue.Null);
                    break;
                case 24:
                    if (!Pop(out var shiftSignedRight) || !Pop(out var shiftSignedLeft) ||
                        !shiftSignedLeft.IsInteger || !shiftSignedRight.IsInteger ||
                        !TryEvaluateVmIntegerBinary(
                            instruction.OpCode, shiftSignedLeft.AsInt64(),
                            shiftSignedRight.AsInt64(), out var shiftSignedResult))
                        return VmFailure("shr requires two known integers.");
                    stack.Add(StaticValue.FromInt64(shiftSignedResult));
                    break;
                case 54:
                    if (!Pop(out var shiftRight) || !Pop(out var shiftLeft) ||
                        !shiftLeft.IsInteger || !shiftRight.IsInteger ||
                        !TryEvaluateVmIntegerBinary(
                            instruction.OpCode, shiftLeft.AsInt64(), shiftRight.AsInt64(),
                            out var shiftResult))
                        return VmFailure("shl requires two known integers.");
                    stack.Add(StaticValue.FromInt64(shiftResult));
                    break;
                case 91:
                    if (!TryEvaluateVmControlFlow(
                            instruction.OpCode, out var handlerPointer, out var returns) ||
                        !returns || handlerPointer + 1 > -2)
                        return VmFailure("ret sentinel did not terminate the current VM frame.");
                    stack.Clear();
                    return (true, steps, string.Empty);
                case 78:
                    if (instruction.Operand is not int loadLocal ||
                        (uint)loadLocal >= (uint)locals.Length)
                        return VmFailure("ldloc index is outside the local array.");
                    stack.Add(locals[loadLocal]);
                    break;
                case 139:
                    if (instruction.Operand is not int storeLocal ||
                        (uint)storeLocal >= (uint)locals.Length || !Pop(out locals[storeLocal]))
                        return VmFailure("stloc has an invalid index or empty stack.");
                    break;
                case 174:
                    if (instruction.Operand is not int argument ||
                        (uint)argument >= (uint)arguments.Count)
                        return VmFailure("ldarg index is outside the argument array.");
                    stack.Add(arguments[argument]);
                    break;
                case 110:
                case 14:
                    if (!Target(instruction.Operand, out next))
                        return VmFailure("unconditional branch target is outside the method.");
                    break;
                case 97:
                    if (!Target(instruction.Operand, out var lessThanTarget) ||
                        !Pop(out var lessThanRight) || !Pop(out var lessThanLeft) ||
                        !lessThanLeft.IsInteger || !lessThanRight.IsInteger)
                        return VmFailure("blt requires two known integers and a valid target.");
                    if (lessThanLeft.AsInt64() < lessThanRight.AsInt64())
                        next = lessThanTarget;
                    break;
                case 77:
                    if (instruction.Operand is not int[] targets || !Pop(out var selector) ||
                        !selector.IsInteger)
                        return VmFailure("switch requires an integer selector.");
                    var selected = selector.AsInt32();
                    if ((uint)selected < (uint)targets.Length)
                    {
                        next = targets[selected];
                        if ((uint)next >= (uint)method.Instructions.Count)
                            return VmFailure("switch target is outside the method.");
                    }
                    break;
                case 143:
                case 156:
                    if (!Target(instruction.Operand, out var conditionalTarget) ||
                        !Pop(out var condition) || !TryVmTruth(condition, out var truth))
                        return VmFailure("conditional branch requires a known truth value.");
                    if (instruction.OpCode == 156)
                        truth = !truth;
                    if (truth)
                        next = conditionalTarget;
                    break;
                case 6:
                    if (!Pop(out _))
                        return VmFailure("pop requires a stack value.");
                    break;
                case 165:
                    if (!Target(instruction.Operand, out var equalTarget) ||
                        !Pop(out var right) || !Pop(out var left) ||
                        !left.IsInteger || !right.IsInteger)
                        return VmFailure("beq requires two known integers.");
                    if (left.AsInt64() == right.AsInt64())
                        next = equalTarget;
                    break;
                case 66:
                    if (instruction.Operand is not int typeToken ||
                        module.ResolveToken(unchecked((uint)typeToken)) is not ITypeDefOrRef arrayType ||
                        !Pop(out var arrayLength) || !arrayLength.IsInteger ||
                        !machine.State.Heap.TryAllocateArray(
                            arrayType.ToTypeSig(), unchecked((int)arrayLength.AsInt64()),
                            out var allocatedArray))
                        return VmFailure("newarr requires a type token and known bounded length.");
                    stack.Add(allocatedArray);
                    break;
                case 67:
                    if (!Pop(out var negate) || !negate.IsInteger)
                        return VmFailure("neg requires one known integer.");
                    stack.Add(StaticValue.FromInt64(unchecked(-negate.AsInt64())));
                    break;
                case 18:
                    if (instruction.Operand is not int fieldToken ||
                        module.ResolveToken(unchecked((uint)fieldToken)) is not IField loadedField)
                        return VmFailure("ldsfld token did not resolve to a field.");
                    stack.Add(machine.State.ReadStaticField(loadedField));
                    break;
                case 116:
                    if (instruction.Operand is not int storedFieldToken ||
                        module.ResolveToken(unchecked((uint)storedFieldToken)) is not IField storedField ||
                        !Pop(out var storedValue))
                        return VmFailure("stsfld token or stack value is invalid.");
                    machine.State.WriteStaticField(storedField, storedValue);
                    break;
                case 157:
                    if (stack.Count == 0)
                        return VmFailure("dup requires a stack value.");
                    stack.Add(stack[^1]);
                    break;
                case 158:
                    if (instruction.Operand is not int instanceFieldToken ||
                        module.ResolveToken(unchecked((uint)instanceFieldToken)) is not IField instanceField ||
                        !Pop(out var instanceFieldValue) || !Pop(out var instanceValue) ||
                        !machine.State.Heap.TryWriteField(
                            instanceValue, instanceField, instanceFieldValue))
                        return VmFailure("stfld requires a modeled instance, field, and value.");
                    break;
                case 127:
                    if (!Pop(out var converted) || !converted.IsInteger)
                        return VmFailure("conv.i8 requires a known integer.");
                    stack.Add(StaticValue.FromInt64(converted.AsInt64()));
                    break;
                case 60:
                    if (!Pop(out var subtractRight) || !Pop(out var subtractLeft) ||
                        !subtractLeft.IsInteger || !subtractRight.IsInteger ||
                        !TryEvaluateVmIntegerBinary(
                            instruction.OpCode, subtractLeft.AsInt64(),
                            subtractRight.AsInt64(), out var subtractResult))
                        return VmFailure("sub requires two known integers.");
                    stack.Add(StaticValue.FromInt64(subtractResult));
                    break;
                case 154:
                    if (!Pop(out var converted32) || !converted32.IsInteger)
                        return VmFailure("conv.i4 requires a known integer.");
                    stack.Add(StaticValue.FromInt32(unchecked((int)converted32.AsInt64())));
                    break;
                case 173:
                    if (!Pop(out var sizedValue) ||
                        !machine.State.Heap.TryGetLength(sizedValue, out var length))
                        return VmFailure("ldlen requires a modeled array.");
                    stack.Add(StaticValue.FromInt32(length));
                    break;
                case 1:
                    if (!Pop(out var element) || !Pop(out var storeIndex) ||
                        !Pop(out var storeArray))
                        return VmFailure(
                            "stelem.i1 requires a modeled array, integer index, and value.");
                    if (!storeIndex.IsInteger ||
                        !machine.State.Heap.TryGetArrayElementReference(
                            storeArray, unchecked((int)storeIndex.AsInt64()), out var storeCell) ||
                        !machine.State.Heap.TryWriteManaged(storeCell, element))
                    {
                        machine.State.Heap.TryGetLength(storeArray, out var storeLength);
                        return VmFailure(
                            $"stelem.i1 rejected array={storeArray.Kind}, " +
                            $"length={storeLength}, index={storeIndex.Kind}/" +
                            $"{(storeIndex.IsInteger ? storeIndex.AsInt64() : -1)}, " +
                            $"value={element.Kind}.");
                    }
                    break;
                case 30:
                    if (!Pop(out var loadIndex) || !Pop(out var loadArray))
                        return VmFailure(
                            "ldelem.u1 requires a modeled array and integer index.");
                    if (!loadIndex.IsInteger ||
                        !machine.State.Heap.TryGetArrayElementReference(
                            loadArray, unchecked((int)loadIndex.AsInt64()), out var loadCell) ||
                        !machine.State.Heap.TryReadManaged(loadCell, out var loadedElement))
                    {
                        machine.State.Heap.TryGetLength(loadArray, out var loadLength);
                        return VmFailure(
                            $"ldelem.u1 rejected array={loadArray.Kind}, length={loadLength}, " +
                            $"index={loadIndex.Kind}/" +
                            $"{(loadIndex.IsInteger ? loadIndex.AsInt64() : -1)}.");
                    }
                    stack.Add(loadedElement);
                    break;
                case 58:
                    if (!Pop(out var xorRight) || !Pop(out var xorLeft) ||
                        !xorLeft.IsInteger || !xorRight.IsInteger ||
                        !TryEvaluateVmIntegerBinary(
                            instruction.OpCode, xorLeft.AsInt64(), xorRight.AsInt64(),
                            out var xorResult))
                        return VmFailure("xor requires two known integers.");
                    stack.Add(StaticValue.FromInt64(xorResult));
                    break;
                case 68:
                    if (!Pop(out var addRight) || !Pop(out var addLeft) ||
                        !addLeft.IsInteger || !addRight.IsInteger ||
                        !TryEvaluateVmIntegerBinary(
                            instruction.OpCode, addLeft.AsInt64(), addRight.AsInt64(),
                            out var addResult))
                        return VmFailure("add requires two known integers.");
                    stack.Add(StaticValue.FromInt64(addResult));
                    break;
                case 75:
                    if (!Pop(out var complement) || !complement.IsInteger)
                        return VmFailure("not requires one known integer.");
                    stack.Add(StaticValue.FromInt64(~complement.AsInt64()));
                    break;
                case 172:
                    if (!Pop(out var convertedByte) || !convertedByte.IsInteger)
                        return VmFailure("conv.u1 requires a known integer.");
                    stack.Add(StaticValue.FromInt32(unchecked((byte)convertedByte.AsInt64())));
                    break;
                case 22:
                    if (instruction.Operand is not int token ||
                        module.ResolveToken(unchecked((uint)token)) is not IMethod called ||
                        called.ResolveMethodDef() is not { } definition)
                        return VmFailure("call token did not resolve to a managed method.");
                    var parameterCount = definition.MethodSig?.Params.Count ?? 0;
                    var callArguments = new StaticValue[
                        parameterCount + (definition.MethodSig?.HasThis == true ? 1 : 0)];
                    for (var callIndex = callArguments.Length - 1; callIndex >= 0; callIndex--)
                    {
                        if (!Pop(out callArguments[callIndex]))
                            return VmFailure("call consumed more values than the VM stack contains.");
                    }
                    var call = machine.Execute(definition, callArguments);
                    if (!call.Succeeded)
                        return VmFailure(
                            $"call {definition.MDToken} failed as {call.Status}: {call.Diagnostic}");
                    if (definition.ReturnType.ElementType != ElementType.Void)
                        stack.Add(call.Value);
                    break;
                case 166:
                    if (instruction.Operand is not int constructorToken ||
                        module.ResolveToken(unchecked((uint)constructorToken)) is not IMethod constructor ||
                        constructor.Name != ".ctor" ||
                        constructor.ResolveMethodDef() is not { } constructorDefinition ||
                        !machine.State.Heap.TryAllocateObject(
                            constructor.DeclaringType.FullName, out var constructed))
                        return VmFailure(
                            "newobj token did not resolve to a modeled managed constructor.");
                    var constructorParameterCount =
                        constructorDefinition.MethodSig?.Params.Count ?? 0;
                    var constructorArguments = new StaticValue[constructorParameterCount + 1];
                    constructorArguments[0] = constructed;
                    for (var constructorIndex = constructorArguments.Length - 1;
                         constructorIndex >= 1;
                         constructorIndex--)
                    {
                        if (!Pop(out constructorArguments[constructorIndex]))
                            return VmFailure(
                                "newobj consumed more values than the VM stack contains.");
                    }
                    var construction = machine.Execute(
                        constructorDefinition, constructorArguments);
                    if (!construction.Succeeded)
                        return VmFailure(
                            $"constructor {constructorDefinition.MDToken} failed as " +
                            $"{construction.Status}: {construction.Diagnostic}");
                    stack.Add(constructed);
                    break;
                default:
                    var resolvedOperand = instruction.Operand is int metadataToken &&
                        (metadataToken & unchecked((int)0xFF000000)) != 0
                            ? module.ResolveToken(unchecked((uint)metadataToken))?.ToString()
                            : null;
                    return VmFailure(
                        $"reachable opcode {instruction.OpCode} operand " +
                        $"{FormatVmOperand(instruction.Operand)} ({resolvedOperand ?? "unresolved"}) " +
                        "has no structurally proven evaluator.");
            }
            pc = next;
            continue;

            (bool Success, int Steps, string Diagnostic) VmFailure(string reason)
            {
                var message =
                    $"Serialized VM ID 0 stopped at instruction {pc}/{method.Instructions.Count}, " +
                    $"opcode {instruction.OpCode}, stackDepth={stack.Count}, steps={steps}: {reason} " +
                    $"Trail={string.Join(" ", trail.Select(index =>
                        $"{index}:{method.Instructions[index].OpCode}"))} " +
                    $"Window={string.Join(" ", method.Instructions.Skip(Math.Max(0, pc - 6)).Take(13)
                        .Select((item, relative) =>
                            $"{Math.Max(0, pc - 6) + relative}:{item.OpCode}:" +
                            $"{DescribeVmOperand(module, item.Operand)}"))}";
                return (false, steps, message);
            }
        }

        if (steps >= maximumSteps)
            return (false, steps,
                $"Serialized VM ID 0 exceeded {maximumSteps} evaluator steps.");
        return (true, steps, string.Empty);
    }

    private static bool TryVmTruth(StaticValue value, out bool truth)
    {
        if (value.IsInteger)
        {
            truth = value.AsInt64() != 0;
            return true;
        }
        if (value.Kind == StaticValueKind.Null)
        {
            truth = false;
            return true;
        }
        if (value.Kind is StaticValueKind.HeapReference or StaticValueKind.NativePointer or
            StaticValueKind.ManagedReference)
        {
            truth = true;
            return true;
        }
        truth = false;
        return false;
    }

    internal static bool TryEvaluateVmIntegerBinary(
        byte opcode,
        long left,
        long right,
        out long result)
    {
        result = opcode switch
        {
            24 => left >> ((int)right & 0x3F),
            54 => unchecked(left << ((int)right & 0x3F)),
            58 => left ^ right,
            60 => unchecked(left - right),
            68 => unchecked(left + right),
            _ => 0
        };
        return opcode is 24 or 54 or 58 or 60 or 68;
    }

    internal static bool TryEvaluateVmControlFlow(
        byte opcode,
        out int handlerInstructionPointer,
        out bool returns)
    {
        handlerInstructionPointer = opcode == 91 ? -3 : 0;
        returns = opcode == 91 && handlerInstructionPointer + 1 <= -2;
        return opcode == 91;
    }

    private static int ReadVmInteger(byte[] bytes, ref int cursor)
    {
        if ((uint)cursor >= (uint)bytes.Length)
            throw new EndOfStreamException();
        var first = bytes[cursor++];
        var negative = (first & 0x40) != 0;
        var value = first & 0x3F;
        var shift = 6;
        var current = first;
        while ((current & 0x80) != 0)
        {
            if ((uint)cursor >= (uint)bytes.Length || shift > 27)
                throw new InvalidDataException("Invalid signed VM integer.");
            current = bytes[cursor++];
            value |= (current & 0x7F) << shift;
            shift += 7;
        }
        return negative ? ~value : value;
    }

    private static long ReadFixedInt64(byte[] bytes, ref int cursor)
    {
        if (cursor < 0 || cursor > bytes.Length - sizeof(long))
            throw new EndOfStreamException();
        var value = BitConverter.ToInt64(bytes, cursor);
        cursor += sizeof(long);
        return value;
    }

    private static uint ReadFixedUInt32(byte[] bytes, ref int cursor)
    {
        if (cursor < 0 || cursor > bytes.Length - sizeof(uint))
            throw new EndOfStreamException();
        var value = BitConverter.ToUInt32(bytes, cursor);
        cursor += sizeof(uint);
        return value;
    }

    private static int[] ReadVmIntegerArray(byte[] bytes, ref int cursor)
    {
        var count = ReadVmInteger(bytes, ref cursor);
        if (count < 0 || count > 1_000_000)
            throw new InvalidDataException("VM integer-array length is outside bounds.");
        var values = new int[count];
        for (var index = 0; index < count; index++)
            values[index] = ReadVmInteger(bytes, ref cursor);
        return values;
    }

    private static string FormatVmOperand(object? operand) => operand switch
    {
        null => "-",
        int[] values => $"[{string.Join(",", values)}]",
        _ => Convert.ToString(operand, System.Globalization.CultureInfo.InvariantCulture) ?? "-"
    };

    private static string DescribeVmOperand(ModuleDefMD module, object? operand)
    {
        if (operand is int token && (token & unchecked((int)0xFF000000)) != 0)
            return $"{token}<{module.ResolveToken(unchecked((uint)token))}>";
        return FormatVmOperand(operand);
    }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static ByteArrayComparer Instance { get; } = new();
        public bool Equals(byte[]? x, byte[]? y) =>
            x is not null && y is not null && x.AsSpan().SequenceEqual(y);
        public int GetHashCode(byte[] obj)
        {
            var hash = new HashCode();
            foreach (var value in obj)
                hash.Add(value);
            return hash.ToHashCode();
        }
    }

    private static IReadOnlyList<StaticValue>? BuildArguments(
        StaticMachine machine,
        MethodDef initializer,
        StaticValue stream,
        int offset)
    {
        var parameters = initializer.MethodSig?.Params;
        if (parameters is null || parameters.Count != 2 || !initializer.IsStatic ||
            parameters[1].ElementType != ElementType.I4)
            return null;
        return [stream, StaticValue.FromInt32(offset)];
    }

    private static MethodDef? FindInitializer(MethodDef resolver)
    {
        var instructions = resolver.Body.Instructions;
        for (var index = 0; index < instructions.Count; index++)
        {
            if (instructions[index].Operand is not IMethod called ||
                called.ResolveMethodDef() is not { } definition ||
                definition.Module != resolver.Module ||
                !definition.IsStatic ||
                definition.MethodSig?.Params.Count != 2 ||
                definition.MethodSig.Params[1].ElementType != ElementType.I4 ||
                definition.ReturnType.ElementType != ElementType.Void)
                continue;
            if (index > 0 && instructions[index - 1].OpCode.Code is
                    Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0)
                return definition;
        }
        return null;
    }

    private static string? FindResourceName(MethodDef resolver)
    {
        var instructions = resolver.Body.Instructions;
        for (var index = 0; index < instructions.Count; index++)
        {
            if (instructions[index].Operand is not IMethod method ||
                method.Name != "GetManifestResourceStream")
                continue;
            for (var previous = index - 1; previous >= Math.Max(0, index - 4); previous--)
            {
                if (instructions[previous].OpCode.Code == Code.Ldstr)
                    return instructions[previous].Operand as string;
            }
        }
        return null;
    }

    private static bool IsVmBridge(MethodDef initializer) =>
        initializer.Body.Instructions.Any(instruction =>
            instruction.Operand is IMethod method &&
            method.MethodSig?.Params.Count == 3 &&
            method.MethodSig.RetType is SZArraySig { Next: { ElementType: ElementType.Object } });

    private sealed class ProxyIntrinsicRegistry : IStaticIntrinsicRegistry
    {
        private readonly IStaticIntrinsicRegistry _defaults;
        private readonly IReadOnlyDictionary<string, IMethod> _targets;
        private readonly ModuleDefMD _module;

        private ProxyIntrinsicRegistry(
            IStaticIntrinsicRegistry defaults,
            IReadOnlyDictionary<string, IMethod> targets,
            ModuleDefMD module)
        {
            _defaults = defaults;
            _targets = targets;
            _module = module;
        }

        public static ProxyIntrinsicRegistry Create(ModuleDefMD module)
        {
            var targets = new Dictionary<string, IMethod>(StringComparer.Ordinal);
            var facts = ReactorStructureDetector.Analyze(module);
            if (StructuralStreamDiscovery.TryDiscoverProxyProfile(
                    module, facts, out var profile) && profile is not null)
            {
                foreach (var binding in profile.Bindings)
                {
                    if (module.ResolveToken(binding.FieldToken) is not FieldDef field ||
                        module.ResolveToken(binding.TargetToken) is not IMethod target)
                        continue;
                    var delegateType = field.FieldSig?.Type.RemovePinnedAndModifiers().FullName;
                    if (!string.IsNullOrEmpty(delegateType))
                        targets.TryAdd(delegateType, target);
                }
            }
            return new ProxyIntrinsicRegistry(
                StaticIntrinsicRegistry.CreateDefault(), targets, module);
        }

        public bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic)
        {
            if (method.Name == "Invoke" &&
                _targets.TryGetValue(method.DeclaringType.FullName, out var target))
            {
                intrinsic = new ProxyIntrinsic(_defaults, target, _module);
                return true;
            }
            if (method.DeclaringType.FullName.StartsWith(
                    "System.Collections.Generic.List`1", StringComparison.Ordinal) ||
                method.DeclaringType.FullName.StartsWith(
                    "System.Collections.Generic.Dictionary`2", StringComparison.Ordinal))
            {
                intrinsic = new CollectionIntrinsic();
                return true;
            }
            if (method.DeclaringType.FullName.StartsWith(
                    "System.Comparison`1", StringComparison.Ordinal) &&
                method.Name == ".ctor")
            {
                intrinsic = new DelegateConstructionIntrinsic();
                return true;
            }
            if (method.DeclaringType.FullName == "System.Reflection.Assembly" &&
                method.Name == "get_EntryPoint")
            {
                intrinsic = new AssemblyEntryPointIntrinsic(_module);
                return true;
            }
            if (method.DeclaringType.FullName == "System.Reflection.MethodInfo" &&
                method.Name == "op_Equality")
            {
                intrinsic = new MethodInfoEqualityIntrinsic();
                return true;
            }
            return _defaults.TryResolve(method, out intrinsic);
        }
    }

    private sealed class MethodInfoEqualityIntrinsic : IStaticIntrinsic
    {
        public bool Matches(IMethod method) => true;

        public IntrinsicResult Invoke(
            IntrinsicContext context,
            IMethod method,
            IReadOnlyList<StaticValue> arguments)
        {
            if (arguments.Count != 2)
                return IntrinsicResult.Invalid("MethodInfo equality arguments are invalid.");
            if (arguments[0].Kind == StaticValueKind.Null ||
                arguments[1].Kind == StaticValueKind.Null)
                return IntrinsicResult.Completed(StaticValue.FromInt32(
                    arguments[0].Kind == arguments[1].Kind ? 1 : 0));
            if (!context.State.Heap.TryGetMetadataHandle(arguments[0], out var left) ||
                !context.State.Heap.TryGetMetadataHandle(arguments[1], out var right))
                return IntrinsicResult.Invalid(
                    "MethodInfo equality requires modeled metadata handles.");
            return IntrinsicResult.Completed(
                StaticValue.FromInt32(Equals(left, right) ? 1 : 0));
        }
    }

    private sealed class AssemblyEntryPointIntrinsic(ModuleDefMD module) : IStaticIntrinsic
    {
        public bool Matches(IMethod method) => true;

        public IntrinsicResult Invoke(
            IntrinsicContext context,
            IMethod method,
            IReadOnlyList<StaticValue> arguments)
        {
            if (arguments.Count != 1)
                return IntrinsicResult.Invalid("Assembly.EntryPoint arguments are invalid.");
            if (module.EntryPoint is null)
                return IntrinsicResult.Completed(StaticValue.Null);
            return context.State.Heap.TryAllocateMetadataHandle(
                module.EntryPoint, out var entryPoint)
                ? IntrinsicResult.Completed(entryPoint)
                : new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "Assembly entry-point metadata exceeded the allocation budget.");
        }
    }

    private sealed class DelegateConstructionIntrinsic : IStaticIntrinsic
    {
        public bool Matches(IMethod method) => true;

        public IntrinsicResult Invoke(
            IntrinsicContext context,
            IMethod method,
            IReadOnlyList<StaticValue> arguments)
        {
            if (arguments.Count != 3)
                return IntrinsicResult.Invalid("Delegate constructor arguments are invalid.");
            context.State.Heap.TrySetModelValue(arguments[0], "Target", arguments[1]);
            context.State.Heap.TrySetModelValue(arguments[0], "Method", arguments[2]);
            return IntrinsicResult.Completed();
        }
    }

    private sealed class CollectionIntrinsic : IStaticIntrinsic
    {
        public bool Matches(IMethod method) => true;

        public IntrinsicResult Invoke(
            IntrinsicContext context,
            IMethod method,
            IReadOnlyList<StaticValue> arguments)
        {
            if (arguments.Count == 0)
                return IntrinsicResult.Invalid("A collection invocation has no instance.");
            var heap = context.State.Heap;
            var dictionary = method.DeclaringType.FullName.StartsWith(
                "System.Collections.Generic.Dictionary`2", StringComparison.Ordinal);
            var name = method.Name.String;
            if (name == ".ctor")
            {
                heap.TrySetModelValue(arguments[0], "Items",
                    dictionary ? new Dictionary<StaticValue, StaticValue>() : new List<StaticValue>());
                return IntrinsicResult.Completed();
            }
            if (dictionary &&
                heap.TryGetModelValue(arguments[0], "Items",
                    out Dictionary<StaticValue, StaticValue>? map) &&
                map is not null)
            {
                if (name == "get_Count")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(map.Count));
                if (name == "Add" && arguments.Count == 3)
                {
                    map.Add(arguments[1], arguments[2]);
                    return IntrinsicResult.Completed();
                }
                if (name == "set_Item" && arguments.Count == 3)
                {
                    map[arguments[1]] = arguments[2];
                    return IntrinsicResult.Completed();
                }
                if (name == "get_Item" && arguments.Count == 2 &&
                    map.TryGetValue(arguments[1], out var value))
                    return IntrinsicResult.Completed(value);
                if (name == "ContainsKey" && arguments.Count == 2)
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        map.ContainsKey(arguments[1]) ? 1 : 0));
                if (name == "TryGetValue" && arguments.Count == 3)
                {
                    var found = map.TryGetValue(arguments[1], out value);
                    if (!heap.TryWriteManaged(
                            arguments[2], found ? value : StaticValue.Unknown))
                        return IntrinsicResult.Invalid("Dictionary out argument is invalid.");
                    return IntrinsicResult.Completed(StaticValue.FromInt32(found ? 1 : 0));
                }
                if (name == "Clear")
                {
                    map.Clear();
                    return IntrinsicResult.Completed();
                }
            }
            if (!dictionary &&
                heap.TryGetModelValue(arguments[0], "Items", out List<StaticValue>? list) &&
                list is not null)
            {
                if (name == "get_Count")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(list.Count));
                if (name == "Add" && arguments.Count == 2)
                {
                    list.Add(arguments[1]);
                    return IntrinsicResult.Completed();
                }
                if (name == "get_Item" && arguments.Count == 2 &&
                    (uint)arguments[1].AsInt32() < (uint)list.Count)
                    return IntrinsicResult.Completed(list[arguments[1].AsInt32()]);
                if (name == "set_Item" && arguments.Count == 3 &&
                    (uint)arguments[1].AsInt32() < (uint)list.Count)
                {
                    list[arguments[1].AsInt32()] = arguments[2];
                    return IntrinsicResult.Completed();
                }
                if (name == "Clear")
                {
                    list.Clear();
                    return IntrinsicResult.Completed();
                }
                if (name == "RemoveAt" && arguments.Count == 2 &&
                    (uint)arguments[1].AsInt32() < (uint)list.Count)
                {
                    list.RemoveAt(arguments[1].AsInt32());
                    return IntrinsicResult.Completed();
                }
                if (name == "Remove" && arguments.Count == 2)
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        list.Remove(arguments[1]) ? 1 : 0));
                if (name == "Insert" && arguments.Count == 3 &&
                    (uint)arguments[1].AsInt32() <= (uint)list.Count)
                {
                    list.Insert(arguments[1].AsInt32(), arguments[2]);
                    return IntrinsicResult.Completed();
                }
                if (name == "Sort" && arguments.Count == 2)
                    return IntrinsicResult.Completed();
            }
            return IntrinsicResult.Invalid($"Unsupported collection operation {method.FullName}.");
        }
    }

    private sealed class ProxyIntrinsic(
        IStaticIntrinsicRegistry defaults,
        IMethod target,
        ModuleDefMD module) : IStaticIntrinsic
    {
        public bool Matches(IMethod method) => true;

        public IntrinsicResult Invoke(
            IntrinsicContext context,
            IMethod method,
            IReadOnlyList<StaticValue> arguments)
        {
            if (arguments.Count == 0)
                return IntrinsicResult.Invalid("A proxy invocation has no delegate instance.");
            var forwarded = arguments.Skip(1).ToArray();
            if (target.DeclaringType.FullName == "System.Threading.Monitor")
            {
                if (target.Name == "Enter" && forwarded.Length == 2 &&
                    context.State.Heap.TryWriteManaged(
                        forwarded[1], StaticValue.FromInt32(1)))
                    return IntrinsicResult.Completed();
                if (target.Name == "Exit" && forwarded.Length == 1)
                    return IntrinsicResult.Completed();
                return IntrinsicResult.Invalid(
                    $"Unsupported Monitor proxy target {target.FullName}.");
            }
            if (target.DeclaringType.FullName == "System.Type" &&
                target.Name == "get_Assembly" && forwarded.Length == 1)
            {
                return context.State.Heap.TryAllocateObject(
                    "System.Reflection.Assembly", out var assembly)
                    ? IntrinsicResult.Completed(assembly)
                    : new IntrinsicResult(
                        StaticExecutionStatus.AllocationLimitExceeded,
                        StaticValue.Unknown,
                        "Assembly model exceeded the allocation budget.");
            }
            if (target.DeclaringType.FullName == "System.Type" &&
                target.Name == "get_Module" && forwarded.Length == 1)
            {
                if (!context.State.Heap.TryAllocateObject(
                        "System.Reflection.Module", out var moduleObject))
                    return new IntrinsicResult(
                        StaticExecutionStatus.AllocationLimitExceeded,
                        StaticValue.Unknown,
                        "Module model exceeded the allocation budget.");
                context.State.Heap.TrySetModelValue(moduleObject, "ModuleDef", module);
                return IntrinsicResult.Completed(moduleObject);
            }
            var targetName = target.Name.String;
            if (target.DeclaringType.FullName == "System.Reflection.Module" &&
                (targetName == "op_Equality" || targetName == "op_Inequality") &&
                forwarded.Length == 2)
            {
                var equal = forwarded[0].Kind == forwarded[1].Kind &&
                    forwarded[0].Bits == forwarded[1].Bits;
                if (targetName == "op_Inequality")
                    equal = !equal;
                return IntrinsicResult.Completed(StaticValue.FromInt32(equal ? 1 : 0));
            }
            if (target.DeclaringType.FullName == "System.Reflection.Module" &&
                targetName is not null &&
                targetName.StartsWith("Resolve", StringComparison.Ordinal) &&
                forwarded.Length >= 2 &&
                forwarded[1].IsInteger)
            {
                var resolved = module.ResolveToken(unchecked((uint)forwarded[1].AsInt32()));
                if (resolved is null)
                    return IntrinsicResult.Invalid(
                        $"Metadata token 0x{forwarded[1].AsInt32():X8} did not resolve.");
                var runtimeType = targetName switch
                {
                    "ResolveMethod" => "System.Reflection.MethodBase",
                    "ResolveField" => "System.Reflection.FieldInfo",
                    "ResolveType" => "System.Type",
                    "ResolveMember" => "System.Reflection.MemberInfo",
                    _ => string.Empty
                };
                if (runtimeType.Length == 0 ||
                    !context.State.Heap.TryAllocateObject(runtimeType, out var member))
                    return IntrinsicResult.Invalid(
                        $"Unsupported module resolution operation {target.FullName}.");
                context.State.Heap.TrySetModelValue(member, "Metadata", resolved);
                return IntrinsicResult.Completed(member);
            }
            if (target.DeclaringType.FullName == "System.Reflection.MethodBase" &&
                targetName == "GetParameters" && forwarded.Length == 1 &&
                context.State.Heap.TryGetModelValue(
                    forwarded[0], "Metadata", out object? methodMetadata) &&
                methodMetadata is IMethod reflectedMethod)
            {
                var parameters = reflectedMethod.MethodSig?.Params ?? [];
                if (!context.State.Heap.TryAllocateArray(
                        null, parameters.Count, out var parameterArray))
                    return new IntrinsicResult(
                        StaticExecutionStatus.AllocationLimitExceeded,
                        StaticValue.Unknown,
                        "Parameter array exceeded the allocation budget.");
                for (var index = 0; index < parameters.Count; index++)
                {
                    if (!context.State.Heap.TryAllocateObject(
                            "System.Reflection.ParameterInfo", out var parameter))
                        return new IntrinsicResult(
                            StaticExecutionStatus.AllocationLimitExceeded,
                            StaticValue.Unknown,
                            "Parameter model exceeded the allocation budget.");
                    context.State.Heap.TrySetModelValue(
                        parameter, "ParameterType", parameters[index]);
                    context.State.Heap.TryWriteArray(parameterArray, index, parameter);
                }
                return IntrinsicResult.Completed(parameterArray);
            }
            if (target.DeclaringType.FullName == "System.Reflection.MethodBase" &&
                targetName == "get_IsStatic" && forwarded.Length == 1 &&
                context.State.Heap.TryGetModelValue(
                    forwarded[0], "Metadata", out object? staticMetadata) &&
                staticMetadata is IMethod staticMethod)
            {
                return IntrinsicResult.Completed(StaticValue.FromInt32(
                    staticMethod.ResolveMethodDef()?.IsStatic == true ? 1 : 0));
            }
            if (target.DeclaringType.FullName == "System.Reflection.ParameterInfo" &&
                targetName == "get_ParameterType" && forwarded.Length == 1 &&
                context.State.Heap.TryGetModelValue(
                    forwarded[0], "ParameterType", out TypeSig? parameterType) &&
                parameterType is not null)
                return AllocateRuntimeType(context, parameterType);
            if (target.DeclaringType.FullName == "System.Type" &&
                forwarded.Length == 1 &&
                context.State.Heap.TryGetModelValue(
                    forwarded[0], "Metadata", out object? typeMetadata) &&
                typeMetadata is TypeSig typeSignature)
            {
                if (targetName == "get_IsByRef")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature is ByRefSig ? 1 : 0));
                if (targetName == "get_IsValueType")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature.IsValueType ? 1 : 0));
                if (targetName == "get_IsEnum")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature.ToTypeDefOrRef()?.ResolveTypeDef()?.IsEnum == true ? 1 : 0));
                if (targetName == "get_IsArray")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature is ArraySig or SZArraySig ? 1 : 0));
                if (targetName == "get_IsPointer")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature is PtrSig ? 1 : 0));
                if (targetName == "get_IsPrimitive")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature.ElementType is >= ElementType.Boolean and <= ElementType.R8
                            or ElementType.I or ElementType.U ? 1 : 0));
                if (targetName is "get_FullName" or "get_Name")
                {
                    var typeName = targetName == "get_Name"
                        ? typeSignature.TypeName
                        : typeSignature.FullName;
                    return context.State.Heap.TryAllocateString(typeName, out var nameValue)
                        ? IntrinsicResult.Completed(nameValue)
                        : new IntrinsicResult(
                            StaticExecutionStatus.AllocationLimitExceeded,
                            StaticValue.Unknown,
                            "Type name exceeded the allocation budget.");
                }
                if (targetName == "GetElementType" &&
                    typeSignature.Next is { } elementType)
                    return AllocateRuntimeType(context, elementType);
            }
            if (target.DeclaringType.FullName == "System.Type" &&
                forwarded.Length == 1 &&
                context.State.Heap.TryGetModelValue(
                    forwarded[0], "TypeName", out string? modeledTypeName) &&
                modeledTypeName is not null)
            {
                if (targetName is "get_IsByRef" or "get_IsValueType" or
                    "get_IsEnum" or "get_IsArray" or "get_IsPointer" or
                    "get_IsPrimitive")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(0));
                if (targetName is "get_FullName" or "get_Name")
                {
                    var value = targetName == "get_Name"
                        ? modeledTypeName[(modeledTypeName.LastIndexOf('.') + 1)..]
                        : modeledTypeName;
                    return context.State.Heap.TryAllocateString(value, out var typeNameValue)
                        ? IntrinsicResult.Completed(typeNameValue)
                        : new IntrinsicResult(
                            StaticExecutionStatus.AllocationLimitExceeded,
                            StaticValue.Unknown,
                            "Type name exceeded the allocation budget.");
                }
                if (targetName == "GetElementType")
                    return IntrinsicResult.Completed(StaticValue.Null);
            }
            if (target.DeclaringType.FullName == "System.Nullable" &&
                targetName == "GetUnderlyingType" &&
                forwarded.Length == 1)
            {
                if (context.State.Heap.TryGetModelValue(
                        forwarded[0], "Metadata", out object? nullableMetadata) &&
                    nullableMetadata is GenericInstSig nullable &&
                    nullable.GenericType.TypeDefOrRef.FullName == "System.Nullable`1" &&
                    nullable.GenericArguments.Count == 1)
                {
                    return AllocateRuntimeType(context, nullable.GenericArguments[0]);
                }
                return IntrinsicResult.Completed(StaticValue.Null);
            }
            if (!defaults.TryResolve(target, out var intrinsic))
                return IntrinsicResult.Invalid(
                    $"Proxy target {target.FullName} is not a supported static intrinsic.");
            return intrinsic.Invoke(context, target, forwarded);
        }

        private static IntrinsicResult AllocateRuntimeType(
            IntrinsicContext context,
            TypeSig signature)
        {
            if (!context.State.Heap.TryAllocateObject("System.Type", out var type))
                return new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "Runtime type model exceeded the allocation budget.");
            context.State.Heap.TrySetModelValue(type, "Metadata", signature);
            return IntrinsicResult.Completed(type);
        }
    }
}
