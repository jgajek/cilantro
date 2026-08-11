using System.Buffers.Binary;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace ReactorUnpack.Core.Interpretation;

public sealed class StaticMachine
{
    private readonly StaticMachineLimits _limits;
    private readonly IStaticIntrinsicRegistry _intrinsics;
    private readonly bool _modelTypeInitialization;

    public StaticMachine(
        StaticMachineLimits? limits = null,
        IStaticIntrinsicRegistry? intrinsics = null,
        bool modelTypeInitialization = false)
    {
        _limits = limits ?? new StaticMachineLimits();
        _limits.Validate();
        _intrinsics = intrinsics ?? StaticIntrinsicRegistry.CreateDefault();
        _modelTypeInitialization = modelTypeInitialization;
        State = new StaticMachineState(_limits);
    }

    public StaticMachineState State { get; }

    public StaticExecutionResult Execute(
        MethodDef method,
        IReadOnlyList<StaticValue>? arguments = null) =>
        Execute(method, arguments, new StaticWorkBudget(_limits.MaximumSteps));

    public StaticExecutionResult Execute(
        MethodDef method,
        IReadOnlyList<StaticValue>? arguments,
        StaticWorkBudget budget)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(budget);
        var directInitializerType = _modelTypeInitialization && method.Name == ".cctor"
            ? method.DeclaringType
            : null;
        var directInitializerStarted = directInitializerType is not null &&
            State.GetTypeInitializationStatus(directInitializerType) ==
                TypeInitializationStatus.Uninitialized;
        if (directInitializerStarted)
            State.TryBeginTypeInitialization(directInitializerType!);
        var result = directInitializerType is not null &&
            State.GetTypeInitializationStatus(directInitializerType) ==
                TypeInitializationStatus.Failed
            ? FrameResult.Fail(
                StaticExecutionStatus.InvalidProgram,
                $"Type initializer {method.FullName} previously failed: " +
                State.GetTypeInitializationFailure(directInitializerType))
            : ExecuteFrame(method, arguments ?? [], budget, 0);
        if (directInitializerStarted)
        {
            if (result.Status == StaticExecutionStatus.Completed)
                State.CompleteTypeInitialization(directInitializerType!);
            else
                State.FailTypeInitialization(
                    directInitializerType!,
                    result.Diagnostic ?? result.Status.ToString());
        }
        if (result.Status == StaticExecutionStatus.Completed &&
            method.ReturnType.ElementType != ElementType.Void &&
            result.Value.Kind == StaticValueKind.Unknown)
            result = result with
            {
                Status = StaticExecutionStatus.Unknown,
                Diagnostic = "Execution returned an unknown value."
            };
        return new StaticExecutionResult(
            result.Status,
            result.Value,
            result.Diagnostic,
            budget.ConsumedSteps,
            State.Heap.AllocatedBytes);
    }

    // Every frame is tracked so that side effects and loader observations can be attributed to the
    // call subtree that produced them, which is what later passes need in order to prove what is
    // safe to remove.
    private FrameResult ExecuteFrame(
        MethodDef method,
        IReadOnlyList<StaticValue> arguments,
        StaticWorkBudget budget,
        int depth)
    {
        State.Evidence.EnterMethod(method);
        try
        {
            return ExecuteFrameCore(method, arguments, budget, depth);
        }
        finally
        {
            State.Evidence.LeaveMethod();
        }
    }

    private FrameResult ExecuteFrameCore(
        MethodDef method,
        IReadOnlyList<StaticValue> arguments,
        StaticWorkBudget budget,
        int depth)
    {
        if (depth > _limits.MaximumRecursionDepth)
            return FrameResult.Fail(
                StaticExecutionStatus.RecursionLimitExceeded,
                $"Call depth exceeded {_limits.MaximumRecursionDepth}.");
        if (_modelTypeInitialization &&
            method.Name != ".cctor" &&
            (method.IsStatic ||
             method.Name == ".ctor" ||
             method.DeclaringType?.IsValueType == true) &&
            EnsureTypeInitialized(
                method.DeclaringType,
                TypeInitializationTrigger.MethodCall,
                budget,
                depth) is { } methodInitializationFailure)
        {
            return methodInitializationFailure;
        }
        if (!method.HasBody || method.Body.Instructions.Count == 0)
            return FrameResult.Fail(
                StaticExecutionStatus.Unsupported,
                $"{method.FullName} has no CIL body.");
        if (method.Body.ExceptionHandlers.Any(handler =>
            handler.HandlerType is ExceptionHandlerType.Filter or ExceptionHandlerType.Fault ||
            handler.TryStart is null ||
            handler.HandlerStart is null))
            return FrameResult.Fail(
                StaticExecutionStatus.Unsupported,
                $"{method.FullName} uses non-deterministic or unsupported exception handlers.");

        var expectedArguments = (method.MethodSig?.Params.Count ?? 0) +
            (method.MethodSig?.HasThis == true ? 1 : 0);
        if (arguments.Count != expectedArguments)
            return FrameResult.Fail(
                StaticExecutionStatus.InvalidProgram,
                $"{method.FullName} expected {expectedArguments} arguments, got {arguments.Count}.");

        var instructions = method.Body.Instructions;
        var indices = instructions.Select((instruction, index) => (instruction, index))
            .ToDictionary(item => item.instruction, item => item.index);
        var mutableArguments = arguments
            .Select((value, index) => value.ProvenanceId != 0
                ? value
                : State.Provenance.Origin(
                    value,
                    ProvenanceKind.Argument,
                    $"{method.MDToken}/arg{index}",
                    method.FullName))
            .ToArray();
        var argumentReferences = new Dictionary<int, StaticValue>();
        var locals = method.Body.Variables
            .Select((local, index) => State.Provenance.Origin(
                DefaultValue(local.Type),
                ProvenanceKind.Default,
                $"{method.MDToken}/local{index}",
                local.Type.FullName))
            .ToArray();
        var localReferences = new Dictionary<int, StaticValue>();
        var pendingLeaves = new Stack<int>();
        var stack = new List<StaticValue>(Math.Max(method.Body.MaxStack, (ushort)8));
        var ip = 0;

        while ((uint)ip < (uint)instructions.Count)
        {
            if (!budget.TryConsumeStep())
                return FrameResult.Fail(
                    StaticExecutionStatus.StepLimitExceeded,
                    $"Execution exhausted its {budget.MaximumSteps}-step budget.");

            var instruction = instructions[ip];
            var next = ip + 1;
            try
            {
                switch (instruction.OpCode.Code)
                {
                    case Code.Nop:
                    case Code.Break:
                        break;
                    case Code.Ldnull:
                        stack.Add(TrackOrigin(method, instruction, StaticValue.Null, "null"));
                        break;
                    case Code.Ldstr:
                        if (!State.Heap.TryAllocateString((string)instruction.Operand, out var text))
                            return AllocationFailure(instruction, "string");
                        stack.Add(TrackOrigin(method, instruction, text, "string"));
                        break;
                    case Code.Ldtoken:
                        State.Heap.TryAllocateMetadataHandle(instruction.Operand, out var token);
                        stack.Add(State.Provenance.Origin(
                            token,
                            ProvenanceKind.Metadata,
                            $"{method.MDToken}/IL_{instruction.Offset:X4}",
                            "ldtoken"));
                        break;
                    case Code.Ldftn:
                        State.Heap.TryAllocateMetadataHandle(instruction.Operand, out var function);
                        stack.Add(State.Provenance.Origin(
                            function,
                            ProvenanceKind.Metadata,
                            $"{method.MDToken}/IL_{instruction.Offset:X4}",
                            "ldftn"));
                        break;
                    case Code.Ldvirtftn:
                        Pop(stack);
                        State.Heap.TryAllocateMetadataHandle(instruction.Operand, out var virtualFunction);
                        stack.Add(virtualFunction);
                        break;
                    case Code.Ldc_I4_M1: stack.Add(TrackOrigin(method, instruction, StaticValue.FromInt32(-1), "-1")); break;
                    case Code.Ldc_I4_0: stack.Add(TrackOrigin(method, instruction, StaticValue.FromInt32(0), "0")); break;
                    case Code.Ldc_I4_1: stack.Add(TrackOrigin(method, instruction, StaticValue.FromInt32(1), "1")); break;
                    case Code.Ldc_I4_2: stack.Add(TrackOrigin(method, instruction, StaticValue.FromInt32(2), "2")); break;
                    case Code.Ldc_I4_3: stack.Add(TrackOrigin(method, instruction, StaticValue.FromInt32(3), "3")); break;
                    case Code.Ldc_I4_4: stack.Add(TrackOrigin(method, instruction, StaticValue.FromInt32(4), "4")); break;
                    case Code.Ldc_I4_5: stack.Add(TrackOrigin(method, instruction, StaticValue.FromInt32(5), "5")); break;
                    case Code.Ldc_I4_6: stack.Add(TrackOrigin(method, instruction, StaticValue.FromInt32(6), "6")); break;
                    case Code.Ldc_I4_7: stack.Add(TrackOrigin(method, instruction, StaticValue.FromInt32(7), "7")); break;
                    case Code.Ldc_I4_8: stack.Add(TrackOrigin(method, instruction, StaticValue.FromInt32(8), "8")); break;
                    case Code.Ldc_I4:
                        stack.Add(TrackOrigin(method, instruction,
                            StaticValue.FromInt32((int)instruction.Operand), "i4"));
                        break;
                    case Code.Ldc_I4_S:
                        stack.Add(TrackOrigin(method, instruction,
                            StaticValue.FromInt32((sbyte)instruction.Operand), "i4.s"));
                        break;
                    case Code.Ldc_I8:
                        stack.Add(TrackOrigin(method, instruction,
                            StaticValue.FromInt64((long)instruction.Operand), "i8"));
                        break;
                    case Code.Ldc_R4:
                        stack.Add(TrackOrigin(method, instruction,
                            StaticValue.FromFloat32((float)instruction.Operand), "r4"));
                        break;
                    case Code.Ldc_R8:
                        stack.Add(TrackOrigin(method, instruction,
                            StaticValue.FromFloat64((double)instruction.Operand), "r8"));
                        break;

                    case Code.Ldarg_0: stack.Add(LoadSlot(mutableArguments, argumentReferences, 0)); break;
                    case Code.Ldarg_1: stack.Add(LoadSlot(mutableArguments, argumentReferences, 1)); break;
                    case Code.Ldarg_2: stack.Add(LoadSlot(mutableArguments, argumentReferences, 2)); break;
                    case Code.Ldarg_3: stack.Add(LoadSlot(mutableArguments, argumentReferences, 3)); break;
                    case Code.Ldarg:
                    case Code.Ldarg_S:
                        stack.Add(LoadSlot(mutableArguments, argumentReferences,
                            ArgumentIndex(method, instruction.Operand)));
                        break;
                    case Code.Starg:
                    case Code.Starg_S:
                        StoreSlot(mutableArguments, argumentReferences,
                            ArgumentIndex(method, instruction.Operand), Pop(stack), State.Heap);
                        break;
                    case Code.Ldarga:
                    case Code.Ldarga_S:
                        stack.Add(AddressOfSlot(mutableArguments, argumentReferences,
                            ArgumentIndex(method, instruction.Operand), State.Heap));
                        break;

                    case Code.Ldloc_0: stack.Add(LoadSlot(locals, localReferences, 0)); break;
                    case Code.Ldloc_1: stack.Add(LoadSlot(locals, localReferences, 1)); break;
                    case Code.Ldloc_2: stack.Add(LoadSlot(locals, localReferences, 2)); break;
                    case Code.Ldloc_3: stack.Add(LoadSlot(locals, localReferences, 3)); break;
                    case Code.Ldloc:
                    case Code.Ldloc_S:
                        stack.Add(LoadSlot(locals, localReferences, LocalIndex(instruction.Operand)));
                        break;
                    case Code.Stloc_0: StoreSlot(locals, localReferences, 0, Pop(stack), State.Heap); break;
                    case Code.Stloc_1: StoreSlot(locals, localReferences, 1, Pop(stack), State.Heap); break;
                    case Code.Stloc_2: StoreSlot(locals, localReferences, 2, Pop(stack), State.Heap); break;
                    case Code.Stloc_3: StoreSlot(locals, localReferences, 3, Pop(stack), State.Heap); break;
                    case Code.Stloc:
                    case Code.Stloc_S:
                        StoreSlot(locals, localReferences, LocalIndex(instruction.Operand),
                            Pop(stack), State.Heap);
                        break;
                    case Code.Ldloca:
                    case Code.Ldloca_S:
                        stack.Add(AddressOfSlot(locals, localReferences,
                            LocalIndex(instruction.Operand), State.Heap));
                        break;
                    case Code.Dup:
                        stack.Add(Peek(stack));
                        break;
                    case Code.Pop:
                        Pop(stack);
                        break;

                    case Code.Add:
                    case Code.Sub:
                    case Code.Mul:
                    case Code.Div:
                    case Code.Div_Un:
                    case Code.Rem:
                    case Code.Rem_Un:
                    case Code.And:
                    case Code.Or:
                    case Code.Xor:
                    case Code.Shl:
                    case Code.Shr:
                    case Code.Shr_Un:
                        {
                            var right = Pop(stack);
                            var left = Pop(stack);
                            stack.Add(TrackOperation(
                                method,
                                instruction,
                                Binary(instruction.OpCode.Code, left, right),
                                ProvenanceKind.Binary,
                                left,
                                right));
                            break;
                        }
                    case Code.Neg:
                    case Code.Not:
                        {
                            var input = Pop(stack);
                            stack.Add(TrackOperation(
                                method,
                                instruction,
                                Unary(instruction.OpCode.Code, input),
                                ProvenanceKind.Unary,
                                input));
                            break;
                        }

                    case Code.Conv_I1:
                    case Code.Conv_U1:
                    case Code.Conv_I2:
                    case Code.Conv_U2:
                    case Code.Conv_I4:
                    case Code.Conv_U4:
                    case Code.Conv_I8:
                    case Code.Conv_U8:
                    case Code.Conv_I:
                    case Code.Conv_U:
                    case Code.Conv_R4:
                    case Code.Conv_R8:
                    case Code.Conv_R_Un:
                        {
                            var input = Pop(stack);
                            stack.Add(TrackOperation(
                                method,
                                instruction,
                                ConvertValue(instruction.OpCode.Code, input),
                                ProvenanceKind.Conversion,
                                input));
                            break;
                        }
                    case Code.Ceq:
                    case Code.Cgt:
                    case Code.Cgt_Un:
                    case Code.Clt:
                    case Code.Clt_Un:
                        {
                            var right = Pop(stack);
                            var left = Pop(stack);
                            stack.Add(TrackOperation(
                                method,
                                instruction,
                                Compare(instruction.OpCode.Code, left, right),
                                ProvenanceKind.Comparison,
                                left,
                                right));
                            break;
                        }

                    case Code.Br:
                    case Code.Br_S:
                        next = Target(indices, instruction.Operand);
                        break;
                    case Code.Brtrue:
                    case Code.Brtrue_S:
                    case Code.Brfalse:
                    case Code.Brfalse_S:
                        {
                            var condition = Truth(Pop(stack));
                            if (condition is null)
                                return UnknownBranch(instruction);
                            var branchOnTrue = instruction.OpCode.Code is Code.Brtrue or Code.Brtrue_S;
                            if (condition.Value == branchOnTrue)
                                next = Target(indices, instruction.Operand);
                            break;
                        }
                    case Code.Beq:
                    case Code.Beq_S:
                    case Code.Bne_Un:
                    case Code.Bne_Un_S:
                    case Code.Bgt:
                    case Code.Bgt_S:
                    case Code.Bgt_Un:
                    case Code.Bgt_Un_S:
                    case Code.Bge:
                    case Code.Bge_S:
                    case Code.Bge_Un:
                    case Code.Bge_Un_S:
                    case Code.Blt:
                    case Code.Blt_S:
                    case Code.Blt_Un:
                    case Code.Blt_Un_S:
                    case Code.Ble:
                    case Code.Ble_S:
                    case Code.Ble_Un:
                    case Code.Ble_Un_S:
                        {
                            var right = Pop(stack);
                            var left = Pop(stack);
                            var condition = BranchCompare(instruction.OpCode.Code, left, right);
                            if (condition is null)
                                return UnknownBranch(instruction);
                            if (condition.Value)
                                next = Target(indices, instruction.Operand);
                            break;
                        }
                    case Code.Switch:
                        {
                            var selector = Pop(stack);
                            if (!selector.IsKnown)
                                return UnknownBranch(instruction);
                            if (!selector.IsInteger)
                                throw new InvalidOperationException("Switch selector is not an integer.");
                            var targets = (IList<Instruction>)instruction.Operand;
                            var selected = selector.AsInt32();
                            if (MachineTrace.Enabled)
                            {
                                var chosen = (uint)selected < (uint)targets.Count
                                    ? targets[selected].Offset
                                    : 0;
                                MachineTrace.Line(
                                    $"switch IL_{instruction.Offset:X4} state={selected} -> IL_{chosen:X4}");
                            }
                            if ((uint)selected < (uint)targets.Count)
                                next = indices[targets[selected]];
                            break;
                        }

                    case Code.Leave:
                    case Code.Leave_S:
                        {
                            stack.Clear();
                            var target = Target(indices, instruction.Operand);
                            var finallyHandler = FindFinally(method, indices, ip, target);
                            if (finallyHandler is null)
                                next = target;
                            else
                            {
                                pendingLeaves.Push(target);
                                next = indices[finallyHandler.HandlerStart];
                            }
                            break;
                        }
                    case Code.Endfinally:
                        if (pendingLeaves.Count == 0)
                            throw new InvalidOperationException("endfinally has no pending leave.");
                        next = pendingLeaves.Pop();
                        break;

                    case Code.Newarr:
                        {
                            var length = Pop(stack);
                            if (!length.IsKnown)
                                return FrameResult.Fail(
                                    StaticExecutionStatus.Unknown,
                                    $"IL_{instruction.Offset:X4}: array length is unknown.");
                            var elementType = (instruction.Operand as ITypeDefOrRef)?.ToTypeSig();
                            if (!State.Heap.TryAllocateArray(elementType, length.AsInt32(), out var array))
                                return FrameResult.Fail(
                                    StaticExecutionStatus.AllocationLimitExceeded,
                                    $"IL_{instruction.Offset:X4}: array exceeded allocation limits.");
                            stack.Add(array);
                            break;
                        }
                    case Code.Ldlen:
                        {
                            var array = Pop(stack);
                            if (!State.Heap.TryGetLength(array, out var length))
                                throw new InvalidOperationException("ldlen target is not an array.");
                            stack.Add(StaticValue.FromInt32(length));
                            break;
                        }
                    case Code.Ldelem:
                    case Code.Ldelem_I:
                    case Code.Ldelem_I1:
                    case Code.Ldelem_U1:
                    case Code.Ldelem_I2:
                    case Code.Ldelem_U2:
                    case Code.Ldelem_I4:
                    case Code.Ldelem_U4:
                    case Code.Ldelem_I8:
                    case Code.Ldelem_R4:
                    case Code.Ldelem_R8:
                    case Code.Ldelem_Ref:
                        {
                            var indexValue = Pop(stack);
                            var index = indexValue.AsInt32();
                            var array = Pop(stack);
                            if (!State.Heap.TryReadArray(array, index, out var value))
                                throw new InvalidOperationException("Array read is out of bounds.");
                            stack.Add(TrackOperation(
                                method,
                                instruction,
                                NormalizeElement(instruction.OpCode.Code, value),
                                ProvenanceKind.ArrayElement,
                                array,
                                indexValue,
                                value));
                            break;
                        }
                    case Code.Stelem:
                    case Code.Stelem_I:
                    case Code.Stelem_I1:
                    case Code.Stelem_I2:
                    case Code.Stelem_I4:
                    case Code.Stelem_I8:
                    case Code.Stelem_R4:
                    case Code.Stelem_R8:
                    case Code.Stelem_Ref:
                        {
                            var value = Pop(stack);
                            var index = Pop(stack).AsInt32();
                            var array = Pop(stack);
                            if (!State.Heap.TryWriteArray(array, index, value))
                                throw new InvalidOperationException("Array write is out of bounds.");
                            break;
                        }
                    case Code.Ldelema:
                        {
                            var index = Pop(stack).AsInt32();
                            var array = Pop(stack);
                            if (!State.Heap.TryGetArrayElementReference(array, index, out var reference))
                                throw new InvalidOperationException("Array address is out of bounds.");
                            stack.Add(reference);
                            break;
                        }

                    case Code.Ldind_I1:
                    case Code.Ldind_U1:
                    case Code.Ldind_I2:
                    case Code.Ldind_U2:
                    case Code.Ldind_I4:
                    case Code.Ldind_U4:
                    case Code.Ldind_I8:
                    case Code.Ldind_I:
                    case Code.Ldind_R4:
                    case Code.Ldind_R8:
                    case Code.Ldind_Ref:
                    case Code.Ldobj:
                        {
                            var address = Pop(stack);
                            if (!TryReadIndirect(instruction.OpCode.Code, address, out var value))
                                throw new InvalidOperationException(
                                    $"Indirect read target is not addressable " +
                                    $"(kind={address.Kind}, value={address.Bits}).");
                            stack.Add(TrackOperation(
                                method,
                                instruction,
                                value,
                                address.Kind == StaticValueKind.NativePointer
                                    ? ProvenanceKind.NativeReference
                                    : ProvenanceKind.ManagedReference,
                                address,
                                value));
                            break;
                        }
                    case Code.Stind_I1:
                    case Code.Stind_I2:
                    case Code.Stind_I4:
                    case Code.Stind_I8:
                    case Code.Stind_I:
                    case Code.Stind_R4:
                    case Code.Stind_R8:
                    case Code.Stind_Ref:
                    case Code.Stobj:
                        {
                            var value = Pop(stack);
                            var address = Pop(stack);
                            if (!TryWriteIndirect(instruction.OpCode.Code, address, value))
                                throw new InvalidOperationException("Indirect write target is not addressable.");
                            break;
                        }
                    case Code.Initobj:
                        {
                            var address = Pop(stack);
                            var typeReference = instruction.Operand as ITypeDefOrRef;
                            var type = typeReference?.ToTypeSig();
                            var initialized = DefaultValue(type);
                            if (typeReference?.ResolveTypeDef()?.IsValueType == true &&
                                type?.ElementType == ElementType.ValueType &&
                                State.Heap.TryAllocateObject(
                                    typeReference.FullName,
                                    out var valueType))
                            {
                                initialized = valueType;
                            }
                            if (!State.Heap.TryWriteManaged(address, initialized))
                                throw new InvalidOperationException(
                                    "initobj target is not a managed reference.");
                            break;
                        }
                    case Code.Cpblk:
                        {
                            var count = Pop(stack).AsInt32();
                            var source = Pop(stack);
                            var destination = Pop(stack);
                            if (count < 0 || count > _limits.MaximumArrayLength)
                                throw new InvalidOperationException("cpblk length is invalid.");
                            var bytes = new byte[count];
                            if (!State.Heap.TryReadBytes(source, 0, bytes) ||
                                !State.Heap.TryWriteBytes(destination, 0, bytes))
                                throw new InvalidOperationException("cpblk range is invalid.");
                            break;
                        }
                    case Code.Initblk:
                        {
                            var count = Pop(stack).AsInt32();
                            var fill = unchecked((byte)Pop(stack).AsInt32());
                            var destination = Pop(stack);
                            if (count < 0 || count > _limits.MaximumArrayLength)
                                throw new InvalidOperationException("initblk length is invalid.");
                            var bytes = new byte[count];
                            Array.Fill(bytes, fill);
                            if (!State.Heap.TryWriteBytes(destination, 0, bytes))
                                throw new InvalidOperationException("initblk range is invalid.");
                            break;
                        }

                    case Code.Ldsfld:
                        {
                            var field = (IField)instruction.Operand;
                            if (_modelTypeInitialization &&
                                EnsureTypeInitialized(
                                    field.DeclaringType.ResolveTypeDef(),
                                    TypeInitializationTrigger.StaticField,
                                    budget,
                                    depth) is { } initializationFailure)
                            {
                                return initializationFailure;
                            }
                            var value = State.ReadStaticField(field);
                            if (!value.IsKnown && field.ResolveFieldDef() is { HasConstant: true } definition)
                                value = ConstantValue(definition.Constant?.Value);
                            stack.Add(TrackOperation(
                                method,
                                instruction,
                                value,
                                ProvenanceKind.StaticField,
                                value));
                            break;
                        }
                    case Code.Stsfld:
                        {
                            var field = (IField)instruction.Operand;
                            if (_modelTypeInitialization &&
                                EnsureTypeInitialized(
                                    field.DeclaringType.ResolveTypeDef(),
                                    TypeInitializationTrigger.StaticField,
                                    budget,
                                    depth) is { } initializationFailure)
                            {
                                return initializationFailure;
                            }
                            State.WriteStaticField(field, Pop(stack));
                            break;
                        }
                    case Code.Ldsflda:
                        {
                            var field = (IField)instruction.Operand;
                            if (_modelTypeInitialization &&
                                EnsureTypeInitialized(
                                    field.DeclaringType.ResolveTypeDef(),
                                    TypeInitializationTrigger.StaticField,
                                    budget,
                                    depth) is { } initializationFailure)
                            {
                                return initializationFailure;
                            }
                            stack.Add(State.GetStaticFieldReference(field));
                            break;
                        }
                    case Code.Ldfld:
                        {
                            var field = (IField)instruction.Operand;
                            var instance = Pop(stack);
                            if (State.Heap.TryReadManaged(instance, out var dereferenced))
                                instance = dereferenced;
                            if (!State.Heap.TryReadField(instance, field, out var value) &&
                                !(field.DeclaringType.ResolveTypeDef()?.IsValueType == true &&
                                  State.Heap.TryAllocateObject(
                                      field.DeclaringType.FullName, out var valueType) &&
                                  State.Heap.TryReadField(valueType, field, out value)))
                                throw new InvalidOperationException(
                                    "ldfld target is not a modeled object.");
                            stack.Add(TrackOperation(
                                method,
                                instruction,
                                value,
                                ProvenanceKind.InstanceField,
                                instance,
                                value));
                            break;
                        }
                    case Code.Stfld:
                        {
                            var field = (IField)instruction.Operand;
                            var value = Pop(stack);
                            var instance = Pop(stack);
                            var instanceReference = instance;
                            if (State.Heap.TryReadManaged(instance, out var dereferenced))
                                instance = dereferenced;
                            if (!State.Heap.TryWriteField(instance, field, value) &&
                                instanceReference.Kind == StaticValueKind.ManagedReference &&
                                field.DeclaringType.ResolveTypeDef()?.IsValueType == true &&
                                State.Heap.TryAllocateObject(
                                    field.DeclaringType.FullName, out var boxedValue) &&
                                State.Heap.TryWriteField(boxedValue, field, value) &&
                                State.Heap.TryWriteManaged(instanceReference, boxedValue))
                            {
                                break;
                            }
                            if (!State.Heap.TryWriteField(instance, field, value))
                                throw new InvalidOperationException("stfld target is not a modeled object.");
                            break;
                        }
                    case Code.Ldflda:
                        {
                            var field = (IField)instruction.Operand;
                            var instance = Pop(stack);
                            if (State.Heap.TryReadManaged(instance, out var dereferenced))
                                instance = dereferenced;
                            if (!State.Heap.TryGetFieldReference(instance, field, out var reference))
                                throw new InvalidOperationException("ldflda target is not a modeled object.");
                            stack.Add(reference);
                            break;
                        }
                    case Code.Box:
                        {
                            var typeName = ((ITypeDefOrRef)instruction.Operand).FullName;
                            if (!State.Heap.TryAllocateBox(typeName, Pop(stack), out var boxed))
                                return AllocationFailure(instruction, "box");
                            stack.Add(boxed);
                            break;
                        }
                    case Code.Castclass:
                    case Code.Isinst:
                        {
                            var value = Pop(stack);
                            if (value.Kind == StaticValueKind.Null)
                            {
                                stack.Add(value);
                                break;
                            }
                            var expected = (instruction.Operand as ITypeDefOrRef)?.FullName;
                            var matches = expected == "System.Object" ||
                                State.Heap.TryGetRuntimeTypeName(value, out var actual) &&
                                (string.Equals(actual, expected, StringComparison.Ordinal) ||
                                 actual == "System.Delegate" &&
                                 (instruction.Operand as ITypeDefOrRef)?
                                     .ResolveTypeDef()?.BaseType?.FullName is
                                         "System.MulticastDelegate" or "System.Delegate");
                            if (matches)
                            {
                                stack.Add(value);
                                break;
                            }
                            if (instruction.OpCode.Code == Code.Isinst)
                            {
                                stack.Add(StaticValue.Null);
                                break;
                            }
                            throw new InvalidOperationException(
                                $"Modeled object cannot be cast to {expected}.");
                        }
                    case Code.Unbox_Any:
                        {
                            var boxed = Pop(stack);
                            if (!State.Heap.TryUnbox(boxed, out var value))
                                throw new InvalidOperationException("unbox.any target is not a concrete box.");
                            stack.Add(value);
                            break;
                        }
                    case Code.Unbox:
                        return FrameResult.Fail(
                            StaticExecutionStatus.Unsupported,
                            $"IL_{instruction.Offset:X4}: unbox managed interior pointers are unsupported.");

                    case Code.Newobj:
                    case Code.Call:
                    case Code.Callvirt:
                        {
                            if (instruction.Operand is not IMethod target)
                                throw new InvalidOperationException("Call operand is not a method.");
                            var signature = target.MethodSig ??
                                throw new InvalidOperationException("Called method has no signature.");
                            var isConstructor = instruction.OpCode.Code == Code.Newobj;
                            var callArguments = PopArguments(stack,
                                signature.Params.Count + (isConstructor ? 0 : signature.HasThis ? 1 : 0));
                            StaticValue constructed = default;
                            if (isConstructor)
                            {
                                if (!State.Heap.TryAllocateObject(target.DeclaringType.FullName, out constructed))
                                    return AllocationFailure(instruction, "object");
                                callArguments = [constructed, .. callArguments];
                            }
                            var definition = target.ResolveMethodDef();
                            if ((instruction.OpCode.Code == Code.Callvirt ||
                                 definition is { HasBody: false }) &&
                                callArguments.Length > 0)
                            {
                                definition = ResolveVirtualTarget(
                                    target,
                                    callArguments[0],
                                    method.Module) ?? definition;
                            }
                            FrameResult callResult;
                            if (definition is not null && definition.HasBody &&
                                definition.Module == method.Module)
                            {
                                callResult = ExecuteFrame(definition, callArguments, budget, depth + 1);
                            }
                            else if (definition is not null &&
                                definition.Module == method.Module &&
                                definition.IsStatic &&
                                definition.MethodSig?.Params.Count == 0 &&
                                definition.ReturnType.ToTypeDefOrRef()?.ResolveTypeDef() is
                                    { IsValueType: false } factoryType &&
                                State.Heap.TryAllocateObject(
                                    factoryType.FullName, out var factoryResult))
                            {
                                callResult = FrameResult.Success(factoryResult);
                            }
                            else if (target.MethodSig is
                                     { Params.Count: 0 } factorySignature &&
                                method.Module.GetTypes().FirstOrDefault(type =>
                                    type.FullName == factorySignature.RetType.FullName &&
                                    !type.IsValueType) is { } unresolvedFactoryType &&
                                State.Heap.TryAllocateObject(
                                    unresolvedFactoryType.FullName,
                                    out var unresolvedFactoryResult))
                            {
                                callResult = FrameResult.Success(unresolvedFactoryResult);
                            }
                            else if (_intrinsics.TryResolve(target, out var intrinsic))
                            {
                                var intrinsicResult = intrinsic.Invoke(
                                    new IntrinsicContext(State),
                                    target,
                                    callArguments);
                                callResult = new FrameResult(
                                    intrinsicResult.Status,
                                    intrinsicResult.Value,
                                    intrinsicResult.Status == StaticExecutionStatus.Completed
                                        ? intrinsicResult.Diagnostic
                                        : $"{target.FullName}: {intrinsicResult.Diagnostic}");
                            }
                            else
                            {
                                var receiver = callArguments.Length > 0 &&
                                    State.Heap.TryGetRuntimeTypeName(
                                        callArguments[0], out var receiverType)
                                        ? $", receiver={receiverType}"
                                        : string.Empty;
                                return FrameResult.Fail(
                                    StaticExecutionStatus.Unsupported,
                                    $"IL_{instruction.Offset:X4}: external call {target.FullName} " +
                                    $"is not allowlisted{receiver}.");
                            }

                            if (callResult.Status != StaticExecutionStatus.Completed)
                                return callResult with
                                {
                                    Diagnostic =
                                        $"{method.FullName} IL_{instruction.Offset:X4} -> " +
                                        $"{target.FullName} args=[" +
                                        string.Join(",", callArguments.Select(value =>
                                            $"{value.Kind}:{value.Bits}")) +
                                        $"] -> {callResult.Diagnostic}" +
                                        (callResult.Diagnostic?.Contains(
                                            "| provenance:",
                                            StringComparison.Ordinal) == true
                                            ? string.Empty
                                            : RenderArgumentProvenance(callArguments))
                                };
                            if (isConstructor)
                                stack.Add(TrackOperation(
                                    method,
                                    instruction,
                                    constructed,
                                    ProvenanceKind.Call,
                                    callArguments));
                            else if (signature.RetType.ElementType != ElementType.Void)
                                stack.Add(TrackOperation(
                                    method,
                                    instruction,
                                    callResult.Value,
                                    _intrinsics.TryResolve(target, out _)
                                        ? ProvenanceKind.Intrinsic
                                        : ProvenanceKind.Call,
                                    [callResult.Value, .. callArguments]));
                            break;
                        }
                    case Code.Ret:
                        if (method.ReturnType.ElementType == ElementType.Void)
                        {
                            if (stack.Count != 0)
                                throw new InvalidOperationException("Void return has a non-empty stack.");
                            return FrameResult.Success(default);
                        }
                        return FrameResult.Success(Pop(stack));

                    default:
                        return FrameResult.Fail(
                            StaticExecutionStatus.Unsupported,
                            $"IL_{instruction.Offset:X4}: opcode {instruction.OpCode.Name} is unsupported.");
                }
            }
            catch (Exception exception) when (
                exception is InvalidOperationException or
                ArgumentOutOfRangeException or
                IndexOutOfRangeException or
                OverflowException or
                DivideByZeroException)
            {
                return FrameResult.Fail(
                    StaticExecutionStatus.InvalidProgram,
                    $"IL_{instruction.Offset:X4} {instruction.OpCode.Name} " +
                    $"{instruction.Operand}: {exception.Message}");
            }
            ip = next;
        }

        return FrameResult.Fail(
            StaticExecutionStatus.InvalidProgram,
            $"{method.FullName} fell through without returning.");
    }

    private StaticValue Binary(Code code, StaticValue left, StaticValue right)
    {
        if (!left.IsKnown || !right.IsKnown)
            return StaticValue.Unknown;
        if (TryOffsetManagedPointer(code, left, right, out var offsetPointer))
            return offsetPointer;
        left = NormalizePointer(left);
        right = NormalizePointer(right);
        if (left.Kind is StaticValueKind.NativePointer or StaticValueKind.HeapReference &&
            right.IsInteger)
        {
            var delta = checked((int)right.AsInt64());
            if (code == Code.Sub)
                delta = checked(-delta);
            if (code is Code.Add or Code.Sub &&
                State.Heap.TryGetNativePointer(left, delta, out var pointer))
            {
                return pointer;
            }
        }
        if (right.Kind is StaticValueKind.NativePointer or StaticValueKind.HeapReference &&
            left.IsInteger &&
            code == Code.Add &&
            State.Heap.TryGetNativePointer(
                right,
                checked((int)left.AsInt64()),
                out var reversedPointer))
        {
            return reversedPointer;
        }
        if (left.Kind == StaticValueKind.NativePointer &&
            right.Kind == StaticValueKind.NativePointer &&
            code == Code.Sub &&
            left.NativeRegionId == right.NativeRegionId)
        {
            return StaticValue.FromInt64((long)left.NativeOffset - right.NativeOffset);
        }
        if (left.IsFloatingPoint || right.IsFloatingPoint)
        {
            var a = left.IsFloatingPoint ? left.AsFloat64() : left.AsInt64();
            var b = right.IsFloatingPoint ? right.AsFloat64() : right.AsInt64();
            var floatingResult = code switch
            {
                Code.Add => a + b,
                Code.Sub => a - b,
                Code.Mul => a * b,
                Code.Div => a / b,
                Code.Rem => a % b,
                _ => throw new InvalidOperationException($"{code} does not accept floating point.")
            };
            return left.Kind == StaticValueKind.Float32 && right.Kind == StaticValueKind.Float32
                ? StaticValue.FromFloat32((float)floatingResult)
                : StaticValue.FromFloat64(floatingResult);
        }
        if (!left.IsInteger || !right.IsInteger)
            throw new InvalidOperationException($"{code} requires numeric values.");

        var wide = left.Kind == StaticValueKind.Int64 || right.Kind == StaticValueKind.Int64;
        var a64 = left.AsInt64();
        var b64 = right.AsInt64();
        long result = code switch
        {
            Code.Add => unchecked(a64 + b64),
            Code.Sub => unchecked(a64 - b64),
            Code.Mul => unchecked(a64 * b64),
            Code.Div => a64 / b64,
            Code.Div_Un => wide
                ? unchecked((long)(unchecked((ulong)a64) / unchecked((ulong)b64)))
                : unchecked((int)(unchecked((uint)a64) / unchecked((uint)b64))),
            Code.Rem => a64 % b64,
            Code.Rem_Un => wide
                ? unchecked((long)(unchecked((ulong)a64) % unchecked((ulong)b64)))
                : unchecked((int)(unchecked((uint)a64) % unchecked((uint)b64))),
            Code.And => a64 & b64,
            Code.Or => a64 | b64,
            Code.Xor => a64 ^ b64,
            Code.Shl => wide
                ? unchecked(a64 << ((int)b64 & 0x3f))
                : unchecked((int)a64 << ((int)b64 & 0x1f)),
            Code.Shr => wide
                ? a64 >> ((int)b64 & 0x3f)
                : (int)a64 >> ((int)b64 & 0x1f),
            Code.Shr_Un => wide
                ? unchecked((long)(unchecked((ulong)a64) >> ((int)b64 & 0x3f)))
                : unchecked((int)(unchecked((uint)a64) >> ((int)b64 & 0x1f))),
            _ => throw new InvalidOperationException($"Unsupported binary operation {code}.")
        };
        return wide ? StaticValue.FromInt64(result) : StaticValue.FromInt32(unchecked((int)result));
    }

    /// <summary>Models <c>ldelema</c>-derived pointer arithmetic. Without this the managed
    /// reference would be dereferenced by <see cref="NormalizePointer"/> and the resulting
    /// integer would alias unrelated storage.</summary>
    private bool TryOffsetManagedPointer(
        Code code,
        StaticValue left,
        StaticValue right,
        out StaticValue result)
    {
        result = StaticValue.Unknown;
        if (code is not (Code.Add or Code.Sub))
            return false;
        if (left.Kind == StaticValueKind.ManagedReference && right.IsInteger)
        {
            var delta = checked((int)right.AsInt64());
            return State.Heap.TryOffsetManagedReference(
                left,
                code == Code.Sub ? checked(-delta) : delta,
                out result);
        }
        return code == Code.Add &&
            right.Kind == StaticValueKind.ManagedReference &&
            left.IsInteger &&
            State.Heap.TryOffsetManagedReference(
                right,
                checked((int)left.AsInt64()),
                out result);
    }

    private StaticValue NormalizePointer(StaticValue value)
    {
        for (var depth = 0; depth < 4; depth++)
        {
            if (State.Heap.TryGetModelValue(value, "Pointer", out StaticValue modeled))
            {
                value = modeled;
                continue;
            }
            if (State.Heap.TryReadManaged(value, out var managed))
            {
                value = managed;
                continue;
            }
            break;
        }
        return value;
    }

    private static StaticValue Unary(Code code, StaticValue value)
    {
        if (!value.IsKnown)
            return StaticValue.Unknown;
        if (code == Code.Neg && value.IsFloatingPoint)
            return value.Kind == StaticValueKind.Float32
                ? StaticValue.FromFloat32(-value.AsFloat32())
                : StaticValue.FromFloat64(-value.AsFloat64());
        if (!value.IsInteger)
            throw new InvalidOperationException($"{code} requires a numeric value.");
        var result = code == Code.Neg ? unchecked(-value.AsInt64()) : ~value.AsInt64();
        return value.Kind == StaticValueKind.Int64
            ? StaticValue.FromInt64(result)
            : StaticValue.FromInt32(unchecked((int)result));
    }

    private StaticValue ConvertValue(Code code, StaticValue value)
    {
        if (!value.IsKnown)
            return StaticValue.Unknown;
        if (value.Kind == StaticValueKind.ManagedReference &&
            code is Code.Conv_I or Code.Conv_U)
        {
            return value;
        }
        if (value.Kind == StaticValueKind.NativePointer &&
            code is Code.Conv_I or Code.Conv_U)
        {
            return value;
        }
        if (code == Code.Conv_R_Un)
        {
            if (!value.IsInteger)
                throw new InvalidOperationException("conv.r.un requires an integer value.");
            var unsigned = value.Kind == StaticValueKind.Int64
                ? (double)unchecked((ulong)value.AsInt64())
                : (double)unchecked((uint)value.AsInt32());
            return StaticValue.FromFloat64(unsigned);
        }
        if (value.IsInteger)
            return ConvertInteger(code, value);
        if (!value.IsFloatingPoint)
            throw new InvalidOperationException($"{code} requires a numeric value.");
        var number = value.AsFloat64();
        if (code is Code.Conv_R4 or Code.Conv_R8)
        {
            return code == Code.Conv_R4
                ? StaticValue.FromFloat32((float)number)
                : StaticValue.FromFloat64(number);
        }
        if (!double.IsFinite(number))
            throw UnspecifiedFloatingConversion(code, number);
        var truncated = Math.Truncate(number);
        return code switch
        {
            Code.Conv_I1 => StaticValue.FromInt32(CheckedSigned(code, truncated, sbyte.MinValue, 128)),
            Code.Conv_U1 => StaticValue.FromInt32(unchecked((byte)CheckedUnsigned(code, truncated, 256))),
            Code.Conv_I2 => StaticValue.FromInt32(CheckedSigned(code, truncated, short.MinValue, 32768)),
            Code.Conv_U2 => StaticValue.FromInt32(unchecked((ushort)CheckedUnsigned(code, truncated, 65536))),
            Code.Conv_I4 => StaticValue.FromInt32(CheckedSigned(code, truncated, int.MinValue, 2147483648d)),
            Code.Conv_U4 => StaticValue.FromInt32(unchecked((int)(uint)CheckedUnsigned(
                code, truncated, 4294967296d))),
            Code.Conv_I8 => StaticValue.FromInt64(CheckedSigned64(code, truncated)),
            Code.Conv_U8 => StaticValue.FromInt64(unchecked((long)CheckedUnsigned64(code, truncated))),
            Code.Conv_I => State.PointerSize == 4
                ? StaticValue.FromInt32(CheckedSigned(code, truncated, int.MinValue, 2147483648d))
                : StaticValue.FromInt64(CheckedSigned64(code, truncated)),
            Code.Conv_U => State.PointerSize == 4
                ? StaticValue.FromInt32(unchecked((int)(uint)CheckedUnsigned(
                    code, truncated, 4294967296d)))
                : StaticValue.FromInt64(unchecked((long)CheckedUnsigned64(code, truncated))),
            _ => throw new InvalidOperationException($"Unsupported conversion {code}.")
        };
    }

    private StaticValue ConvertInteger(Code code, StaticValue value)
    {
        var number = value.AsInt64();
        return code switch
        {
            Code.Conv_I1 => StaticValue.FromInt32(unchecked((sbyte)number)),
            Code.Conv_U1 => StaticValue.FromInt32(unchecked((byte)number)),
            Code.Conv_I2 => StaticValue.FromInt32(unchecked((short)number)),
            Code.Conv_U2 => StaticValue.FromInt32(unchecked((ushort)number)),
            Code.Conv_I4 => StaticValue.FromInt32(unchecked((int)number)),
            Code.Conv_U4 => StaticValue.FromInt32(unchecked((int)(uint)number)),
            Code.Conv_I8 => StaticValue.FromInt64(number),
            Code.Conv_U8 => StaticValue.FromInt64(value.Kind == StaticValueKind.Int32
                ? unchecked((long)(uint)value.AsInt32())
                : number),
            Code.Conv_I => State.PointerSize == 4
            ? StaticValue.FromInt32(unchecked((int)number))
            : StaticValue.FromInt64(number),
            Code.Conv_U => State.PointerSize == 4
            ? StaticValue.FromInt32(unchecked((int)(uint)number))
            : StaticValue.FromInt64(value.Kind == StaticValueKind.Int32
                ? unchecked((long)(uint)value.AsInt32())
                : number),
            Code.Conv_R4 => StaticValue.FromFloat32((float)number),
            Code.Conv_R8 => StaticValue.FromFloat64(number),
            _ => throw new InvalidOperationException($"Unsupported conversion {code}.")
        };
    }

    private static int CheckedSigned(Code code, double value, int minimum, double exclusiveMaximum)
    {
        if (value < minimum || value >= exclusiveMaximum)
            throw UnspecifiedFloatingConversion(code, value);
        return (int)value;
    }

    private static uint CheckedUnsigned(Code code, double value, double exclusiveMaximum)
    {
        if (value < 0 || value >= exclusiveMaximum)
            throw UnspecifiedFloatingConversion(code, value);
        return (uint)value;
    }

    private static long CheckedSigned64(Code code, double value)
    {
        const double exclusiveMaximum = 9223372036854775808d;
        if (value < -exclusiveMaximum || value >= exclusiveMaximum)
            throw UnspecifiedFloatingConversion(code, value);
        return (long)value;
    }

    private static ulong CheckedUnsigned64(Code code, double value)
    {
        const double exclusiveMaximum = 18446744073709551616d;
        if (value < 0 || value >= exclusiveMaximum)
            throw UnspecifiedFloatingConversion(code, value);
        return (ulong)value;
    }

    private static InvalidOperationException UnspecifiedFloatingConversion(
        Code code,
        double value) =>
        new(
            $"{code} input {value:R} has implementation-dependent ECMA-335 " +
            "floating-to-integer overflow behavior.");

    private static StaticValue Compare(Code code, StaticValue left, StaticValue right)
    {
        if (!left.IsKnown || !right.IsKnown)
            return StaticValue.Unknown;
        var result = code switch
        {
            Code.Ceq => Equal(left, right),
            Code.Cgt => OrderedCompare(left, right, unsigned: false) > 0,
            Code.Cgt_Un => OrderedCompare(left, right, unsigned: true) > 0,
            Code.Clt => OrderedCompare(left, right, unsigned: false) < 0,
            Code.Clt_Un => OrderedCompare(left, right, unsigned: true) < 0,
            _ => false
        };
        return StaticValue.FromInt32(result ? 1 : 0);
    }

    private static bool? BranchCompare(Code code, StaticValue left, StaticValue right)
    {
        if (!left.IsKnown || !right.IsKnown)
            return null;
        if (code is Code.Beq or Code.Beq_S)
            return Equal(left, right);
        if (code is Code.Bne_Un or Code.Bne_Un_S)
            return !Equal(left, right);
        var unsigned = code is
            Code.Bgt_Un or Code.Bgt_Un_S or Code.Bge_Un or Code.Bge_Un_S or
            Code.Blt_Un or Code.Blt_Un_S or Code.Ble_Un or Code.Ble_Un_S;
        var comparison = OrderedCompare(left, right, unsigned);
        return code switch
        {
            Code.Bgt or Code.Bgt_S or Code.Bgt_Un or Code.Bgt_Un_S => comparison > 0,
            Code.Bge or Code.Bge_S or Code.Bge_Un or Code.Bge_Un_S => comparison >= 0,
            Code.Blt or Code.Blt_S or Code.Blt_Un or Code.Blt_Un_S => comparison < 0,
            Code.Ble or Code.Ble_S or Code.Ble_Un or Code.Ble_Un_S => comparison <= 0,
            _ => false
        };
    }

    private static bool Equal(StaticValue left, StaticValue right)
    {
        if (left.Kind == StaticValueKind.Null || right.Kind == StaticValueKind.Null ||
            left.Kind is StaticValueKind.HeapReference or StaticValueKind.ManagedReference or
                StaticValueKind.NativePointer ||
            right.Kind is StaticValueKind.HeapReference or StaticValueKind.ManagedReference or
                StaticValueKind.NativePointer)
            return left.Kind == right.Kind && left.Bits == right.Bits;
        if (left.IsFloatingPoint || right.IsFloatingPoint)
            return (left.IsFloatingPoint ? left.AsFloat64() : left.AsInt64()) ==
                (right.IsFloatingPoint ? right.AsFloat64() : right.AsInt64());
        return left.AsInt64() == right.AsInt64();
    }

    private static int OrderedCompare(StaticValue left, StaticValue right, bool unsigned)
    {
        if (left.IsFloatingPoint || right.IsFloatingPoint)
        {
            var a = left.IsFloatingPoint ? left.AsFloat64() : left.AsInt64();
            var b = right.IsFloatingPoint ? right.AsFloat64() : right.AsInt64();
            if (double.IsNaN(a) || double.IsNaN(b))
                return unsigned ? 1 : -1;
            return a.CompareTo(b);
        }
        if (!left.IsInteger || !right.IsInteger)
            throw new InvalidOperationException("Ordered comparison requires numeric values.");
        if (!unsigned)
            return left.AsInt64().CompareTo(right.AsInt64());
        return left.Kind == StaticValueKind.Int32 && right.Kind == StaticValueKind.Int32
            ? unchecked((uint)left.AsInt64()).CompareTo(unchecked((uint)right.AsInt64()))
            : unchecked((ulong)left.AsInt64()).CompareTo(unchecked((ulong)right.AsInt64()));
    }

    private static bool? Truth(StaticValue value) => value.Kind switch
    {
        StaticValueKind.Unknown => null,
        StaticValueKind.Null => false,
        StaticValueKind.HeapReference => true,
        StaticValueKind.ManagedReference => true,
        StaticValueKind.NativePointer => true,
        StaticValueKind.Int32 or StaticValueKind.Int64 => value.AsInt64() != 0,
        _ => throw new InvalidOperationException("Branch condition is not integer or reference.")
    };

    private static StaticValue NormalizeElement(Code code, StaticValue value)
    {
        if (!value.IsKnown || !value.IsInteger)
            return value;
        return code switch
        {
            Code.Ldelem_I1 => StaticValue.FromInt32(unchecked((sbyte)value.AsInt64())),
            Code.Ldelem_U1 => StaticValue.FromInt32(unchecked((byte)value.AsInt64())),
            Code.Ldelem_I2 => StaticValue.FromInt32(unchecked((short)value.AsInt64())),
            Code.Ldelem_U2 => StaticValue.FromInt32(unchecked((ushort)value.AsInt64())),
            Code.Ldelem_I4 or Code.Ldelem_U4 or Code.Ldelem_I =>
                StaticValue.FromInt32(unchecked((int)value.AsInt64())),
            Code.Ldelem_I8 => StaticValue.FromInt64(value.AsInt64()),
            _ => value
        };
    }

    private bool TryReadIndirect(Code code, StaticValue address, out StaticValue value)
    {
        if (!SpansManagedElements(code, address) &&
            State.Heap.TryReadManaged(address, out value))
        {
            value = NormalizeIndirect(code, value);
            return true;
        }
        if (address.IsInteger &&
            State.Heap.TryResolveNativeAddress(
                address.AsInt64(),
                out var syntheticAddress))
        {
            address = syntheticAddress;
        }
        else if (address.IsInteger &&
            address.AsInt64() is >= 0 and <= int.MaxValue &&
            State.Heap.TryGetNativePointer(
                State.ImageRegion,
                checked((int)address.AsInt64()),
                out syntheticAddress))
        {
            address = syntheticAddress;
        }
        var width = IndirectWidth(code);
        Span<byte> bytes = stackalloc byte[8];
        if (width == 0 || !State.Heap.TryReadBytes(address, 0, bytes[..width]))
        {
            value = StaticValue.Unknown;
            return false;
        }
        value = code switch
        {
            Code.Ldind_I1 => StaticValue.FromInt32(unchecked((sbyte)bytes[0])),
            Code.Ldind_U1 => StaticValue.FromInt32(bytes[0]),
            Code.Ldind_I2 => StaticValue.FromInt32(BinaryPrimitives.ReadInt16LittleEndian(bytes)),
            Code.Ldind_U2 => StaticValue.FromInt32(BinaryPrimitives.ReadUInt16LittleEndian(bytes)),
            Code.Ldind_I4 or Code.Ldind_U4 =>
                StaticValue.FromInt32(BinaryPrimitives.ReadInt32LittleEndian(bytes)),
            Code.Ldind_I8 =>
                StaticValue.FromInt64(BinaryPrimitives.ReadInt64LittleEndian(bytes)),
            Code.Ldind_I => State.PointerSize == 4
                ? StaticValue.FromInt32(BinaryPrimitives.ReadInt32LittleEndian(bytes))
                : StaticValue.FromInt64(BinaryPrimitives.ReadInt64LittleEndian(bytes)),
            Code.Ldind_R4 => StaticValue.FromFloat32(BitConverter.Int32BitsToSingle(
                BinaryPrimitives.ReadInt32LittleEndian(bytes))),
            Code.Ldind_R8 => StaticValue.FromFloat64(BitConverter.Int64BitsToDouble(
                BinaryPrimitives.ReadInt64LittleEndian(bytes))),
            _ => StaticValue.Unknown
        };
        return value.IsKnown;
    }

    private bool TryWriteIndirect(Code code, StaticValue address, StaticValue value)
    {
        if (address.Kind == StaticValueKind.ManagedReference &&
            !SpansManagedElements(code, address))
        {
            var normalized = code switch
            {
                Code.Stind_I1 => StaticValue.FromInt32(unchecked((sbyte)value.AsInt64())),
                Code.Stind_I2 => StaticValue.FromInt32(unchecked((short)value.AsInt64())),
                Code.Stind_I4 => StaticValue.FromInt32(unchecked((int)value.AsInt64())),
                Code.Stind_I8 => StaticValue.FromInt64(value.AsInt64()),
                Code.Stind_I => State.PointerSize == 4
                    ? StaticValue.FromInt32(unchecked((int)value.AsInt64()))
                    : StaticValue.FromInt64(value.AsInt64()),
                Code.Stind_R4 => StaticValue.FromFloat32((float)value.AsFloat64()),
                Code.Stind_R8 => StaticValue.FromFloat64(value.AsFloat64()),
                _ => value
            };
            return State.Heap.TryWriteManaged(address, normalized);
        }
        if (address.IsInteger &&
            State.Heap.TryResolveNativeAddress(
                address.AsInt64(),
                out var syntheticAddress))
        {
            address = syntheticAddress;
        }
        else if (address.IsInteger &&
            address.AsInt64() is >= 0 and <= int.MaxValue &&
            State.Heap.TryGetNativePointer(
                State.ImageRegion,
                checked((int)address.AsInt64()),
                out syntheticAddress))
        {
            address = syntheticAddress;
        }
        var width = IndirectWidth(code);
        Span<byte> bytes = stackalloc byte[8];
        if (width == 0)
            return false;
        if (value.IsFloatingPoint)
        {
            if (width == 4)
                BinaryPrimitives.WriteInt32LittleEndian(
                    bytes,
                    BitConverter.SingleToInt32Bits((float)value.AsFloat64()));
            else
                BinaryPrimitives.WriteInt64LittleEndian(
                    bytes,
                    BitConverter.DoubleToInt64Bits(value.AsFloat64()));
        }
        else if (value.IsInteger)
        {
            var integer = value.AsInt64();
            if (width == 1)
                bytes[0] = unchecked((byte)integer);
            else if (width == 2)
                BinaryPrimitives.WriteInt16LittleEndian(bytes, unchecked((short)integer));
            else if (width == 4)
                BinaryPrimitives.WriteInt32LittleEndian(bytes, unchecked((int)integer));
            else
                BinaryPrimitives.WriteInt64LittleEndian(bytes, integer);
        }
        else
        {
            return false;
        }
        return State.Heap.TryWriteBytes(address, 0, bytes[..width]);
    }

    /// <summary>True when an indirect access through a managed reference is wider than the
    /// element it points at, so it must be serviced as raw bytes rather than one element.</summary>
    private bool SpansManagedElements(Code code, StaticValue address)
    {
        var width = IndirectWidth(code);
        return width != 0 &&
            State.Heap.TryGetManagedElementWidth(address, out var elementWidth) &&
            elementWidth != width;
    }

    private int IndirectWidth(Code code) => code switch
    {
        Code.Ldind_I1 or Code.Ldind_U1 or Code.Stind_I1 => 1,
        Code.Ldind_I2 or Code.Ldind_U2 or Code.Stind_I2 => 2,
        Code.Ldind_I4 or Code.Ldind_U4 or Code.Ldind_R4 or
            Code.Stind_I4 or Code.Stind_R4 => 4,
        Code.Ldind_I8 or Code.Ldind_R8 or Code.Stind_I8 or Code.Stind_R8 => 8,
        Code.Ldind_I or Code.Stind_I => State.PointerSize,
        _ => 0
    };

    private static StaticValue NormalizeIndirect(Code code, StaticValue value)
    {
        if (!value.IsKnown || !value.IsInteger)
            return value;
        return code switch
        {
            Code.Ldind_I1 => StaticValue.FromInt32(unchecked((sbyte)value.AsInt64())),
            Code.Ldind_U1 => StaticValue.FromInt32(unchecked((byte)value.AsInt64())),
            Code.Ldind_I2 => StaticValue.FromInt32(unchecked((short)value.AsInt64())),
            Code.Ldind_U2 => StaticValue.FromInt32(unchecked((ushort)value.AsInt64())),
            Code.Ldind_I4 or Code.Ldind_U4 or Code.Ldind_I =>
                StaticValue.FromInt32(unchecked((int)value.AsInt64())),
            Code.Ldind_I8 => StaticValue.FromInt64(value.AsInt64()),
            _ => value
        };
    }

    private static StaticValue DefaultValue(TypeSig? type) =>
        type?.ElementType is ElementType.Class or ElementType.Object or ElementType.String or
            ElementType.Array or ElementType.SZArray
            ? StaticValue.Null
            : type?.ElementType is ElementType.I8 or ElementType.U8
                ? StaticValue.FromInt64(0)
                : type?.ElementType == ElementType.R4
                    ? StaticValue.FromFloat32(0)
                    : type?.ElementType == ElementType.R8
                        ? StaticValue.FromFloat64(0)
                        : StaticValue.FromInt32(0);

    private static StaticValue ConstantValue(object? value) => value switch
    {
        null => StaticValue.Null,
        bool item => StaticValue.FromInt32(item ? 1 : 0),
        byte item => StaticValue.FromInt32(item),
        sbyte item => StaticValue.FromInt32(item),
        short item => StaticValue.FromInt32(item),
        ushort item => StaticValue.FromInt32(item),
        int item => StaticValue.FromInt32(item),
        uint item => StaticValue.FromInt32(unchecked((int)item)),
        long item => StaticValue.FromInt64(item),
        ulong item => StaticValue.FromInt64(unchecked((long)item)),
        float item => StaticValue.FromFloat32(item),
        double item => StaticValue.FromFloat64(item),
        _ => StaticValue.Unknown
    };

    private static StaticValue[] PopArguments(List<StaticValue> stack, int count)
    {
        if (count < 0 || stack.Count < count)
            throw new InvalidOperationException("Evaluation stack underflow.");
        var result = new StaticValue[count];
        for (var index = count - 1; index >= 0; index--)
            result[index] = Pop(stack);
        return result;
    }

    private MethodDef? ResolveVirtualTarget(
        IMethod target,
        StaticValue instance,
        ModuleDef module)
    {
        var expected = target.ResolveMethodDef();
        var comparer = new SigComparer();
        if (State.Heap.TryGetRuntimeTypeName(instance, out var runtimeTypeName) &&
            module.GetTypes().FirstOrDefault(type =>
                type.FullName == runtimeTypeName) is { } runtimeType)
        {
            for (var type = runtimeType; type is not null; type = type.BaseType?.ResolveTypeDef())
            {
                foreach (var candidate in type.Methods.Where(candidate =>
                             candidate.HasBody && !candidate.IsAbstract))
                {
                    if (expected is not null &&
                        candidate.Overrides.Any(implementation =>
                            implementation.MethodDeclaration.ResolveMethodDef() == expected))
                        return candidate;
                    if (candidate.Name == target.Name &&
                        comparer.Equals(candidate.MethodSig, target.MethodSig))
                        return candidate;
                }
            }
        }
        var uniqueOverrides = module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(candidate => expected is not null &&
                candidate.HasBody && !candidate.IsAbstract &&
                candidate.Overrides.Any(implementation =>
                    implementation.MethodDeclaration.ResolveMethodDef() == expected))
            .Take(2)
            .ToArray();
        return uniqueOverrides.Length == 1 ? uniqueOverrides[0] : null;
    }

    private StaticValue LoadSlot(
        StaticValue[] slots,
        Dictionary<int, StaticValue> references,
        int index)
    {
        if ((uint)index >= (uint)slots.Length)
            throw new InvalidOperationException("Slot index is out of range.");
        return references.TryGetValue(index, out var reference) &&
            State.Heap.TryReadManaged(reference, out var value)
                ? value
                : slots[index];
    }

    private static void StoreSlot(
        StaticValue[] slots,
        Dictionary<int, StaticValue> references,
        int index,
        StaticValue value,
        StaticHeap heap)
    {
        if ((uint)index >= (uint)slots.Length)
            throw new InvalidOperationException("Slot index is out of range.");
        slots[index] = value;
        if (references.TryGetValue(index, out var reference) &&
            !heap.TryWriteManaged(reference, value))
            throw new InvalidOperationException("Managed slot reference is invalid.");
    }

    private static StaticValue AddressOfSlot(
        StaticValue[] slots,
        Dictionary<int, StaticValue> references,
        int index,
        StaticHeap heap)
    {
        if ((uint)index >= (uint)slots.Length)
            throw new InvalidOperationException("Slot index is out of range.");
        if (!references.TryGetValue(index, out var reference))
        {
            reference = heap.AllocateManagedCell(slots[index]);
            references[index] = reference;
        }
        return reference;
    }

    private static ExceptionHandler? FindFinally(
        MethodDef method,
        Dictionary<Instruction, int> indices,
        int source,
        int target)
    {
        return method.Body.ExceptionHandlers
            .Where(handler => handler.HandlerType == ExceptionHandlerType.Finally)
            .Where(handler =>
            {
                var start = indices[handler.TryStart];
                var end = indices[handler.TryEnd];
                return source >= start && source < end && (target < start || target >= end);
            })
            .OrderBy(handler => indices[handler.TryEnd] - indices[handler.TryStart])
            .FirstOrDefault();
    }

    private static FrameResult AllocationFailure(Instruction instruction, string kind) =>
        FrameResult.Fail(
            StaticExecutionStatus.AllocationLimitExceeded,
            $"IL_{instruction.Offset:X4}: {kind} exceeded allocation limits.");

    private static int ArgumentIndex(MethodDef method, object operand)
    {
        if (operand is Parameter parameter)
        {
            var index = method.Parameters.IndexOf(parameter);
            if (index >= 0)
                return index;
            return parameter.Index;
        }
        return operand switch
        {
            byte value => value,
            ushort value => value,
            int value => value,
            _ => throw new InvalidOperationException("Invalid argument operand.")
        };
    }

    private static int LocalIndex(object operand) => operand switch
    {
        Local local => local.Index,
        byte value => value,
        ushort value => value,
        int value => value,
        _ => throw new InvalidOperationException("Invalid local operand.")
    };

    private static int Target(
        Dictionary<Instruction, int> indices,
        object operand) =>
        operand is Instruction target && indices.TryGetValue(target, out var index)
            ? index
            : throw new InvalidOperationException("Branch target is outside the method.");

    private static StaticValue Pop(List<StaticValue> stack)
    {
        if (stack.Count == 0)
            throw new InvalidOperationException("Evaluation stack underflow.");
        var index = stack.Count - 1;
        var value = stack[index];
        stack.RemoveAt(index);
        return value;
    }

    private static StaticValue Peek(List<StaticValue> stack) =>
        stack.Count == 0
            ? throw new InvalidOperationException("Evaluation stack underflow.")
            : stack[^1];

    private static FrameResult UnknownBranch(Instruction instruction) =>
        FrameResult.Fail(
            StaticExecutionStatus.Unknown,
            $"IL_{instruction.Offset:X4}: branch condition is unknown.");

    private StaticValue TrackOrigin(
        MethodDef method,
        Instruction instruction,
        StaticValue value,
        string detail) =>
        State.Provenance.Origin(
            value,
            ProvenanceKind.Literal,
            $"{method.MDToken}/IL_{instruction.Offset:X4}",
            detail);

    private StaticValue TrackOperation(
        MethodDef method,
        Instruction instruction,
        StaticValue value,
        ProvenanceKind kind,
        params StaticValue[] inputs) =>
        State.Provenance.Operation(
            value,
            kind,
            $"{method.MDToken}/IL_{instruction.Offset:X4}",
            instruction.OpCode.Name,
            inputs);

    private string RenderArgumentProvenance(IReadOnlyList<StaticValue> arguments)
    {
        var slices = arguments
            .Select((value, index) => (value, index))
            .Where(item => item.value.ProvenanceId != 0)
            .Take(6)
            .Select(item =>
                $" arg{item.index}: {State.Provenance.Render(item.value.ProvenanceId)}");
        var rendered = string.Join(string.Empty, slices);
        return rendered.Length == 0 ? string.Empty : $" | provenance:{rendered}";
    }

    private FrameResult? EnsureTypeInitialized(
        TypeDef? type,
        TypeInitializationTrigger trigger,
        StaticWorkBudget budget,
        int depth)
    {
        var initializer = type?.FindStaticConstructor();
        if (type is null ||
            initializer?.HasBody != true ||
            (trigger == TypeInitializationTrigger.MethodCall && type.IsBeforeFieldInit))
        {
            return null;
        }
        var status = State.GetTypeInitializationStatus(type);
        if (status is TypeInitializationStatus.Initialized or
            TypeInitializationStatus.Initializing)
        {
            return null;
        }
        if (status == TypeInitializationStatus.Failed)
        {
            return FrameResult.Fail(
                StaticExecutionStatus.InvalidProgram,
                $"Type initializer {initializer.FullName} previously failed: " +
                State.GetTypeInitializationFailure(type));
        }
        State.TryBeginTypeInitialization(type);
        var result = ExecuteFrame(initializer, [], budget, depth + 1);
        if (result.Status == StaticExecutionStatus.Completed)
        {
            State.CompleteTypeInitialization(type);
            return null;
        }
        State.FailTypeInitialization(type, result.Diagnostic ?? result.Status.ToString());
        return result with
        {
            Diagnostic =
                $"{trigger} requires {initializer.FullName}: {result.Diagnostic}"
        };
    }

    private enum TypeInitializationTrigger
    {
        StaticField,
        MethodCall
    }

    private readonly record struct FrameResult(
        StaticExecutionStatus Status,
        StaticValue Value,
        string? Diagnostic)
    {
        public static FrameResult Success(StaticValue value) =>
            new(StaticExecutionStatus.Completed, value, null);
        public static FrameResult Fail(StaticExecutionStatus status, string diagnostic) =>
            new(status, StaticValue.Unknown, diagnostic);
    }
}
