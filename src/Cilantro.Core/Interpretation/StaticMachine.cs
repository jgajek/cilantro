using System.Buffers.Binary;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Interpretation;

public sealed class StaticMachine
{
    private readonly StaticMachineLimits _limits;
    private readonly IStaticIntrinsicRegistry _intrinsics;
    private readonly bool _modelTypeInitialization;

    // Answers about the shape of the metadata, which does not change while an interpretation runs.
    // Each was a scan of every type, or every method of every type, performed per instruction that
    // asked; on a module with thousands of types that is the same cost per step as the whole module,
    // and dnlib takes a lock for each step of a lazy list, so the scans showed up as lock contention
    // rather than as work. A machine reads metadata and never adds to it, so caching for the life of
    // the machine is caching for exactly as long as the answers hold.
    private readonly Dictionary<ModuleDef, Dictionary<string, TypeDef>> _typesByName = [];
    private readonly Dictionary<ModuleDef, Dictionary<string, TypeDef>> _classesByName = [];
    private readonly Dictionary<MethodDef, MethodDef?> _soleImplementations = [];
    private readonly Dictionary<TypeDef, MethodDef?> _staticConstructors = [];
    private readonly Dictionary<Instruction, string> _locations = [];

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
        // Recorded here rather than where the throw happened, because a throw the program catches is
        // the program working and only one that reaches the top stopped anything.
        if (result.Status == StaticExecutionStatus.Threw)
            State.Blockers.Record(
                BlockerKind.Threw,
                State.ThrowSites.Count != 0 ? State.ThrowSites[^1] : method.FullName,
                result.Diagnostic ?? "The interpreted program threw.",
                where: method.FullName);
        // A value that was never determined is only worth recording where nothing else was: the frame
        // that declined to produce it has already said so, and saying it again from out here would
        // report one stop as two.
        else if (result.Status == StaticExecutionStatus.Unknown && State.Blockers.Count == 0)
            State.Blockers.Record(
                BlockerKind.UnknownValue,
                method.FullName,
                (result.Diagnostic ?? "A value was not determined.") + Earlier,
                where: method.FullName);
        if (MachineTrace.Enabled && result.Status != StaticExecutionStatus.Completed)
            MachineTrace.DumpRecent($"{method.Name} gave up: {result.Diagnostic}");
        return new StaticExecutionResult(
            result.Status,
            result.Value,
            result.Diagnostic,
            budget.ConsumedSteps,
            State.Heap.AllocatedBytes);
    }

    /// <summary>
    /// Performs one call the way the machine's own call instruction performs one.
    /// </summary>
    /// <remarks>
    /// A protector's virtual program is a list of operations rather than instructions, so whatever
    /// steps through it is not this machine's instruction loop. The calls it makes are still this
    /// machine's calls: a body in the module is run, an override is dispatched to the type the
    /// receiver turned out to be, and everything else is offered to the models. Nothing about that
    /// belongs to the instruction loop, and a reader that had to decide it again would be a second
    /// answer to a question with one answer — which is how a framework type comes to be modeled in
    /// one reading and refused in another.
    /// </remarks>
    /// <param name="method">The method the call names, resolved or not.</param>
    /// <param name="arguments">Its arguments, the receiver first where it has one.</param>
    public StaticExecutionResult Invoke(
        IMethod method,
        IReadOnlyList<StaticValue>? arguments = null)
    {
        ArgumentNullException.ThrowIfNull(method);
        var budget = new StaticWorkBudget(_limits.MaximumSteps);
        var result = Reenter(method, arguments ?? [], budget, 0);
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
    /// <summary>
    /// The methods currently on the machine's stack, outermost first.
    /// </summary>
    /// <remarks>
    /// Kept because protected code asks. A string decrypter that reads its own caller and folds the
    /// caller's token into the key is only answerable by a machine that knows who called it, and the
    /// machine does know — this is simply that knowledge written down where a modeled API can reach
    /// it.
    /// </remarks>
    private readonly List<MethodDef> _frames = [];

    /// <summary>Steps the current frame spent inside the frames it called, for the profile.</summary>
    private long _stepsInCalls;

    /// <summary>
    /// Called as each frame is entered, when something wants to watch interpretation happen.
    /// </summary>
    /// <remarks>
    /// An obfuscator's own interpreter can be studied far more cheaply by watching it work than by
    /// reading it: what its bytecode decodes to, and which handler each operation reaches, are
    /// answered by the calls it makes. Nothing observes by default, and the cost when nothing does
    /// is a null check per call.
    /// </remarks>
    public Action<MethodDef, IReadOnlyList<StaticValue>>? FrameEntered { get; set; }

    /// <summary>Called as each frame is left, so an observer can follow the call structure.</summary>
    public Action<MethodDef>? FrameExited { get; set; }

    /// <summary>
    /// Called before each instruction runs, for an observer that needs to see inside a frame.
    /// </summary>
    /// <remarks>
    /// A virtualizer that inlines its handlers into one dispatch method makes no calls to watch, so
    /// the only way to see which handler an operation reached is to watch which instructions it ran.
    /// </remarks>
    public Action<MethodDef, Instruction>? Stepped { get; set; }

    private FrameResult ExecuteFrame(
        MethodDef method,
        IReadOnlyList<StaticValue> arguments,
        StaticWorkBudget budget,
        int depth,
        GenericScope? generics = null)
    {
        State.Evidence.EnterMethod(method);
        _frames.Add(method);
        var entry = budget.ConsumedSteps;
        var enclosing = _stepsInCalls;
        _stepsInCalls = 0;
        FrameEntered?.Invoke(method, arguments);
        try
        {
            return ExecuteFrameCore(method, arguments, budget, depth, generics);
        }
        finally
        {
            var total = budget.ConsumedSteps - entry;
            MachineTrace.Frame(method, total - _stepsInCalls, total);
            _stepsInCalls = enclosing + total;
            _frames.RemoveAt(_frames.Count - 1);
            State.Evidence.LeaveMethod();
            FrameExited?.Invoke(method);
        }
    }

    private FrameResult ExecuteFrameCore(
        MethodDef method,
        IReadOnlyList<StaticValue> arguments,
        StaticWorkBudget budget,
        int depth,
        GenericScope? generics)
    {
        if (depth > _limits.MaximumRecursionDepth)
        {
            var deep = $"Call depth exceeded {_limits.MaximumRecursionDepth}.";
            Stopped(
                BlockerKind.Budget,
                "depth",
                deep,
                Declaring.Budget("depth", _limits.MaximumRecursionDepth));
            return FrameResult.Fail(StaticExecutionStatus.RecursionLimitExceeded, deep);
        }
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
        {
            // A method that declares no code at all and one whose code could not be read are
            // different facts about the module, and saying the first when the second is true sends
            // a reader looking for a P/Invoke that is not there. The distinction matters most where
            // a protector encrypts its own bodies: until its decryptor has run, every method it
            // covers reads as bodiless, and the run may be interpreting that decryptor.
            var bodiless = (uint)method.RVA == 0
                ? $"{method.FullName} has no CIL body."
                : $"{method.FullName} declares a body at RVA 0x{(uint)method.RVA:X8} that could " +
                  "not be read as CIL.";
            Stopped(BlockerKind.UnsupportedBody, method.FullName, bodiless);
            return FrameResult.Fail(StaticExecutionStatus.Unsupported, bodiless);
        }
        if (method.Body.ExceptionHandlers.Any(handler =>
            handler.HandlerType is ExceptionHandlerType.Filter or ExceptionHandlerType.Fault ||
            handler.TryStart is null ||
            handler.HandlerStart is null))
        {
            var unsupported =
                $"{method.FullName} uses non-deterministic or unsupported exception handlers.";
            Stopped(
                BlockerKind.UnsupportedBody,
                $"{method.FullName} exception handlers",
                unsupported);
            return FrameResult.Fail(StaticExecutionStatus.Unsupported, unsupported);
        }

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
        var caught = StaticValue.Null;
        var ip = 0;

        while ((uint)ip < (uint)instructions.Count)
        {
            if (!budget.TryConsumeStep())
            {
                // A caller deciding whether spending more would help needs to know this happened
                // even when the code that ran out of budget went on to catch its own failure.
                State.RanOutOfBudget = true;
                var spent = $"Execution exhausted its {budget.MaximumSteps}-step budget.";
                Stopped(
                    BlockerKind.Budget,
                    "steps",
                    spent,
                    Declaring.Budget("steps", budget.MaximumSteps));
                return FrameResult.Fail(StaticExecutionStatus.StepLimitExceeded, spent);
            }


            var instruction = instructions[ip];
            var next = ip + 1;
            Stepped?.Invoke(method, instruction);
            if (MachineTrace.Enabled)
            {
                MachineTrace.Step(
                    $"{method.Name} [{ip}] {instruction.OpCode.Name}" +
                    (instruction.Operand is { } shown ? $" {Abbreviate(shown)}" : string.Empty) +
                    $" | stack {stack.Count}" +
                    (stack.Count != 0 ? $" top={Describe(stack[^1])}" : string.Empty));
            }

            try
            {
                switch (instruction.OpCode.Code)
                {
                    case Code.Nop:
                    case Code.Break:
                    // Prefixes that qualify how the next instruction runs on real hardware without
                    // changing what it computes. The call that follows resolves its own target and
                    // follows a reference receiver where it finds one, so there is nothing here for
                    // the machine to do differently.
                    case Code.Constrained:
                    case Code.Volatile:
                    case Code.Readonly:
                    case Code.Unaligned:
                    case Code.Tailcall:
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
                        State.Heap.TryAllocateMetadataHandle(
                            Denoted(instruction.Operand, generics), out var token);
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
                    case Code.Conv_Ovf_I1:
                    case Code.Conv_Ovf_I1_Un:
                    case Code.Conv_Ovf_U1:
                    case Code.Conv_Ovf_U1_Un:
                    case Code.Conv_Ovf_I2:
                    case Code.Conv_Ovf_I2_Un:
                    case Code.Conv_Ovf_U2:
                    case Code.Conv_Ovf_U2_Un:
                    case Code.Conv_Ovf_I4:
                    case Code.Conv_Ovf_I4_Un:
                    case Code.Conv_Ovf_U4:
                    case Code.Conv_Ovf_U4_Un:
                    case Code.Conv_Ovf_I8:
                    case Code.Conv_Ovf_I8_Un:
                    case Code.Conv_Ovf_U8:
                    case Code.Conv_Ovf_U8_Un:
                    case Code.Conv_Ovf_I:
                    case Code.Conv_Ovf_I_Un:
                    case Code.Conv_Ovf_U:
                    case Code.Conv_Ovf_U_Un:
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

                    case Code.Throw:
                    case Code.Rethrow:
                        {
                            var thrown = instruction.OpCode.Code == Code.Rethrow
                                ? caught
                                : Pop(stack);
                            var landed = TryDispatchToCatch(
                                method, indices, ip, thrown, out var handlerIndex);
                            State.RecordThrow(
                                (State.Heap.TryGetRuntimeTypeName(thrown, out var thrownType)
                                    ? thrownType
                                    : "an unmodeled object") +
                                $" from {method.Name} IL_{instruction.Offset:X4}" +
                                (landed ? " (caught here)" : " (left the method)") +
                                $" after [{Preceding(instructions, ip)}]");
                            // The first throw is the one worth the approach. Later ones are usually
                            // the program's own error handling reacting to it, and dumping each in
                            // turn would push the cause out of the ring before it could be read.
                            if (MachineTrace.Enabled && State.ThrowSites.Count == 1)
                                MachineTrace.DumpRecent($"{method.Name} threw");
                            if (landed)
                            {
                                stack.Clear();
                                stack.Add(thrown);
                                caught = thrown;
                                next = handlerIndex;
                                break;
                            }

                            return new FrameResult(
                                StaticExecutionStatus.Threw,
                                thrown,
                                $"{method.FullName} IL_{instruction.Offset:X4} threw.");
                        }

                    case Code.Newarr:
                        {
                            var length = Pop(stack);
                            if (!length.IsKnown)
                                return UnknownNumber(instruction, "array length");

                            var elementType = (instruction.Operand as ITypeDefOrRef)?.ToTypeSig();
                            if (!State.Heap.TryAllocateArray(elementType, length.AsInt32(), out var array))
                                return AllocationFailure(instruction, "array");
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
                            if (!indexValue.IsKnown)
                                return UnknownNumber(instruction, "array index");
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
                            var stored = Pop(stack);
                            if (!stored.IsKnown)
                                return UnknownNumber(instruction, "array index");
                            var index = stored.AsInt32();
                            var array = Pop(stack);
                            if (!State.Heap.TryWriteArray(
                                    array,
                                    index,
                                    value,
                                    StoredPrimitive(instruction.OpCode.Code),
                                    out var inBounds))
                            {
                                State.Heap.TryGetArrayElementType(array, out var elementType);
                                throw new InvalidOperationException(inBounds
                                    ? $"Array of {elementType} cannot hold what was stored in it."
                                    : "Array write is out of bounds.");
                            }
                            break;
                        }
                    case Code.Ldelema:
                        {
                            var addressed = Pop(stack);
                            if (!addressed.IsKnown)
                                return UnknownNumber(instruction, "array index");
                            var index = addressed.AsInt32();
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
                            var copied = Pop(stack);
                            if (!copied.IsKnown)
                                return UnknownNumber(instruction, "cpblk length");
                            var count = copied.AsInt32();
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
                            var filled = Pop(stack);
                            if (!filled.IsKnown)
                                return UnknownNumber(instruction, "initblk length");
                            var count = filled.AsInt32();
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
                            if (!TryReadModeledStatic(field, out var value))
                            {
                                value = State.ReadStaticField(field);
                                if (!value.IsKnown &&
                                    field.ResolveFieldDef() is { HasConstant: true } definition)
                                    value = ConstantValue(definition.Constant?.Value);
                            }

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
                            if (Castable(value, expected, instruction.Operand as ITypeDefOrRef))
                            {
                                stack.Add(value);
                                break;
                            }
                            if (instruction.OpCode.Code == Code.Isinst)
                            {
                                if (Declined(value, expected, instruction))
                                    throw new InvalidOperationException(
                                        $"Whether this is a {expected} cannot be read from the " +
                                        "metadata in hand, so the test was not answered.");
                                stack.Add(StaticValue.Null);
                                break;
                            }
                            throw new InvalidOperationException(
                                $"Modeled object cannot be cast to {expected}.");
                        }
                    case Code.Unbox_Any:
                        {
                            var boxed = Pop(stack);
                            if (State.Heap.TryUnbox(boxed, out var value))
                            {
                                stack.Add(value);
                                break;
                            }
                            // A cast to a generic parameter is written as unbox.any whatever the
                            // parameter turns out to be, and when it turns out to be a reference
                            // type the instruction is a cast and nothing is unboxed. What the
                            // parameter stands for is known here, so which of the two this is is
                            // known too.
                            var cast = Denoted(instruction.Operand, generics) as TypeSig ??
                                (instruction.Operand as ITypeDefOrRef)?.ToTypeSig();
                            if (cast is null || cast.IsValueType || cast.ContainsGenericParameter)
                            {
                                throw new InvalidOperationException(
                                    "unbox.any target is not a concrete box.");
                            }
                            if (boxed.Kind != StaticValueKind.Null &&
                                !Castable(boxed, cast.FullName, cast.ToTypeDefOrRef()))
                            {
                                throw new InvalidOperationException(
                                    $"Modeled object cannot be cast to {cast.FullName}.");
                            }
                            stack.Add(boxed);
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
                            var definition = target.ResolveMethodDef() ??
                                ResolveThroughInstantiation(target);
                            if ((instruction.OpCode.Code == Code.Callvirt ||
                                 definition is { HasBody: false }) &&
                                callArguments.Length > 0)
                            {
                                definition = ResolveVirtualTarget(
                                    target,
                                    callArguments[0],
                                    State.ModuleMetadata ?? method.Module) ?? definition;
                            }
                            FrameResult callResult;
                            if (isConstructor && IsDelegateConstructor(target))
                            {
                                BindDelegate(constructed, callArguments);
                                callResult = FrameResult.Success(default);
                            }
                            else if (TryInvokeDelegate(
                                target, callArguments, budget, depth, out var invoked))
                            {
                                callResult = invoked;
                            }
                            else if (definition is not null && definition.HasBody &&
                                BelongsToSubject(definition, method))
                            {
                                callResult = ExecuteFrame(
                                    definition,
                                    callArguments,
                                    budget,
                                    depth + 1,
                                    GenericScope.For(target, generics));
                            }
                            else if (definition is not null &&
                                BelongsToSubject(definition, method) &&
                                definition.IsStatic &&
                                definition.MethodSig?.Params.Count == 0 &&
                                definition.ReturnType.ToTypeDefOrRef()?.ResolveTypeDef() is
                                    { IsValueType: false } factoryType &&
                                Fabricated(factoryType.FullName, out var factoryResult))
                            {
                                callResult = FrameResult.Success(factoryResult);
                            }
                            else if (target.MethodSig is
                                     { Params.Count: 0 } factorySignature &&
                                ClassNamed(
                                    method.Module,
                                    factorySignature.RetType.FullName) is { } unresolvedFactoryType &&
                                Fabricated(
                                    unresolvedFactoryType.FullName,
                                    out var unresolvedFactoryResult))
                            {
                                callResult = FrameResult.Success(unresolvedFactoryResult);
                            }
                            else if (_intrinsics.TryResolve(target, out var intrinsic))
                            {
                                // A model that refuses knows what was asked but not where from, and
                                // where from is half of what makes the refusal worth reading.
                                State.Blockers.Site = (method, instruction);
                                var intrinsicResult = intrinsic.Invoke(
                                    Assisting(budget, depth), target, callArguments);
                                callResult = new FrameResult(
                                    intrinsicResult.Status,
                                    intrinsicResult.Value,
                                    intrinsicResult.Status == StaticExecutionStatus.Completed
                                        ? intrinsicResult.Diagnostic
                                        : $"{target.FullName}: {intrinsicResult.Diagnostic}");
                            }
                            // Last, after every way of actually following the call has been tried, so
                            // that a declaration can never stand in front of a model or a body.
                            else if (Declared(target, instruction, out var declaredResult))
                            {
                                callResult = declaredResult;
                            }
                            else
                            {
                                var receiver = callArguments.Length > 0 &&
                                    State.Heap.TryGetRuntimeTypeName(
                                        callArguments[0], out var receiverType)
                                        ? $", receiver={receiverType}"
                                        : string.Empty;

                                // A platform call is not an unlisted managed method that could be
                                // modeled by adding it: it leaves the runtime entirely, and saying
                                // so is the difference between a gap and a boundary.
                                if (definition?.ImplMap is { } native)
                                {
                                    var entry = $"{native.Module?.Name}!{native.Name}";
                                    var left = $"IL_{instruction.Offset:X4}: {target.FullName} " +
                                        $"calls {entry} outside the runtime.";
                                    if (!SteppedOver(
                                        target,
                                        instruction,
                                        BlockerKind.PlatformCall,
                                        entry,
                                        left,
                                        out var steppedNative))
                                    {
                                        Stopped(
                                            BlockerKind.PlatformCall,
                                            entry,
                                            left,
                                            Declaring.Call(target),
                                            instruction);
                                        return FrameResult.Fail(
                                            StaticExecutionStatus.Unsupported, left);
                                    }

                                    callResult = steppedNative;
                                }
                                else
                                {
                                    var unmodeled =
                                        $"IL_{instruction.Offset:X4}: external call " +
                                        $"{target.FullName} is not allowlisted{receiver}.";
                                    if (!SteppedOver(
                                        target,
                                        instruction,
                                        BlockerKind.UnmodeledCall,
                                        target.FullName,
                                        unmodeled,
                                        out var stepped))
                                    {
                                        Stopped(
                                            BlockerKind.UnmodeledCall,
                                            target.FullName,
                                            unmodeled,
                                            Declaring.Call(target),
                                            instruction);
                                        return FrameResult.Fail(
                                            StaticExecutionStatus.Unsupported, unmodeled);
                                    }

                                    callResult = stepped;
                                }
                            }

                            // A callee that threw is not a callee the machine failed on. If this
                            // frame guards the call site, the throw is delivered there and the
                            // program carries on exactly as it would have.
                            if (callResult.Status == StaticExecutionStatus.Threw)
                            {
                                if (TryDispatchToCatch(
                                        method, indices, ip, callResult.Value, out var caughtAt))
                                {
                                    stack.Clear();
                                    stack.Add(callResult.Value);
                                    caught = callResult.Value;
                                    next = caughtAt;
                                    break;
                                }

                                return callResult;
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
                            {
                                // An intrinsic that models a framework type builds its own instance
                                // with the state that makes it usable, and that is the object the
                                // program ends up holding. Keeping the placeholder instead would
                                // hand back something that answers no question about itself, which
                                // is how a modeled collection turns into an unmodeled one.
                                var produced =
                                    callResult.Value.Kind == StaticValueKind.HeapReference &&
                                    !callResult.Value.Equals(constructed)
                                        ? callResult.Value
                                        : constructed;
                                stack.Add(TrackOperation(
                                    method,
                                    instruction,
                                    produced,
                                    ProvenanceKind.Call,
                                    callArguments));
                            }
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
                        var unrun =
                            $"IL_{instruction.Offset:X4}: opcode {instruction.OpCode.Name} is " +
                            "unsupported.";
                        Stopped(
                            BlockerKind.UnsupportedInstruction,
                            instruction.OpCode.Name,
                            unrun,
                            instruction: instruction);
                        return FrameResult.Fail(StaticExecutionStatus.Unsupported, unrun);
                }
            }
            catch (Exception exception) when (
                exception is InvalidOperationException or
                ArgumentOutOfRangeException or
                IndexOutOfRangeException or
                OverflowException or
                DivideByZeroException)
            {
                // Named, because an offset alone belongs to whichever method the reader guesses,
                // and the guess is wrong whenever a fault happened one call below the one in hand.
                return FrameResult.Fail(
                    StaticExecutionStatus.InvalidProgram,
                    $"{method.FullName} IL_{instruction.Offset:X4} {instruction.OpCode.Name} " +
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

    /// <summary>
    /// The overflow-checking conversions, each paired with the plain conversion it narrows to and
    /// whether it reads its source as unsigned.
    /// </summary>
    private static readonly Dictionary<Code, (Code Target, bool FromUnsigned)> CheckedConversions =
        new()
        {
            [Code.Conv_Ovf_I1] = (Code.Conv_I1, false),
            [Code.Conv_Ovf_I1_Un] = (Code.Conv_I1, true),
            [Code.Conv_Ovf_U1] = (Code.Conv_U1, false),
            [Code.Conv_Ovf_U1_Un] = (Code.Conv_U1, true),
            [Code.Conv_Ovf_I2] = (Code.Conv_I2, false),
            [Code.Conv_Ovf_I2_Un] = (Code.Conv_I2, true),
            [Code.Conv_Ovf_U2] = (Code.Conv_U2, false),
            [Code.Conv_Ovf_U2_Un] = (Code.Conv_U2, true),
            [Code.Conv_Ovf_I4] = (Code.Conv_I4, false),
            [Code.Conv_Ovf_I4_Un] = (Code.Conv_I4, true),
            [Code.Conv_Ovf_U4] = (Code.Conv_U4, false),
            [Code.Conv_Ovf_U4_Un] = (Code.Conv_U4, true),
            [Code.Conv_Ovf_I8] = (Code.Conv_I8, false),
            [Code.Conv_Ovf_I8_Un] = (Code.Conv_I8, true),
            [Code.Conv_Ovf_U8] = (Code.Conv_U8, false),
            [Code.Conv_Ovf_U8_Un] = (Code.Conv_U8, true),
            [Code.Conv_Ovf_I] = (Code.Conv_I, false),
            [Code.Conv_Ovf_I_Un] = (Code.Conv_I, true),
            [Code.Conv_Ovf_U] = (Code.Conv_U, false),
            [Code.Conv_Ovf_U_Un] = (Code.Conv_U, true)
        };

    /// <summary>
    /// Converts a value the way an overflow-checking conversion would, refusing to fold one that
    /// would not have survived.
    /// </summary>
    /// <remarks>
    /// The whole point of these instructions is that an out-of-range value stops the program rather
    /// than quietly losing its high bits. Narrowing anyway would hand the rest of the run a number
    /// the program would never have seen, so the machine stops instead and says why.
    /// </remarks>
    private StaticValue ConvertChecked(Code code, Code target, bool fromUnsigned, StaticValue value)
    {
        if (!value.IsInteger)
            return ConvertValue(target, value);
        var signed = value.Kind == StaticValueKind.Int64 ? value.AsInt64() : value.AsInt32();
        var unsigned = value.Kind == StaticValueKind.Int64
            ? unchecked((ulong)value.AsInt64())
            : unchecked((uint)value.AsInt32());
        var narrow = State.PointerSize == 4;
        long low;
        ulong high;
        switch (target)
        {
            case Code.Conv_I1: low = sbyte.MinValue; high = (ulong)sbyte.MaxValue; break;
            case Code.Conv_U1: low = 0; high = byte.MaxValue; break;
            case Code.Conv_I2: low = short.MinValue; high = (ulong)short.MaxValue; break;
            case Code.Conv_U2: low = 0; high = ushort.MaxValue; break;
            case Code.Conv_I4: low = int.MinValue; high = int.MaxValue; break;
            case Code.Conv_U4: low = 0; high = uint.MaxValue; break;
            case Code.Conv_I8: low = long.MinValue; high = long.MaxValue; break;
            case Code.Conv_I: low = narrow ? int.MinValue : long.MinValue;
                high = narrow ? int.MaxValue : (ulong)long.MaxValue; break;
            case Code.Conv_U: low = 0; high = narrow ? uint.MaxValue : ulong.MaxValue; break;
            default: low = 0; high = ulong.MaxValue; break;
        }

        var fits = fromUnsigned
            ? unsigned <= high
            : signed >= low && (signed < 0 || (ulong)signed <= high);
        if (!fits)
            throw new InvalidOperationException($"{code} overflowed converting {signed}.");
        return ConvertInteger(target, value);
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
        if (CheckedConversions.TryGetValue(code, out var narrowing))
            return ConvertChecked(code, narrowing.Target, narrowing.FromUnsigned, value);
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

        // Comparing a reference as though it were an unsigned number is how every C# compiler
        // writes "is not null", and the only ordering it can mean is "the same or not". Reading it
        // as an inequality is what the runtime does with it, and the alternative is to stop on an
        // idiom that appears in ordinary code everywhere.
        if (code is Code.Cgt_Un or Code.Clt_Un && (Referential(left) || Referential(right)))
            return StaticValue.FromInt32(Equal(left, right) ? 0 : 1);
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

    /// <summary>Whether a value is a reference rather than a number.</summary>
    private static bool Referential(StaticValue value) =>
        value.Kind is StaticValueKind.Null or StaticValueKind.HeapReference or
            StaticValueKind.ManagedReference;

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

    /// <summary>
    /// The primitive a store instruction names, for an element type that names none this reader can
    /// resolve.
    /// </summary>
    /// <remarks>
    /// The unsigned spelling is used where the opcode does not distinguish, so that what is kept is
    /// the slot as it was written; the matching read normalizes it to whichever the reading side
    /// meant. <c>stelem</c> is absent because its operand is the element type, which is the thing
    /// already tried.
    /// </remarks>
    private static string? StoredPrimitive(Code code) => code switch
    {
        Code.Stelem_I1 => "System.Byte",
        Code.Stelem_I2 => "System.UInt16",
        Code.Stelem_I4 or Code.Stelem_I => "System.Int32",
        Code.Stelem_I8 => "System.Int64",
        Code.Stelem_R4 => "System.Single",
        Code.Stelem_R8 => "System.Double",
        _ => null
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

    /// <summary>
    /// The base types of the framework models the machine allocates.
    /// </summary>
    /// <remarks>
    /// A model is named by the concrete type it stands for, so a cast to one of that type's bases
    /// has to be allowed or perfectly ordinary code stops on a cast that would always have
    /// succeeded. Only the reflection types the machine actually mints are listed, because a
    /// relationship it has not modeled is one it should not be asserting.
    /// </remarks>
    private static readonly Dictionary<string, string[]> ModelBaseTypes = new(StringComparer.Ordinal)
    {
        ["System.Reflection.MethodInfo"] =
            ["System.Reflection.MethodBase", "System.Reflection.MemberInfo"],
        ["System.Reflection.ConstructorInfo"] =
            ["System.Reflection.MethodBase", "System.Reflection.MemberInfo"],
        ["System.Reflection.MethodBase"] = ["System.Reflection.MemberInfo"],
        ["System.Reflection.FieldInfo"] = ["System.Reflection.MemberInfo"],
        ["System.Type"] = ["System.Reflection.MemberInfo"]
    };

    private static bool InheritsModel(string? actual, string? expected) =>
        actual is not null && expected is not null &&
        ModelBaseTypes.TryGetValue(actual, out var bases) &&
        bases.Contains(expected, StringComparer.Ordinal);

    internal const string DelegateTargetKey = "DelegateTarget";
    internal const string DelegateMethodKey = "DelegateMethod";

    /// <summary>
    /// Whether a constructor is a delegate's, decided from its signature rather than its type.
    /// </summary>
    /// <remarks>
    /// A delegate constructor is the only one the runtime gives the signature
    /// <c>(object, native int)</c>, so the shape identifies it outright. Deciding it this way rather
    /// than by resolving the declaring type matters, because the delegate types that show up here
    /// are usually generic instantiations of framework types such as <c>Comparison&lt;T&gt;</c>,
    /// whose definitions live in an assembly the machine deliberately cannot see.
    /// </remarks>
    private static bool IsDelegateConstructor(IMethod target) =>
        target.Name == ".ctor" &&
        target.MethodSig is { Params.Count: 2 } signature &&
        signature.Params[0].ElementType == ElementType.Object &&
        signature.Params[1].ElementType is ElementType.I or ElementType.U or ElementType.Ptr;

    /// <summary>
    /// Remembers what a delegate was built over, so that calling it later can mean something.
    /// </summary>
    /// <remarks>
    /// The two operands of the construction are the receiver and the function pointer, and the
    /// pointer arrived from <c>ldftn</c> as a metadata handle that still names the method. Keeping
    /// both on the delegate is what turns an opaque object into a call the machine can make, which
    /// is the difference between interpreting a token-driven runtime and refusing it.
    /// </remarks>
    private void BindDelegate(StaticValue constructed, StaticValue[] callArguments)
    {
        if (callArguments.Length != 3)
            return;
        State.Heap.TrySetModelValue(constructed, DelegateTargetKey, callArguments[1]);
        if (State.Heap.TryGetMetadataHandle(callArguments[2], out var handle) &&
            handle is IMethod bound)
        {
            State.Heap.TrySetModelValue(constructed, DelegateMethodKey, bound);
        }
    }

    /// <summary>
    /// Calls a delegate that was built here, or reports that this was not one.
    /// </summary>
    /// <remarks>
    /// Only a delegate the machine watched being constructed can be invoked, because only then is
    /// the bound method known; anything else declines and takes the ordinary path. The receiver is
    /// prepended for an instance target and omitted for a static one, which is exactly the shape
    /// the callee's frame expects.
    /// </remarks>
    private bool TryInvokeDelegate(
        IMethod target,
        StaticValue[] callArguments,
        StaticWorkBudget budget,
        int depth,
        out FrameResult result)
    {
        result = default!;
        if (target.Name != "Invoke" || callArguments.Length == 0)
            return false;
        if (!State.Heap.TryGetModelValue<IMethod>(callArguments[0], DelegateMethodKey, out var bound) ||
            bound is null)
        {
            return false;
        }

        State.Heap.TryGetModelValue<StaticValue>(callArguments[0], DelegateTargetKey, out var receiver);
        var definition = bound.ResolveMethodDef();
        var unbound = definition?.IsStatic ?? bound.MethodSig?.HasThis != true;
        StaticValue[] arguments = unbound
            ? [.. callArguments[1..]]
            : [receiver, .. callArguments[1..]];
        if (definition is { HasBody: true })
        {
            result = ExecuteFrame(
                definition, arguments, budget, depth + 1, GenericScope.For(target, null));
            return true;
        }

        // The delegate stands for a method whose body is not here to run, which for an obfuscator
        // runtime usually means a framework method it chose to reach through a delegate rather than
        // a direct call. It is the same call either way, so it is dispatched the same way.
        if (!_intrinsics.TryResolve(bound, out var intrinsic))
            return false;
        var answered = intrinsic.Invoke(Assisting(budget, depth), bound, arguments);
        result = new FrameResult(
            answered.Status,
            answered.Value,
            answered.Status == StaticExecutionStatus.Completed
                ? answered.Diagnostic
                : $"{bound.FullName}: {answered.Diagnostic}");
        return true;
    }

    /// <summary>
    /// Whether an array can be viewed as the type a cast is asking for.
    /// </summary>
    /// <remarks>
    /// Arrays have no declaration to walk, so the hierarchy check has nothing to work with. What the
    /// runtime promises about them is fixed and short: every array is an <c>Array</c>, meets the
    /// untyped list and sequence contracts, and may be seen through an array of any base of the type
    /// it holds.
    /// </remarks>
    private bool ArraySatisfies(string actual, string? expected)
    {
        const string suffix = "[]";
        if (expected is null || !actual.EndsWith(suffix, StringComparison.Ordinal))
            return false;
        if (expected is "System.Array" or "System.ICloneable" or
            "System.Collections.IList" or "System.Collections.ICollection" or
            "System.Collections.IEnumerable" or "System.Collections.IStructuralComparable" or
            "System.Collections.IStructuralEquatable")
        {
            return true;
        }

        if (!expected.EndsWith(suffix, StringComparison.Ordinal))
            return false;
        var wanted = expected[..^suffix.Length];
        return wanted == "System.Object" || DerivesFrom(actual[..^suffix.Length], wanted);
    }

    /// <summary>
    /// Stands something in for the result of a parameterless call whose body could not be followed.
    /// </summary>
    /// <remarks>
    /// A fresh object is the right stand-in for most types, because nothing is known about the one the
    /// call would have returned. The assembly is the exception: only one is visible to an
    /// interpretation, so a second model of it is not an unknown assembly but the same assembly wearing
    /// a disguise, and everything that asks a reflection handle whether it addresses this metadata gets
    /// told no. Reactor asks exactly that, about its own entry point, from inside its virtual machine.
    /// </remarks>
    private bool Fabricated(string typeName, out StaticValue value)
    {
        if (typeName != "System.Reflection.Assembly")
            return State.Heap.TryAllocateObject(typeName, out value);
        if (!State.TryGetOrAllocateRuntimeSingleton(typeName, out value))
            return false;
        State.Heap.TrySetModelValue(value, LoaderFrameworkIntrinsic.HomeModuleMark, true);
        return true;
    }

    /// <summary>
    /// Finds the method behind a call whose declaring type is written as a generic instantiation.
    /// </summary>
    /// <remarks>
    /// A member of a generic type is referred to through a TypeSpec, and resolving one of those is not
    /// the same lookup as resolving a reference to a member of an ordinary type. The second is
    /// answered for us and the first is not always, so a construct with nothing obfuscated about it —
    /// a generic closure class caching its only instance in a static field, which is what a compiler
    /// emits for a lambda that captures nothing — reads as a call leaving the assembly, and the
    /// interpretation stops on a method whose body is sitting in the same module. The instantiation
    /// names the type, so the method is a name and signature lookup away.
    /// </remarks>
    private static MethodDef? ResolveThroughInstantiation(IMethod target)
    {
        var reference = target as MemberRef ?? (target as MethodSpec)?.Method as MemberRef;
        if (reference?.MethodSig is null)
            return null;
        return reference.DeclaringType?.ScopeType?.ResolveTypeDef() is { } declaring
            ? declaring.FindMethod(reference.Name, reference.MethodSig)
            : null;
    }

    /// <summary>
    /// Whether a callee's body is part of the code this machine was set running on.
    /// </summary>
    /// <remarks>
    /// Normally that is just "the same module as the caller". The exception is a body the machine
    /// assembled itself from instructions a program emitted: it lives in a scratch module of its
    /// own, but the methods it calls are the subject's, and asking about the caller would refuse
    /// to run them.
    /// </remarks>
    private bool BelongsToSubject(MethodDef definition, MethodDef caller) =>
        definition.Module == caller.Module ||
        definition.Module == State.ModuleMetadata ||
        State.IsTrusted(definition.Module);

    /// <summary>
    /// Supplies a framework constant that the machine models rather than stores.
    /// </summary>
    /// <remarks>
    /// Most static fields hold whatever the program last wrote there, but a few are the framework's
    /// own and hold a value the program never assigns. An opcode is the case that matters here: a
    /// program building a method reads them by name and hands them straight back, so the machine
    /// only needs to remember which one it was told about.
    /// </remarks>
    /// <summary>
    /// What a metadata operand denotes in the frame that loaded it.
    /// </summary>
    /// <remarks>
    /// <c>typeof(T)</c> compiles to a token for the parameter rather than for a type, and what it
    /// means depends on who called. Resolving it here means everything downstream — the reflection
    /// models, the type questions, the enum handling — sees the type the program is actually working
    /// with and needs to know nothing about generics.
    /// </remarks>
    /// <summary>
    /// Discloses a type test the machine answered no to without being able to settle it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>isinst</c> answering null is a legitimate answer and also the machine's most dangerous one.
    /// The program takes it as a fact about its own object and acts on it, so where the machine said no
    /// only because it could not tell, the run continues down a path the program would never have
    /// taken and fails somewhere else entirely — most often at the first field read of the null.
    /// Nothing about that later failure points back here, which is what makes this worth a line in the
    /// ledger rather than a silent answer.
    /// </para>
    /// <para>
    /// Only the unsettled ones. A test whose answer the hierarchy gives is the program's own logic —
    /// an engine asking an object which of its dozen instruction kinds it is will be told no eleven
    /// times, and reporting those would bury the one that matters in the eleven that do not.
    /// </para>
    /// </remarks>
    /// <returns>Whether a run being asked to prove itself should refuse rather than answer no.</returns>
    private bool Declined(StaticValue value, string? expected, Instruction instruction)
    {
        var named = State.Heap.TryGetRuntimeTypeName(value, out var actual) && actual is not null;
        if (named && Settles(actual, expected))
            return false;
        var key = $"isinst:{(named ? actual : "unrecorded")}->{expected ?? "?"}";
        var detail = named
            ? $"Whether a {actual} is a {expected} could not be read from the metadata in hand."
            : $"Something the machine never recorded a type for was asked whether it is a {expected}.";
        State.Blockers.Site = (_frames.Count != 0 ? _frames[^1] : null, instruction);
        if (State.Strict)
        {
            State.Blockers.Record(BlockerKind.UnknownValue, key, detail);
            return true;
        }

        State.Blockers.Continued(
            BlockerKind.UnknownValue, key, $"{detail} The test answered no.");
        return false;
    }

    /// <summary>Whether the hierarchy in hand can answer the question at all.</summary>
    /// <remarks>
    /// Asked of whatever is in hand rather than only of a machine that was told which module it is
    /// reading. Most questions of this kind are between two of the framework's own types — an
    /// enumerator at the end of a <c>foreach</c> being asked whether it wants disposing is the
    /// commonest by far — and the framework answers those whether a subject module was named or
    /// not. Requiring one turned every such test into an unsettled one, which a run asked to prove
    /// itself then stopped on, in the epilogue of an ordinary loop.
    /// </remarks>
    private bool Settles(string? actual, string? expected) =>
        Ancestry.Reaches(
            State.ModuleMetadata is { } metadata ? Searchable(metadata) : State.TrustedModules,
            State.ModuleMetadata,
            actual,
            expected) is not null;

    /// <summary>Whether what is on the stack can stand as an instance of the named type.</summary>
    private bool Castable(StaticValue value, string? expected, ITypeDefOrRef? named) =>
        expected == "System.Object" ||
        State.Heap.TryGetRuntimeTypeName(value, out var actual) &&
        (string.Equals(actual, expected, StringComparison.Ordinal) ||
            InheritsModel(actual, expected) ||
            DerivesFrom(actual, expected) ||
            ArraySatisfies(actual, expected) ||
            actual == "System.Delegate" &&
            named?.ResolveTypeDef()?.BaseType?.FullName is
                "System.MulticastDelegate" or "System.Delegate");

    private static object Denoted(object operand, GenericScope? generics)
    {
        if (generics is null || operand is not ITypeDefOrRef named)
            return operand;
        var signature = named.ToTypeSig();
        return signature?.ContainsGenericParameter == true &&
            generics.Bind(signature) is { } bound &&
            !bound.ContainsGenericParameter
                ? bound
                : operand;
    }

    /// <summary>
    /// Reads a static field of a type the machine models rather than interprets.
    /// </summary>
    /// <remarks>
    /// Some of the framework's best-known values are fields and not properties, and a field read has
    /// no call for an intrinsic to answer. Left alone they read as the zero this machine gives an
    /// external static it has never seen written, which is null for a reference — so a program that
    /// opens a registry hive gets nothing back and fails at its next step, several frames from the
    /// field that was actually the problem. Each one here is a value the framework fixes, so naming
    /// it is reading it rather than assuming it.
    /// </remarks>
    private bool TryReadModeledStatic(IField field, out StaticValue value)
    {
        value = StaticValue.Unknown;
        var declaring = field.DeclaringType?.FullName;
        var name = field.Name.String;
        if (declaring == "System.Reflection.Emit.OpCodes")
        {
            if (!ReflectionEmitIntrinsic.Opcodes.ContainsKey(name) ||
                !State.Heap.TryAllocateObject("System.Reflection.Emit.OpCode", out value))
                return false;
            State.Heap.TrySetModelValue(value, "OpCode", name);
            return true;
        }

        if (declaring == "Microsoft.Win32.Registry")
            return RegistryIntrinsic.TryOpenHive(State.Heap, name, out value);
        return declaring == "System.String" && name == "Empty" &&
            State.Heap.TryAllocateString(string.Empty, out value);
    }

    /// <summary>
    /// The context a modeled API needs to call back into the machine while it runs.
    /// </summary>
    private IntrinsicContext Assisting(StaticWorkBudget budget, int depth) =>
        new(
            State,
            (callee, arguments) => CallDelegate(callee, arguments, budget, depth),
            (callee, arguments) => Reenter(callee, arguments, budget, depth),
            _frames);

    /// <summary>
    /// Runs a delegate on behalf of a modeled API that was handed one.
    /// </summary>
    private IntrinsicResult CallDelegate(
        StaticValue callee,
        IReadOnlyList<StaticValue> arguments,
        StaticWorkBudget budget,
        int depth)
    {
        if (!State.Heap.TryGetModelValue<IMethod>(callee, DelegateMethodKey, out var bound) ||
            bound?.ResolveMethodDef() is not { HasBody: true } definition)
        {
            return IntrinsicResult.Invalid("The callback is not a delegate this machine built.");
        }

        State.Heap.TryGetModelValue<StaticValue>(callee, DelegateTargetKey, out var receiver);
        StaticValue[] callArguments = definition.IsStatic
            ? [.. arguments]
            : [receiver, .. arguments];
        var result = ExecuteFrame(
            definition, callArguments, budget, depth + 1, GenericScope.For(bound, null));
        return new IntrinsicResult(result.Status, result.Value, result.Diagnostic);
    }

    /// <summary>
    /// Runs a method for a modeled reflection call, on the caller's budget.
    /// </summary>
    /// <remarks>
    /// Reflection reaches framework methods as readily as the file's own, so a call arriving here
    /// with no body to run is not a failure — it is a call the machine already knows how to answer
    /// by other means, and it is answered the same way a direct call to it would be.
    ///
    /// A method named here can also be one no instance ever runs: an abstract or overridden one,
    /// where what runs is decided by the object it is called on. Reflection and the protector's own
    /// delegates both name methods that way, and both mean the same thing a <c>callvirt</c> means,
    /// so the object is asked before the name is given up on.
    /// </remarks>
    private IntrinsicResult Reenter(
        IMethod method,
        IReadOnlyList<StaticValue> arguments,
        StaticWorkBudget budget,
        int depth)
    {
        if (method.ResolveMethodDef() is { HasBody: true } definition)
        {
            var result = ExecuteFrame(
                definition, [.. arguments], budget, depth + 1, GenericScope.For(method, null));
            return new IntrinsicResult(result.Status, result.Value, result.Diagnostic);
        }

        if (method.ResolveMethodDef() is { IsVirtual: true } declared &&
            !declared.IsStatic &&
            arguments.Count > 0 &&
            method.DeclaringType?.Module is { } module &&
            ResolveVirtualTarget(method, arguments[0], module) is { } dispatched)
        {
            var result = ExecuteFrame(
                dispatched, [.. arguments], budget, depth + 1, GenericScope.For(method, null));
            return new IntrinsicResult(result.Status, result.Value, result.Diagnostic);
        }

        return _intrinsics.TryResolve(method, out var intrinsic)
            ? intrinsic.Invoke(Assisting(budget, depth), method, [.. arguments])
            : IntrinsicResult.Invalid($"{method.FullName} has no body to run.");
    }

    /// <summary>
    /// The metadata a type or an override may be looked up in.
    /// </summary>
    /// <remarks>
    /// A machine allowed to run a library's IL has to be able to dispatch inside it, because the
    /// first thing a library of any size does is call one of its own abstract methods. Searching
    /// only the sample would resolve that to nothing and stop the interpretation one call into code
    /// that was supplied precisely so it could be followed.
    /// </remarks>
    private IEnumerable<ModuleDef> Searchable(ModuleDef first)
    {
        yield return first;
        foreach (var trusted in State.TrustedModules)
        {
            if (trusted != first)
                yield return trusted;
        }
    }

    private MethodDef? ResolveVirtualTarget(
        IMethod target,
        StaticValue instance,
        ModuleDef module)
    {
        var expected = target.ResolveMethodDef();
        var comparer = new SigComparer();
        if (State.Heap.TryGetRuntimeTypeName(instance, out var runtimeTypeName) &&
            TypeNamed(module, runtimeTypeName) is { } runtimeType)
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
        // Nothing overrides a target that did not resolve, so there is nothing for the search below
        // to find. It used to be asked anyway, and answering it costs a pass over every method in
        // every searchable module.
        return expected is null ? null : SoleImplementationOf(expected, module);
    }

    /// <summary>The one method overriding this one, where the searchable modules hold exactly one.</summary>
    /// <remarks>
    /// Only the target is asked about, so the answer holds for every call site that shares one, and a
    /// dispatcher calls the same handful of targets over and over.
    /// </remarks>
    private MethodDef? SoleImplementationOf(MethodDef expected, ModuleDef module)
    {
        if (_soleImplementations.TryGetValue(expected, out var known))
            return known;
        var overriding = Searchable(module)
            .SelectMany(searched => searched.GetTypes())
            .SelectMany(type => type.Methods)
            .Where(candidate =>
                candidate.HasBody && !candidate.IsAbstract &&
                candidate.Overrides.Any(implementation =>
                    implementation.MethodDeclaration.ResolveMethodDef() == expected))
            .Take(2)
            .ToArray();
        return _soleImplementations[expected] =
            overriding.Length == 1 ? overriding[0] : null;
    }

    /// <summary>The type of this name in the searchable modules, the first one where names repeat.</summary>
    private TypeDef? TypeNamed(ModuleDef module, string name) =>
        Index(_typesByName, module, Searchable(module), static _ => true)
            .GetValueOrDefault(name);

    /// <summary>
    /// The type of this name that an object could be made of, so not a value type. The sample's own
    /// module only, since a factory returning a type from somebody else's is not what this reads.
    /// </summary>
    private TypeDef? ClassNamed(ModuleDef module, string name) =>
        Index(_classesByName, module, [module], static type => !type.IsValueType)
            .GetValueOrDefault(name);

    private static Dictionary<string, TypeDef> Index(
        Dictionary<ModuleDef, Dictionary<string, TypeDef>> cache,
        ModuleDef module,
        IEnumerable<ModuleDef> searched,
        Func<TypeDef, bool> wanted)
    {
        if (cache.TryGetValue(module, out var known))
            return known;
        var index = new Dictionary<string, TypeDef>(StringComparer.Ordinal);
        foreach (var type in searched.SelectMany(searchedModule => searchedModule.GetTypes()))
        {
            // First one wins, which is what searching in order and taking the first found did.
            if (wanted(type))
                index.TryAdd(type.FullName, type);
        }
        return cache[module] = index;
    }

    /// <summary>The type's static constructor, which dnlib finds by walking its methods.</summary>
    /// <remarks>
    /// Asked before every call and every field access that could trigger initialization, and the same
    /// few types are asked about throughout.
    /// </remarks>
    private MethodDef? StaticConstructorOf(TypeDef type)
    {
        if (_staticConstructors.TryGetValue(type, out var known))
            return known;
        return _staticConstructors[type] = type.FindStaticConstructor();
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

    /// <summary>
    /// Finds the catch handler that would receive a throw at this point, if any.
    /// </summary>
    /// <remarks>
    /// The innermost enclosing try wins, matching the runtime's own search order, and a handler is
    /// only accepted when the thrown object can be shown to be of its caught type. Where the
    /// object's type is not known the handler is accepted only if it catches everything, since
    /// guessing that a specific catch applies would resume the program on a path it might never
    /// have taken.
    /// </remarks>
    private bool TryDispatchToCatch(
        MethodDef method,
        Dictionary<Instruction, int> indices,
        int ip,
        StaticValue thrown,
        out int handlerIndex)
    {
        handlerIndex = -1;
        var best = default(ExceptionHandler);
        var bestStart = -1;
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            if (handler.HandlerType != ExceptionHandlerType.Catch ||
                handler.TryStart is null || handler.HandlerStart is null ||
                !indices.TryGetValue(handler.TryStart, out var start))
            {
                continue;
            }

            var end = handler.TryEnd is not null && indices.TryGetValue(handler.TryEnd, out var stop)
                ? stop
                : indices.Count;
            if (ip < start || ip >= end || start <= bestStart || !Catches(handler, thrown))
                continue;
            best = handler;
            bestStart = start;
        }

        if (best?.HandlerStart is null)
            return false;
        handlerIndex = indices[best.HandlerStart];
        return true;
    }

    /// <summary>
    /// Whether a handler catches what was thrown.
    /// </summary>
    /// <remarks>
    /// A handler catches a type and everything derived from it, so the question is asked of the
    /// thrown object's ancestry rather than the handler's. Where the thrown type is not known, only
    /// a catch-all is accepted, since resuming in a handler that would not really have run puts the
    /// program on a path it never took.
    /// </remarks>
    private bool Catches(ExceptionHandler handler, StaticValue thrown)
    {
        var caught = handler.CatchType?.FullName;
        if (caught is null or "System.Object" or "System.Exception")
            return true;
        if (!State.Heap.TryGetRuntimeTypeName(thrown, out var actual) || actual is null)
            return false;
        return string.Equals(actual, caught, StringComparison.Ordinal) ||
            DerivesFrom(actual, caught);
    }

    private readonly Dictionary<(string, string), bool> _ancestry = [];

    /// <summary>
    /// Whether one type in the module under interpretation is the other, or is one of its kinds.
    /// </summary>
    /// <remarks>
    /// The machine records what an object is by name, so answering this means going back to the
    /// metadata and walking. Interfaces are walked alongside base classes because a cast to an
    /// interface is a cast, and stopping at the base chain would quietly turn one into a null.
    ///
    /// Getting this wrong is not a small matter of precision. Obfuscated code casts to base types
    /// constantly — every value passed as its abstract kind and taken back out again — and a
    /// machine that answers no to a cast that would have succeeded does not fail where it went
    /// wrong. It hands back a null that travels until the program itself objects to it, which is
    /// how a fidelity gap ends up looking like the protected program rejecting its own state.
    /// </remarks>
    private bool DerivesFrom(string? actual, string? expected)
    {
        if (actual is null || expected is null || State.ModuleMetadata is not { } metadata)
            return false;
        if (_ancestry.TryGetValue((actual, expected), out var known))
            return known;
        // A hierarchy that cannot be read far enough to tell is treated here as no, which is what
        // the machine did before there was anything else to say. The reflective form of the same
        // question refuses instead, because a program that asked it is deciding something with the
        // answer rather than moving a value from one shape to another.
        return _ancestry[(actual, expected)] =
            Ancestry.Reaches(Searchable(metadata), metadata, actual, expected) == true;
    }

    /// <summary>
    /// Renders a value the way a reader of the trace needs to see it: what it is, not where it is.
    /// </summary>
    private string Describe(StaticValue value)
    {
        if (value.Kind != StaticValueKind.HeapReference)
        {
            return value.Kind switch
            {
                StaticValueKind.Null => "null",
                StaticValueKind.Int32 when value.IsKnown => $"i4:{value.AsInt32()}",
                StaticValueKind.Int64 when value.IsKnown => $"i8:{value.AsInt64()}",
                _ => $"{value.Kind}"
            };
        }

        if (State.Heap.TryGetString(value, out var text))
            return $"\"{(text.Length > 32 ? text[..32] + "..." : text)}\"";
        if (!State.Heap.TryGetRuntimeTypeName(value, out var runtimeType))
            return "object";
        if (runtimeType.EndsWith("[]", StringComparison.Ordinal) &&
            State.Heap.TryGetLength(value, out var length))
            return $"{runtimeType}({length})";

        // A modeled Type is the one object whose identity, rather than its class, is the thing a
        // reader is asking about, since the code around it is deciding what kind of value it holds.
        // A reflection model is described by what it denotes, since the code around it is deciding
        // which member or type it has, not what class the model belongs to.
        if (State.Heap.TryGetModelValue(value, "TypeName", out string? named) && named is not null)
            return $"{runtimeType}({named})";
        return State.Heap.TryGetModelValue(value, "Metadata", out object? metadata) &&
            metadata is IFullName denoted
                ? $"{runtimeType}({denoted.FullName})"
                : runtimeType;
    }

    /// <summary>
    /// Renders an operand short enough to keep one traced step on one line.
    /// </summary>
    private static string Abbreviate(object operand)
    {
        const int enoughToIdentify = 72;
        var text = operand switch
        {
            Instruction target => $"-> {target.OpCode.Name}",
            Instruction[] targets => $"switch({targets.Length})",
            _ => operand.ToString() ?? string.Empty
        };
        return text.Length <= enoughToIdentify ? text : text[..enoughToIdentify] + "...";
    }

    /// <summary>
    /// The handful of instructions leading to a point, for describing it without using offsets.
    /// </summary>
    /// <remarks>
    /// An instruction's recorded offset goes stale as soon as a pass rewrites the body around it,
    /// so quoting one sends a reader to the wrong place in the file they are looking at. The
    /// instructions themselves do not drift.
    ///
    /// The operands are abbreviated for the same reason the traced steps are: a dispatcher switch
    /// carries a couple of hundred targets, and printing them spells out in thousands of characters
    /// what the number of them says. Anyone who needs the targets is reading the body, not this.
    /// </remarks>
    private static string Preceding(IList<Instruction> instructions, int ip)
    {
        const int worthShowing = 6;
        var from = Math.Max(0, ip - worthShowing);
        return string.Join("; ", Enumerable.Range(from, ip - from)
            .Select(index => instructions[index].OpCode.Name +
                (instructions[index].Operand is { } operand
                    ? $" {Abbreviate(operand)}"
                    : string.Empty)));
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

    private FrameResult AllocationFailure(Instruction instruction, string kind)
    {
        var detail = $"IL_{instruction.Offset:X4}: {kind} exceeded allocation limits.";
        Stopped(
            BlockerKind.Budget,
            "allocatedBytes",
            detail,
            Declaring.Budget("allocatedBytes", _limits.MaximumAllocatedBytes),
            instruction);
        return FrameResult.Fail(StaticExecutionStatus.AllocationLimitExceeded, detail);
    }

    /// <summary>
    /// What a call was declared to do, where the run was allowed to be told and the call is one the
    /// machine was about to refuse.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Consulted after every way of actually following the call — a body in the module, a trusted
    /// library, a model, a constructor of a type that is being modeled — so a declaration can only
    /// ever answer a call that would otherwise have stopped the run. That ordering is the whole of the
    /// safety here: nothing the tool knows how to do is displaced by somebody's assertion about it.
    /// </para>
    /// <para>
    /// Every use is recorded as an observation, and a call declared to do nothing is also recorded as
    /// a registration, so that the pass which removes loader frames it can prove do nothing cannot
    /// reach that conclusion on the strength of a declaration that they do nothing.
    /// </para>
    /// </remarks>
    private bool Declared(IMethod target, Instruction instruction, out FrameResult result)
    {
        result = default;
        if (!State.Declarations.TryAnswerCall(target.FullName, out var declared))
            return false;
        var returns = target.MethodSig?.RetType;
        var nothing = returns is null || returns.ElementType == ElementType.Void;
        State.Observe(LoaderObservationKind.DeclaredCall, $"{target.FullName} {declared.Describe()}");
        if (declared.Inert)
        {
            State.RecordRegistration($"declared call {target.FullName}");
            if (!nothing)
            {
                var silent = $"IL_{instruction.Offset:X4}: {target.FullName} was declared inert, " +
                    "but it returns a value and nothing says what the value is.";
                Stopped(
                    BlockerKind.UnmodeledCall,
                    target.FullName,
                    silent,
                    Declaring.Call(target),
                    instruction);
                result = FrameResult.Fail(StaticExecutionStatus.Unsupported, silent);
                return true;
            }

            result = FrameResult.Success(default);
            return true;
        }

        if (nothing)
        {
            result = FrameResult.Success(default);
            return true;
        }

        if (!TryStated(declared.Returns, returns!, out var value))
        {
            var unusable = $"IL_{instruction.Offset:X4}: what {target.FullName} was declared to " +
                $"return cannot stand in for a {returns!.FullName}.";
            Stopped(
                BlockerKind.UnmodeledCall,
                target.FullName,
                unusable,
                Declaring.Call(target),
                instruction);
            result = FrameResult.Fail(StaticExecutionStatus.Unsupported, unusable);
            return true;
        }

        result = FrameResult.Success(State.Provenance.Origin(
            value,
            ProvenanceKind.Declared,
            $"{(_frames.Count != 0 ? _frames[^1].MDToken.ToString() : "?")}/" +
            $"IL_{instruction.Offset:X4}",
            target.FullName));
        return true;
    }

    /// <summary>
    /// Steps over a call the machine cannot follow, where the run is not being asked to prove itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Consulted after a declaration, so somebody who has said what a call does still gets what they
    /// said rather than an unknown. What this does instead is the weakest thing that lets the frame
    /// continue: a call that hands nothing back is stepped over, and one that returns something returns
    /// a value that is explicitly not known. Nothing is invented — an unknown is carried exactly as an
    /// unknown from anywhere else is, and it still cannot become a branch, an index or a length.
    /// </para>
    /// <para>
    /// This is what makes an unfamiliar sample yield something. Most of what protected code asks about
    /// its surroundings never reaches the part worth reading: a thread is constructed, a window handle
    /// is fetched, a counter is incremented, and the payload comes out of the same method regardless.
    /// Stopping at the first of those loses everything behind it, which is a high price for a call the
    /// result of which nothing used.
    /// </para>
    /// <para>
    /// The frame is still recorded as having handed something to the runtime, because a call nobody
    /// followed might have done anything, and the pass which removes loader frames it can prove do
    /// nothing must not conclude that from a call the tool declined to read.
    /// </para>
    /// </remarks>
    private bool SteppedOver(
        IMethod target,
        Instruction instruction,
        BlockerKind kind,
        string key,
        string detail,
        out FrameResult result)
    {
        result = default;
        if (State.Strict)
            return false;
        var returns = Returning(target);
        State.Blockers.Site = (_frames.Count != 0 ? _frames[^1] : null, instruction);
        State.Blockers.Continued(
            kind,
            key,
            detail,
            Declaring.Call(target));
        State.Observe(
            LoaderObservationKind.SteppedCall,
            $"{target.FullName} {(returns ? "returned something unknown" : "was not followed")}");
        State.RecordRegistration($"stepped over {target.FullName}");
        result = FrameResult.Success(returns
            ? State.Provenance.Origin(
                StaticValue.Unknown,
                ProvenanceKind.Call,
                $"{(_frames.Count != 0 ? _frames[^1].MDToken.ToString() : "?")}/" +
                $"IL_{instruction.Offset:X4}",
                $"{target.FullName} was not followed")
            : default);
        return true;
    }

    /// <summary>Turns what was stated about a call's result into the value it stands for.</summary>
    private bool TryStated(HostAnswer stated, TypeSig returns, out StaticValue value)
    {
        value = StaticValue.Null;
        switch (stated.Kind)
        {
            case HostAnswerKind.Absent:
                if (returns.IsValueType)
                    value = Wide(returns) ? StaticValue.FromInt64(0) : StaticValue.FromInt32(0);
                return true;
            case HostAnswerKind.Text:
                return State.Heap.TryAllocateString(stated.Text, out value);
            case HostAnswerKind.Bytes:
                return State.Heap.TryAllocateByteArray(stated.Data, out value);
            case HostAnswerKind.Boolean:
            case HostAnswerKind.Number:
                // A declared number can stand for anything an integer stands for, which is every
                // integral type, a character, a truth value and an enumeration. What it cannot stand
                // for is a fraction, because nothing here computes in fractions.
                if (returns.ElementType is ElementType.R4 or ElementType.R8)
                    return false;
                value = Wide(returns)
                    ? StaticValue.FromInt64(stated.Number)
                    : StaticValue.FromInt32((int)stated.Number);
                return true;
            default:
                return false;
        }
    }

    /// <summary>Whether a call hands anything back, which decides how it can be declared.</summary>
    private static bool Returning(IMethod target) =>
        target.MethodSig?.RetType is { } returns && returns.ElementType != ElementType.Void;

    private static bool Wide(TypeSig returns) =>
        returns.ElementType is ElementType.I8 or ElementType.U8 or ElementType.I or ElementType.U;

    /// <summary>
    /// Writes down what stopped the interpretation here, alongside the diagnostic it returns.
    /// </summary>
    /// <remarks>
    /// The diagnostic is for reading and this is for acting on, and they are recorded together
    /// because the only place both the reason and the location are known is the place the refusal is
    /// raised. Anything reconstructed later from the text would be a guess at what the text meant.
    /// </remarks>
    private void Stopped(
        BlockerKind kind,
        string key,
        string detail,
        Remedy? declare = null,
        Instruction? instruction = null)
    {
        var method = _frames.Count != 0 ? _frames[^1].FullName : null;
        State.Blockers.Record(
            kind,
            key,
            detail,
            declare,
            instruction is null
                ? method
                : $"{method} IL_{instruction.Offset:X4}");
    }

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

    /// <summary>
    /// A branch the machine cannot take, because what it turns on was never determined.
    /// </summary>
    /// <remarks>
    /// Nothing can be declared to fix this one. A value is unknown because something earlier declined
    /// to produce it, so the thing to act on is that earlier refusal, and the ledger says so rather
    /// than offering a remedy that would not work.
    /// </remarks>
    private FrameResult UnknownBranch(Instruction instruction)
    {
        var detail = $"IL_{instruction.Offset:X4}: branch condition is unknown.";
        Stopped(
            BlockerKind.UnknownValue,
            Unfollowable(instruction),
            detail + Earlier,
            instruction: instruction);
        return FrameResult.Fail(StaticExecutionStatus.Unknown, detail);
    }

    /// <summary>
    /// What every unknown value has in common, said once so that every entry of the kind carries it.
    /// </summary>
    private const string Earlier =
        " A value is unknown because something earlier declined to produce one, so the refusal to " +
        "act on is that one rather than this.";

    /// <summary>
    /// Refuses where an unknown would have to become a number for the machine to go on.
    /// </summary>
    /// <remarks>
    /// An index, a length or a count is the one place an unknown cannot be carried: every other use
    /// can hold it and hand it on, but there is no such thing as reading the unknownth element of an
    /// array. This is deliberately the same stop as a branch on an unknown, for the same reason — the
    /// value would have to be invented, and inventing it is how a reading of a path the program never
    /// takes comes out looking like a reading of the program.
    ///
    /// Before unfollowable calls were stepped over, these were nearly unreachable and the coercion was
    /// left to throw, which reported an honest unknown as a fault in the interpreted program.
    /// </remarks>
    private FrameResult UnknownNumber(Instruction instruction, string what)
    {
        var detail = $"IL_{instruction.Offset:X4}: {what} is unknown.";
        Stopped(
            BlockerKind.UnknownValue,
            Unfollowable(instruction),
            detail + Earlier,
            instruction: instruction);
        return FrameResult.Fail(StaticExecutionStatus.Unknown, detail);
    }

    private string Unfollowable(Instruction instruction) =>
        $"{(_frames.Count != 0 ? _frames[^1].FullName : "?")} IL_{instruction.Offset:X4}";

    private StaticValue TrackOrigin(
        MethodDef method,
        Instruction instruction,
        StaticValue value,
        string detail) =>
        State.Provenance.Origin(
            value,
            ProvenanceKind.Literal,
            Located(method, instruction),
            detail);

    private StaticValue TrackOperation(
        MethodDef method,
        Instruction instruction,
        StaticValue value,
        ProvenanceKind kind,
        params ReadOnlySpan<StaticValue> inputs) =>
        State.Provenance.Operation(
            value,
            kind,
            Located(method, instruction),
            instruction.OpCode.Name,
            inputs);

    /// <summary>Where an instruction is, spelled the way provenance records it.</summary>
    /// <remarks>
    /// One instruction is at one place, so this is the same text every time that instruction runs, and
    /// a loop runs one instruction a great many times. Composing it per execution meant formatting two
    /// numbers and allocating a string on every step of the machine; here it is composed once. An
    /// <see cref="Instruction"/> belongs to the one method body, so it identifies the place on its own.
    /// </remarks>
    private string Located(MethodDef method, Instruction instruction)
    {
        if (_locations.TryGetValue(instruction, out var known))
            return known;
        return _locations[instruction] = $"{method.MDToken}/IL_{instruction.Offset:X4}";
    }

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
        var initializer = type is null ? null : StaticConstructorOf(type);
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
