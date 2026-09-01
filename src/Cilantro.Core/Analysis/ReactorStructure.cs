using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

[Flags]
public enum ReactorCapability
{
    None = 0,
    DelegateProxy = 1 << 0,
    InvalidCallJunk = 1 << 1,
    DispatcherControlFlow = 1 << 2,
    ProtectedStrings = 1 << 3,
    ResourceContainer = 1 << 4,
    MethodStubs = 1 << 5,
    JitHook = 1 << 6,
    AntiTamper = 1 << 7,
    Virtualization = 1 << 8
}

public sealed record ReactorStructureFacts(
    int DelegateProxyCount,
    int DeadCallPrefixCount,
    int DispatcherMethodCount,
    int MethodStubCount,
    int StringResolverCount,
    int HighEntropyResourceCount,
    int VirtualizedMethodCount,
    bool ReferencesClrJit,
    bool HasRuntimeModulePointerAccess,
    ReactorCapability Capabilities,
    double Confidence,
    string Generation)
{
    public bool IsReactor => Confidence >= 0.55;

    public IReadOnlyList<string> CapabilityNames =>
        Enum.GetValues<ReactorCapability>()
            .Where(value => value != ReactorCapability.None && Capabilities.HasFlag(value))
            .Select(value => value switch
            {
                ReactorCapability.DelegateProxy => "delegate-proxy",
                ReactorCapability.InvalidCallJunk => "invalid-call-junk",
                ReactorCapability.DispatcherControlFlow => "dispatcher-control-flow",
                ReactorCapability.ProtectedStrings => "protected-strings",
                ReactorCapability.ResourceContainer => "resource-container",
                ReactorCapability.MethodStubs => "method-stubs",
                ReactorCapability.JitHook => "jit-hook",
                ReactorCapability.AntiTamper => "anti-tamper",
                ReactorCapability.Virtualization => "virtualization",
                _ => value.ToString()
            })
            .ToArray();
}

public static class ReactorStructureDetector
{
    public static ReactorStructureFacts Analyze(ModuleDefMD module)
    {
        var types = module.GetTypes().ToArray();
        var methods = types.SelectMany(type => type.Methods).ToArray();
        var delegates = types.Count(IsDelegateProxy);
        var deadPrefixes = methods.Count(HasDeadCallPrefix);
        var dispatchers = methods.Count(IsDispatcher);
        var stubs = methods.Count(IsProtectedMethodStub);
        var stringResolvers = methods.Count(IsStringResolver);
        var resourceInfos = ResourceInspector.Inspect(module);
        var highEntropyResources = resourceInfos.Count(resource => resource.Entropy >= 7.75);
        var virtualized = VirtualizedMethodDetector.Detect(module).Count;
        var strings = methods
            .Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions)
            .Select(instruction => instruction.Operand as string)
            .Where(value => value is not null)
            .Cast<string>()
            .ToArray();
        var clrJit = strings.Any(value =>
            value.Contains("clrjit", StringComparison.OrdinalIgnoreCase));
        var runtimePointer = strings.Any(value =>
            value is "m_pData" or "m_ptr" ||
            value.Contains("RuntimeModule", StringComparison.Ordinal));

        var capabilities = ReactorCapability.None;
        if (delegates >= 10) capabilities |= ReactorCapability.DelegateProxy;
        if (deadPrefixes >= 10) capabilities |= ReactorCapability.InvalidCallJunk;
        if (dispatchers >= 2) capabilities |= ReactorCapability.DispatcherControlFlow;
        if (stringResolvers > 0) capabilities |= ReactorCapability.ProtectedStrings;
        if (highEntropyResources >= 2) capabilities |= ReactorCapability.ResourceContainer;
        if (stubs >= 10) capabilities |= ReactorCapability.MethodStubs;
        if (clrJit) capabilities |= ReactorCapability.JitHook;
        if (stubs >= 10 && highEntropyResources >= 2) capabilities |= ReactorCapability.AntiTamper;
        if (virtualized > 0) capabilities |= ReactorCapability.Virtualization;

        // Weighed in whole percentage points rather than fractions, because some of these signals
        // are meant to reach the gate exactly when they combine and no closer: a resolver with its
        // dispatchers and an encrypted resource comes to precisely the 55 the gate asks for. Added
        // up as binary fractions that total lands a sixteenth of a quadrillionth short, so a
        // boundary the weights were chosen to sit on would read as a miss.
        var points = 0;
        if (delegates >= 10) points += 35;
        if (deadPrefixes >= 10) points += 15;
        if (dispatchers >= 2) points += 15;
        if (stubs >= 10) points += 35;
        // A method that takes an integer and returns a string by reading a manifest resource is
        // Reactor's protected-string resolver and almost nothing else -- far more specific than the
        // dispatchers or dead-call junk other obfuscators also emit -- so a strings-only Reactor
        // configuration, which has no stubs or proxies to lean on, still clears the gate on the
        // strength of the resolver plus its corroborating control flow.
        if (stringResolvers > 0) points += 30;
        if (highEntropyResources >= 2) points += 10;
        if (clrJit) points += 20;
        if (runtimePointer) points += 10;
        var score = Math.Min(100, points) / 100.0;

        var generation = stubs >= 10 && clrJit
            ? "jit-hook"
            : delegates >= 10 ? "delegate-runtime" : "unknown";
        return new ReactorStructureFacts(
            delegates,
            deadPrefixes,
            dispatchers,
            stubs,
            stringResolvers,
            highEntropyResources,
            virtualized,
            clrJit,
            runtimePointer,
            capabilities,
            score,
            generation);
    }

    public static bool IsDelegateProxy(TypeDef type) =>
        type.BaseType?.FullName == "System.MulticastDelegate" &&
        type.Fields.Any(field => field.IsStatic && field.FieldType.FullName == type.FullName);

    public static bool HasDeadCallPrefix(MethodDef method)
    {
        if (!method.HasBody || method.Body.Instructions.Count < 3)
        {
            return false;
        }

        var instructions = method.Body.Instructions;
        return instructions[0].OpCode.FlowControl == FlowControl.Branch &&
               instructions[0].Operand is Instruction target &&
               ReferenceEquals(target, instructions[2]) &&
               instructions[1].OpCode.FlowControl == FlowControl.Call;
    }

    public static bool IsDispatcher(MethodDef method)
    {
        if (!method.HasBody)
        {
            return false;
        }

        return method.Body.Instructions.Any(instruction =>
            instruction.OpCode == OpCodes.Switch &&
            instruction.Operand is IList<Instruction> targets &&
            targets.Count >= 3);
    }

    public static bool IsProtectedMethodStub(MethodDef method)
    {
        if (!method.HasBody || !method.IsNoInlining)
        {
            return false;
        }

        var instructions = method.Body.Instructions;
        if (instructions.Count is < 3 or > 6 || instructions[^1].OpCode != OpCodes.Ret)
        {
            return false;
        }

        // A stub returns the default of its return type: it pushes a constant and optionally
        // coerces it to the declared type. Reactor emits the coercion for value-typed and
        // widened returns, so matching only the bare constant misses those stubs.
        var meaningful = instructions
            .Take(instructions.Count - 1)
            .Where(instruction => instruction.OpCode != OpCodes.Nop)
            .ToArray();
        return meaningful.Length switch
        {
            0 => true,
            1 => IsDefaultValuePush(meaningful[0].OpCode),
            2 => IsDefaultValuePush(meaningful[0].OpCode) &&
                IsDefaultValueCoercion(meaningful[1].OpCode),
            _ => false
        };
    }

    private static bool IsDefaultValuePush(OpCode opcode) =>
        opcode == OpCodes.Ldnull ||
        opcode == OpCodes.Ldc_I4_0 ||
        opcode == OpCodes.Ldc_I4_1 ||
        opcode == OpCodes.Ldc_I4 ||
        opcode == OpCodes.Ldc_I4_S ||
        opcode == OpCodes.Ldc_I8 ||
        opcode == OpCodes.Ldc_R4 ||
        opcode == OpCodes.Ldc_R8;

    private static bool IsDefaultValueCoercion(OpCode opcode) =>
        opcode == OpCodes.Unbox_Any ||
        opcode == OpCodes.Box ||
        opcode == OpCodes.Castclass ||
        opcode == OpCodes.Isinst ||
        opcode.Code is Code.Conv_I or Code.Conv_I1 or Code.Conv_I2 or Code.Conv_I4 or
            Code.Conv_I8 or Code.Conv_U or Code.Conv_U1 or Code.Conv_U2 or Code.Conv_U4 or
            Code.Conv_U8 or Code.Conv_R4 or Code.Conv_R8 or Code.Conv_R_Un;

    /// <summary>
    /// The minimum number of integer instance fields before a self-rooted singleton is treated
    /// as a resolver key holder rather than an ordinary application type.
    /// </summary>
    private const int MinimumResolverKeyFields = 8;

    /// <summary>
    /// Recognizes the type Reactor uses to hold per-call-site resolver keys.
    /// </summary>
    /// <remarks>
    /// Protected string and boolean call sites never pass a literal offset. Each computes
    /// <c>constant XOR key</c>, loading the key with <c>ldsfld singleton; ldfld key</c>. The
    /// holder is structurally distinctive: a class that roots an instance of itself in one of
    /// its own static fields and declares a large block of integer instance fields that its
    /// type initializer fills. Matching that shape avoids depending on the randomized
    /// <c>&lt;Module&gt;{guid}</c> naming Reactor emits.
    /// </remarks>
    public static bool IsResolverKeyHolder(TypeDef type) =>
        type.IsClass &&
        !type.IsInterface &&
        type.FindStaticConstructor() is not null &&
        type.Fields.Any(field =>
            field.IsStatic && field.FieldType?.FullName == type.FullName) &&
        type.Fields.Count(field =>
            !field.IsStatic &&
            field.FieldSig?.Type.ElementType == ElementType.I4) >= MinimumResolverKeyFields;

    public static bool IsStringResolver(MethodDef method) =>
        method.HasBody &&
        method.MethodSig?.Params.Count == 1 &&
        method.MethodSig.Params[0].ElementType == ElementType.I4 &&
        method.ReturnType.ElementType == ElementType.String &&
        method.Body.Instructions.Any(instruction =>
            instruction.Operand is IMethod called &&
            called.Name == "GetManifestResourceStream");
}

public sealed record StrategyMatch(
    string Id,
    double Confidence,
    ReactorCapability Capabilities,
    IReadOnlyList<string> Evidence);

public interface IReactorStrategy
{
    string Id { get; }
    StrategyMatch Match(ModuleDefMD assemblyModule, ReactorStructureFacts facts);
}

public sealed class StructuralReactor6Strategy : IReactorStrategy
{
    public string Id => "reactor-structural";

    public StrategyMatch Match(ModuleDefMD assemblyModule, ReactorStructureFacts facts)
    {
        var evidence = new List<string>();
        if (facts.DelegateProxyCount >= 10)
            evidence.Add($"{facts.DelegateProxyCount} delegate proxy types");
        if (facts.MethodStubCount >= 10)
            evidence.Add($"{facts.MethodStubCount} NoInlining default-return stubs");
        if (facts.DispatcherMethodCount >= 2)
            evidence.Add($"{facts.DispatcherMethodCount} switch dispatcher methods");
        if (facts.ReferencesClrJit)
            evidence.Add("clrjit runtime reference");
        if (facts.HighEntropyResourceCount >= 2)
            evidence.Add($"{facts.HighEntropyResourceCount} high-entropy resources");
        return new StrategyMatch(Id, facts.Confidence, facts.Capabilities, evidence);
    }
}

public readonly record struct AbstractInt(bool Known, int Value)
{
    public static AbstractInt Unknown => new(false, 0);
    public static AbstractInt Constant(int value) => new(true, value);
}

public static class BoundedIntegerEvaluator
{
    public static AbstractInt Evaluate(IList<Instruction> instructions, int endExclusive, int budget = 128)
    {
        var stack = new Stack<AbstractInt>();
        var start = Math.Max(0, endExclusive - budget);
        for (var index = start; index < endExclusive; index++)
        {
            var instruction = instructions[index];
            if (instruction.IsLdcI4())
            {
                stack.Push(AbstractInt.Constant(instruction.GetLdcI4Value()));
                continue;
            }

            if (instruction.OpCode == OpCodes.Neg && stack.Count >= 1)
            {
                var value = stack.Pop();
                stack.Push(value.Known ? AbstractInt.Constant(unchecked(-value.Value)) : AbstractInt.Unknown);
                continue;
            }

            if (instruction.OpCode == OpCodes.Not && stack.Count >= 1)
            {
                var value = stack.Pop();
                stack.Push(value.Known ? AbstractInt.Constant(~value.Value) : AbstractInt.Unknown);
                continue;
            }

            if (stack.Count >= 2 && IsBinary(instruction.OpCode))
            {
                var right = stack.Pop();
                var left = stack.Pop();
                stack.Push(EvaluateBinary(instruction.OpCode, left, right));
                continue;
            }

            if (instruction.OpCode == OpCodes.Dup && stack.Count >= 1)
            {
                stack.Push(stack.Peek());
                continue;
            }

            if (instruction.OpCode == OpCodes.Pop && stack.Count >= 1)
            {
                stack.Pop();
            }
        }

        return stack.Count == 1 ? stack.Peek() : AbstractInt.Unknown;
    }

    private static bool IsBinary(OpCode opcode) =>
        opcode == OpCodes.Add || opcode == OpCodes.Sub || opcode == OpCodes.Mul ||
        opcode == OpCodes.Xor || opcode == OpCodes.And || opcode == OpCodes.Or ||
        opcode == OpCodes.Shl || opcode == OpCodes.Shr || opcode == OpCodes.Shr_Un;

    private static AbstractInt EvaluateBinary(OpCode opcode, AbstractInt left, AbstractInt right)
    {
        if (!left.Known || !right.Known)
        {
            return AbstractInt.Unknown;
        }

        var value = opcode.Code switch
        {
            Code.Add => unchecked(left.Value + right.Value),
            Code.Sub => unchecked(left.Value - right.Value),
            Code.Mul => unchecked(left.Value * right.Value),
            Code.Xor => left.Value ^ right.Value,
            Code.And => left.Value & right.Value,
            Code.Or => left.Value | right.Value,
            Code.Shl => left.Value << (right.Value & 31),
            Code.Shr => left.Value >> (right.Value & 31),
            Code.Shr_Un => (int)((uint)left.Value >> (right.Value & 31)),
            _ => 0
        };
        return AbstractInt.Constant(value);
    }
}

public static class ConstantArrayDiscovery
{
    public static IReadOnlyList<byte[]> FindThirtyTwoByteArrays(ModuleDef module)
    {
        var results = new List<byte[]>();
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods)
                     .Where(method => method.HasBody))
        {
            FindInitializedArrays(method.Body.Instructions, results);
            FindWordSequences(method.Body.Instructions, results);
        }

        return results
            .Distinct(ByteSequenceComparer.Instance)
            .ToArray();
    }

    private static void FindInitializedArrays(
        IList<Instruction> instructions,
        List<byte[]> results)
    {
        for (var index = 1; index < instructions.Count; index++)
        {
            if (instructions[index].OpCode != OpCodes.Newarr ||
                !instructions[index - 1].IsLdcI4())
            {
                continue;
            }

            var length = instructions[index - 1].GetLdcI4Value();
            var element = (instructions[index].Operand as ITypeDefOrRef)?.FullName;
            var byteLength = element switch
            {
                "System.Byte" when length == 32 => 32,
                "System.Int32" or "System.UInt32" when length == 8 => 32,
                _ => 0
            };
            if (byteLength == 0)
                continue;

            var output = new byte[byteLength];
            var assigned = new bool[length];
            var end = Math.Min(instructions.Count, index + 512);
            for (var cursor = index + 4; cursor < end; cursor++)
            {
                var store = instructions[cursor];
                var opcode = store.OpCode;
                if (opcode != OpCodes.Stelem_I1 &&
                    opcode != OpCodes.Stelem_I4)
                {
                    continue;
                }

                var indexValue = instructions[cursor - 2];
                var storedValue = instructions[cursor - 1];
                if (!indexValue.IsLdcI4() || !storedValue.IsLdcI4())
                    continue;
                var elementIndex = indexValue.GetLdcI4Value();
                if ((uint)elementIndex >= (uint)length)
                    continue;
                var value = storedValue.GetLdcI4Value();
                if (opcode == OpCodes.Stelem_I1 && length == 32)
                {
                    output[elementIndex] = unchecked((byte)value);
                }
                else if (opcode == OpCodes.Stelem_I4 && length == 8)
                {
                    System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(
                        output.AsSpan(elementIndex * 4, 4),
                        value);
                }
                else
                {
                    continue;
                }
                assigned[elementIndex] = true;
            }

            if (assigned.All(value => value))
                results.Add(output);
        }
    }

    private static void FindWordSequences(
        IList<Instruction> instructions,
        List<byte[]> results)
    {
        var constants = new Queue<int>();
        var previousConstant = -10;
        for (var instructionIndex = 0; instructionIndex < instructions.Count; instructionIndex++)
        {
            var instruction = instructions[instructionIndex];
            if (!instruction.IsLdcI4())
            {
                if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Return)
                    constants.Clear();
                continue;
            }

            if (instructionIndex - previousConstant > 4)
                constants.Clear();
            previousConstant = instructionIndex;
            constants.Enqueue(instruction.GetLdcI4Value());
            if (constants.Count > 8)
                constants.Dequeue();
            if (constants.Count != 8)
                continue;
            var bytes = new byte[32];
            var offset = 0;
            foreach (var value in constants)
            {
                System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(
                    bytes.AsSpan(offset, 4),
                    value);
                offset += 4;
            }
            results.Add(bytes);
        }
    }

    private sealed class ByteSequenceComparer : IEqualityComparer<byte[]>
    {
        public static ByteSequenceComparer Instance { get; } = new();
        public bool Equals(byte[]? left, byte[]? right) =>
            left is not null && right is not null && left.AsSpan().SequenceEqual(right);
        public int GetHashCode(byte[] value)
        {
            var hash = new HashCode();
            foreach (var item in value)
                hash.Add(item);
            return hash.ToHashCode();
        }
    }
}
