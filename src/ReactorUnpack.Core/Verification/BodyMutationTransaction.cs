using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace ReactorUnpack.Core.Verification;

/// <summary>
/// Captures a method body and restores it unless the transaction is committed.
/// </summary>
public sealed class BodyMutationTransaction : IDisposable
{
    private readonly MethodDef method;
    private readonly MethodBodySnapshot snapshot;
    private bool completed;

    public BodyMutationTransaction(MethodDef method)
    {
        this.method = method ?? throw new ArgumentNullException(nameof(method));
        snapshot = MethodBodySnapshot.Capture(method);
    }

    public MethodBodySnapshot Snapshot => snapshot;

    public void Commit()
    {
        if (completed)
            return;

        completed = true;
    }

    public void Rollback()
    {
        if (completed)
            return;

        snapshot.Restore(method);
        completed = true;
    }

    public void Dispose()
    {
        if (!completed)
            Rollback();
    }
}

/// <summary>
/// An isolated structural snapshot of a dnlib CIL method body.
/// </summary>
public sealed class MethodBodySnapshot
{
    private readonly CilBody? capturedBody;
    private readonly BodyState? state;
    private readonly string structuralRepresentation;

    private MethodBodySnapshot(CilBody? body)
    {
        capturedBody = body;
        state = body is null ? null : BodyState.Capture(body);
        structuralRepresentation = BodyStructure.Describe(body);
        Fingerprint = BodyStructure.Hash(structuralRepresentation);
    }

    public bool HasBody => state is not null;

    public string Fingerprint { get; }

    public static MethodBodySnapshot Capture(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        return new MethodBodySnapshot(method.Body);
    }

    public static MethodBodySnapshot Capture(CilBody? body) => new(body);

    /// <summary>
    /// Restores both the body contents and the body object originally assigned to the method.
    /// </summary>
    public void Restore(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);

        if (state is null)
        {
            method.Body = null;
            return;
        }

        var destination = capturedBody ?? new CilBody();
        state.RestoreInto(destination);
        method.Body = destination;
    }

    public bool StructurallyEquals(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        return string.Equals(
            structuralRepresentation,
            BodyStructure.Describe(method.Body),
            StringComparison.Ordinal);
    }

    public bool StructurallyEquals(CilBody? body) =>
        string.Equals(
            structuralRepresentation,
            BodyStructure.Describe(body),
            StringComparison.Ordinal);

    private sealed class BodyState
    {
        private readonly bool keepOldMaxStack;
        private readonly bool initLocals;
        private readonly byte headerSize;
        private readonly ushort maxStack;
        private readonly uint localVarSigTok;
        private readonly LocalState[] locals;
        private readonly InstructionState[] instructions;
        private readonly ExceptionHandlerState[] exceptionHandlers;

        private BodyState(
            bool keepOldMaxStack,
            bool initLocals,
            byte headerSize,
            ushort maxStack,
            uint localVarSigTok,
            LocalState[] locals,
            InstructionState[] instructions,
            ExceptionHandlerState[] exceptionHandlers)
        {
            this.keepOldMaxStack = keepOldMaxStack;
            this.initLocals = initLocals;
            this.headerSize = headerSize;
            this.maxStack = maxStack;
            this.localVarSigTok = localVarSigTok;
            this.locals = locals;
            this.instructions = instructions;
            this.exceptionHandlers = exceptionHandlers;
        }

        public static BodyState Capture(CilBody body)
        {
            var instructionIndices = body.Instructions
                .Select((instruction, index) => (instruction, index))
                .ToDictionary(item => item.instruction, item => item.index);
            var localIndices = body.Variables
                .Select((local, index) => (local, index))
                .ToDictionary(item => item.local, item => item.index);

            return new BodyState(
                body.KeepOldMaxStack,
                body.InitLocals,
                body.HeaderSize,
                body.MaxStack,
                body.LocalVarSigTok,
                body.Variables.Select(LocalState.Capture).ToArray(),
                body.Instructions
                    .Select(instruction => InstructionState.Capture(
                        instruction,
                        instructionIndices,
                        localIndices))
                    .ToArray(),
                body.ExceptionHandlers
                    .Select(handler => ExceptionHandlerState.Capture(handler, instructionIndices))
                    .ToArray());
        }

        public void RestoreInto(CilBody body)
        {
            body.Variables.Clear();
            foreach (var local in locals)
                body.Variables.Add(local.Create());

            body.Instructions.Clear();
            foreach (var instruction in instructions)
                body.Instructions.Add(new Instruction(instruction.OpCode, null));

            for (var index = 0; index < instructions.Length; index++)
            {
                body.Instructions[index].Operand = instructions[index].Operand.Restore(
                    body.Instructions,
                    body.Variables);
            }

            body.ExceptionHandlers.Clear();
            foreach (var handler in exceptionHandlers)
                body.ExceptionHandlers.Add(handler.Create(body.Instructions));

            body.KeepOldMaxStack = keepOldMaxStack;
            body.InitLocals = initLocals;
            body.HeaderSize = headerSize;
            body.MaxStack = maxStack;
            body.LocalVarSigTok = localVarSigTok;
            body.UpdateInstructionOffsets();
        }
    }

    private sealed record LocalState(TypeSig Type, string? Name, dnlib.DotNet.Pdb.PdbLocalAttributes Attributes)
    {
        public static LocalState Capture(Local local) =>
            new(local.Type, local.Name, local.Attributes);

        public Local Create() => new(Type, Name) { Attributes = Attributes };
    }

    private sealed record InstructionState(OpCode OpCode, OperandState Operand)
    {
        public static InstructionState Capture(
            Instruction instruction,
            IReadOnlyDictionary<Instruction, int> instructionIndices,
            IReadOnlyDictionary<Local, int> localIndices) =>
            new(
                instruction.OpCode,
                OperandState.Capture(instruction.Operand, instructionIndices, localIndices));
    }

    private sealed record OperandState(
        object? Value,
        int? InstructionIndex,
        int? LocalIndex,
        int[]? SwitchIndices)
    {
        public static OperandState Capture(
            object? operand,
            IReadOnlyDictionary<Instruction, int> instructionIndices,
            IReadOnlyDictionary<Local, int> localIndices)
        {
            if (operand is Instruction instruction)
                return new(null, IndexOf(instruction, instructionIndices), null, null);

            if (operand is IList<Instruction> targets)
            {
                return new(
                    null,
                    null,
                    null,
                    targets.Select(target => IndexOf(target, instructionIndices)).ToArray());
            }

            if (operand is Local local)
                return new(null, null, IndexOf(local, localIndices), null);

            return new(operand, null, null, null);
        }

        public object? Restore(IList<Instruction> instructions, LocalList locals)
        {
            if (InstructionIndex is int instructionIndex)
                return instructions[instructionIndex];
            if (LocalIndex is int localIndex)
                return locals[localIndex];
            if (SwitchIndices is not null)
                return SwitchIndices.Select(index => instructions[index]).ToArray();
            return Value;
        }

        private static int IndexOf<T>(T value, IReadOnlyDictionary<T, int> indices)
            where T : class
        {
            if (indices.TryGetValue(value, out var index))
                return index;
            throw new InvalidOperationException("The method body contains an operand outside its own structure.");
        }
    }

    private sealed record ExceptionHandlerState(
        ExceptionHandlerType HandlerType,
        int? TryStart,
        int? TryEnd,
        int? FilterStart,
        int? HandlerStart,
        int? HandlerEnd,
        ITypeDefOrRef? CatchType)
    {
        public static ExceptionHandlerState Capture(
            ExceptionHandler handler,
            IReadOnlyDictionary<Instruction, int> instructionIndices) =>
            new(
                handler.HandlerType,
                Boundary(handler.TryStart, instructionIndices),
                Boundary(handler.TryEnd, instructionIndices),
                Boundary(handler.FilterStart, instructionIndices),
                Boundary(handler.HandlerStart, instructionIndices),
                Boundary(handler.HandlerEnd, instructionIndices),
                handler.CatchType);

        public ExceptionHandler Create(IList<Instruction> instructions) =>
            new(HandlerType)
            {
                TryStart = Resolve(TryStart, instructions),
                TryEnd = Resolve(TryEnd, instructions),
                FilterStart = Resolve(FilterStart, instructions),
                HandlerStart = Resolve(HandlerStart, instructions),
                HandlerEnd = Resolve(HandlerEnd, instructions),
                CatchType = CatchType,
            };

        private static int? Boundary(
            Instruction? instruction,
            IReadOnlyDictionary<Instruction, int> instructionIndices)
        {
            if (instruction is null)
                return null;
            if (instructionIndices.TryGetValue(instruction, out var index))
                return index;
            throw new InvalidOperationException("An exception-handler boundary is outside the method body.");
        }

        private static Instruction? Resolve(int? index, IList<Instruction> instructions) =>
            index is null ? null : instructions[index.Value];
    }
}

/// <summary>
/// Produces structural equality results and stable fingerprints for CIL bodies.
/// </summary>
public static class MethodBodyStructuralComparer
{
    public static bool AreEqual(MethodDef left, MethodDef right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return BodyStructure.Describe(left.Body) == BodyStructure.Describe(right.Body);
    }

    public static bool AreEqual(CilBody? left, CilBody? right) =>
        BodyStructure.Describe(left) == BodyStructure.Describe(right);

    public static bool AreEqual(MethodBodySnapshot snapshot, MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return snapshot.StructurallyEquals(method);
    }

    public static string Fingerprint(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        return Fingerprint(method.Body);
    }

    public static string Fingerprint(CilBody? body) =>
        BodyStructure.Hash(BodyStructure.Describe(body));
}

internal static class BodyStructure
{
    public static string Describe(CilBody? body)
    {
        if (body is null)
            return "body:null";

        var instructionIndices = body.Instructions
            .Select((instruction, index) => (instruction, index))
            .ToDictionary(item => item.instruction, item => item.index);
        var localIndices = body.Variables
            .Select((local, index) => (local, index))
            .ToDictionary(item => item.local, item => item.index);
        var result = new StringBuilder();

        Append(result, "body");
        Append(result, body.KeepOldMaxStack);
        Append(result, body.InitLocals);
        Append(result, body.HeaderSize);
        Append(result, body.MaxStack);
        Append(result, body.LocalVarSigTok);

        Append(result, body.Variables.Count);
        foreach (var local in body.Variables)
        {
            Append(result, local.Type.FullName);
            Append(result, local.Name);
            Append(result, (int)local.Attributes);
        }

        Append(result, body.Instructions.Count);
        foreach (var instruction in body.Instructions)
        {
            Append(result, instruction.OpCode.Value);
            DescribeOperand(result, instruction.Operand, instructionIndices, localIndices);
        }

        Append(result, body.ExceptionHandlers.Count);
        foreach (var handler in body.ExceptionHandlers)
        {
            Append(result, (int)handler.HandlerType);
            AppendBoundary(result, handler.TryStart, instructionIndices);
            AppendBoundary(result, handler.TryEnd, instructionIndices);
            AppendBoundary(result, handler.FilterStart, instructionIndices);
            AppendBoundary(result, handler.HandlerStart, instructionIndices);
            AppendBoundary(result, handler.HandlerEnd, instructionIndices);
            DescribeMetadataOperand(result, handler.CatchType);
        }

        return result.ToString();
    }

    public static string Hash(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static void DescribeOperand(
        StringBuilder result,
        object? operand,
        IReadOnlyDictionary<Instruction, int> instructionIndices,
        IReadOnlyDictionary<Local, int> localIndices)
    {
        switch (operand)
        {
            case null:
                Append(result, "null");
                break;
            case Instruction instruction:
                Append(result, "instruction");
                AppendBoundary(result, instruction, instructionIndices);
                break;
            case IList<Instruction> targets:
                Append(result, "switch");
                Append(result, targets.Count);
                foreach (var target in targets)
                    AppendBoundary(result, target, instructionIndices);
                break;
            case Local local:
                Append(result, "local");
                Append(result, TryIndexOf(local, localIndices));
                break;
            case Parameter parameter:
                Append(result, "parameter");
                Append(result, parameter.Index);
                Append(result, parameter.Type.FullName);
                break;
            case string text:
                Append(result, "string");
                Append(result, text);
                break;
            case IConvertible convertible:
                Append(result, operand.GetType().FullName);
                Append(result, convertible.ToString(CultureInfo.InvariantCulture));
                break;
            default:
                DescribeMetadataOperand(result, operand);
                break;
        }
    }

    private static void DescribeMetadataOperand(StringBuilder result, object? operand)
    {
        if (operand is null)
        {
            Append(result, "null");
            return;
        }

        Append(result, operand.GetType().FullName);
        Append(result, operand is IMDTokenProvider provider ? provider.MDToken.Raw : 0U);
        Append(result, operand is IFullName fullName ? fullName.FullName : operand.ToString());
    }

    private static void AppendBoundary(
        StringBuilder result,
        Instruction? instruction,
        IReadOnlyDictionary<Instruction, int> instructionIndices)
    {
        Append(result, instruction is null ? -1 : TryIndexOf(instruction, instructionIndices));
    }

    private static int TryIndexOf<T>(T value, IReadOnlyDictionary<T, int> indices)
        where T : class =>
        indices.TryGetValue(value, out var index) ? index : int.MinValue;

    private static void Append(StringBuilder result, object? value)
    {
        var text = Convert.ToString(value, CultureInfo.InvariantCulture) ?? "<null>";
        result.Append(text.Length);
        result.Append(':');
        result.Append(text);
        result.Append(';');
    }
}
