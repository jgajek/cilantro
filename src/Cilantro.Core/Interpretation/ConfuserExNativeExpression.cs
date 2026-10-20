using System.Buffers.Binary;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Interpretation;

/// <summary>Evaluates the closed x86 expression stub emitted by ConfuserEx constants mode.</summary>
internal static class ConfuserExNativeExpression
{
    private abstract record Expression
    {
        internal abstract int Nodes { get; }
        internal abstract int Evaluate(int argument);
        internal abstract void Emit(IList<Instruction> output);
    }
    private sealed record Argument : Expression
    {
        internal override int Nodes => 1;
        internal override int Evaluate(int argument) => argument;
        internal override void Emit(IList<Instruction> output) => output.Add(OpCodes.Ldarg_0.ToInstruction());
    }
    private sealed record Constant(int Value) : Expression
    {
        internal override int Nodes => 1;
        internal override int Evaluate(int argument) => Value;
        internal override void Emit(IList<Instruction> output) => output.Add(OpCodes.Ldc_I4.ToInstruction(Value));
    }
    private sealed record Unary(Code Operation, Expression Value) : Expression
    {
        internal override int Nodes => 1 + Value.Nodes;
        internal override int Evaluate(int argument) => Operation == Code.Neg
            ? unchecked(-Value.Evaluate(argument)) : ~Value.Evaluate(argument);
        internal override void Emit(IList<Instruction> output)
        {
            Value.Emit(output);
            output.Add((Operation == Code.Neg ? OpCodes.Neg : OpCodes.Not).ToInstruction());
        }
    }
    private sealed record Binary(Code Operation, Expression Left, Expression Right) : Expression
    {
        internal override int Nodes => 1 + Left.Nodes + Right.Nodes;
        internal override int Evaluate(int argument)
        {
            var left = Left.Evaluate(argument);
            var right = Right.Evaluate(argument);
            return Operation switch
            {
                Code.Add => unchecked(left + right),
                Code.Sub => unchecked(left - right),
                Code.Mul => unchecked(left * right),
                _ => left ^ right
            };
        }
        internal override void Emit(IList<Instruction> output)
        {
            Left.Emit(output);
            Right.Emit(output);
            output.Add((Operation switch
            {
                Code.Add => OpCodes.Add,
                Code.Sub => OpCodes.Sub,
                Code.Mul => OpCodes.Mul,
                _ => OpCodes.Xor
            }).ToInstruction());
        }
    }

    internal static bool TryTranslate(MethodDef method, byte[] file, out CilBody? body)
    {
        body = null;
        if (method.HasBody || method.ImplMap is not null || !method.IsStatic ||
            method.DeclaringType?.IsGlobalModuleType != true ||
            method.MethodSig is not { Params.Count: 1 } signature ||
            signature.Params[0].ElementType != ElementType.I4 ||
            signature.RetType.ElementType != ElementType.I4 ||
            (uint)method.RVA == 0 || file.Length == 0)
            return false;
        PeImageView image;
        try { image = new PeImageView(file); }
        catch (BadImageFormatException) { return false; }
        if (!image.TryRead((uint)method.RVA, 256, out var memory)) return false;
        var code = memory.Span;
        if (!code[..Prologue.Length].SequenceEqual(Prologue)) return false;
        var registers = new Expression?[8];
        var poppedArgument = false;
        var position = Prologue.Length;
        for (var step = 0; step < 64 && position < code.Length - 4; step++)
        {
            if (code.Slice(position, 4).SequenceEqual(Epilogue))
            {
                if (!poppedArgument || registers[0] is not { Nodes: <= 256 } answer) return false;
                var probes = new[] { 0, 1, -1, int.MinValue, int.MaxValue,
                    unchecked((int)0x12345678), unchecked((int)0x87654321) };
                foreach (var probe in probes)
                    if (!TryEvaluate(method, file, probe, out var observed) ||
                        answer.Evaluate(probe) != observed)
                        return false;
                var translated = new CilBody();
                answer.Emit(translated.Instructions);
                translated.Instructions.Add(OpCodes.Ret.ToInstruction());
                translated.MaxStack = 256;
                body = translated;
                return true;
            }
            var opcode = code[position++];
            if (opcode is >= 0x58 and <= 0x5f)
            {
                if (poppedArgument || opcode is 0x5c or 0x5d) return false;
                registers[opcode - 0x58] = new Argument();
                poppedArgument = true;
            }
            else if (opcode is >= 0xb8 and <= 0xbf)
            {
                if (!ReadImmediate(code, ref position, out var immediate)) return false;
                registers[opcode - 0xb8] = new Constant(immediate);
            }
            else if (opcode == 0x0f)
            {
                if (position >= code.Length || code[position++] != 0xaf ||
                    !ReadRegisters(code, ref position, out var destination, out var source) ||
                    registers[source] is not { } left || registers[destination] is not { } right) return false;
                registers[source] = new Binary(Code.Mul, left, right);
            }
            else if (opcode == 0x69)
            {
                if (!ReadRegisters(code, ref position, out var source, out var destination) ||
                    !ReadImmediate(code, ref position, out var immediate) ||
                    registers[source] is not { } left) return false;
                registers[destination] = new Binary(Code.Mul, left, new Constant(immediate));
            }
            else if (opcode == 0xf7)
            {
                if (position >= code.Length) return false;
                var modrm = code[position++];
                if ((modrm & 0xc0) != 0xc0 || (modrm & 7) is 4 or 5) return false;
                var register = modrm & 7;
                if (registers[register] is not { } value) return false;
                registers[register] = ((modrm >> 3) & 7) switch
                {
                    2 => new Unary(Code.Not, value),
                    3 => new Unary(Code.Neg, value),
                    _ => null
                };
                if (registers[register] is null) return false;
            }
            else if (opcode == 0x81)
            {
                if (position >= code.Length) return false;
                var modrm = code[position++];
                if ((modrm & 0xc0) != 0xc0 || (modrm & 7) is 4 or 5 ||
                    !ReadImmediate(code, ref position, out var immediate)) return false;
                var register = modrm & 7;
                if (registers[register] is not { } value) return false;
                var operation = ((modrm >> 3) & 7) switch
                {
                    0 => Code.Add, 5 => Code.Sub, 6 => Code.Xor, _ => Code.Nop
                };
                if (operation == Code.Nop) return false;
                registers[register] = new Binary(operation, value, new Constant(immediate));
            }
            else if (opcode is 0x89 or 0x01 or 0x29 or 0x31)
            {
                if (!ReadRegisters(code, ref position, out var destination, out var source) ||
                    registers[source] is not { } sourceValue) return false;
                if (opcode == 0x89) registers[destination] = sourceValue;
                else
                {
                    if (registers[destination] is not { } destinationValue) return false;
                    registers[destination] = new Binary(opcode switch
                    {
                        0x01 => Code.Add, 0x29 => Code.Sub, _ => Code.Xor
                    }, destinationValue, sourceValue);
                }
            }
            else return false;
            if (registers.Any(value => value is { Nodes: > 256 })) return false;
        }
        return false;
    }

    private static readonly byte[] Prologue =
    [
        0x89, 0xe0, 0x53, 0x57, 0x56, 0x29, 0xe0, 0x83, 0xf8, 0x18,
        0x74, 0x07, 0x8b, 0x44, 0x24, 0x10, 0x50, 0xeb, 0x01, 0x51
    ];
    private static readonly byte[] Epilogue = [0x5e, 0x5f, 0x5b, 0xc3];

    public static bool TryEvaluate(MethodDef method, byte[] file, int argument, out int result)
    {
        result = 0;
        if (method.HasBody || method.ImplMap is not null || !method.IsStatic ||
            method.DeclaringType?.IsGlobalModuleType != true ||
            method.MethodSig is not { Params.Count: 1 } signature ||
            signature.Params[0].ElementType != ElementType.I4 ||
            signature.RetType.ElementType != ElementType.I4 ||
            (uint)method.RVA == 0 || file.Length == 0)
            return false;

        PeImageView image;
        try { image = new PeImageView(file); }
        catch (BadImageFormatException) { return false; }
        if (!image.TryRead((uint)method.RVA, 256, out var memory))
            return false;
        var code = memory.Span;
        if (!code[..Prologue.Length].SequenceEqual(Prologue))
            return false;

        Span<int> registers = stackalloc int[8];
        var poppedArgument = false;
        var position = Prologue.Length;
        for (var step = 0; step < 64 && position < code.Length - 4; step++)
        {
            if (code.Slice(position, 4).SequenceEqual(Epilogue))
            {
                if (!poppedArgument) return false;
                result = registers[0];
                return true;
            }
            var opcode = code[position++];
            if (opcode is >= 0x58 and <= 0x5f)
            {
                if (poppedArgument || opcode is 0x5c or 0x5d) return false;
                registers[opcode - 0x58] = argument;
                poppedArgument = true;
                continue;
            }
            if (opcode is >= 0xb8 and <= 0xbf)
            {
                if (!ReadImmediate(code, ref position, out var immediate)) return false;
                registers[opcode - 0xb8] = immediate;
                continue;
            }
            if (opcode == 0x0f)
            {
                if (position >= code.Length || code[position++] != 0xaf ||
                    !ReadRegisters(code, ref position, out var destination, out var source)) return false;
                registers[source] = unchecked(registers[source] * registers[destination]);
                continue;
            }
            if (opcode == 0x69)
            {
                if (!ReadRegisters(code, ref position, out var source, out var destination) ||
                    !ReadImmediate(code, ref position, out var immediate)) return false;
                registers[destination] = unchecked(registers[source] * immediate);
                continue;
            }
            if (opcode == 0xf7)
            {
                if (position >= code.Length) return false;
                var modrm = code[position++];
                if ((modrm & 0xc0) != 0xc0 || (modrm & 7) is 4 or 5) return false;
                var register = modrm & 7;
                switch ((modrm >> 3) & 7)
                {
                    case 2: registers[register] = ~registers[register]; break;
                    case 3: registers[register] = unchecked(-registers[register]); break;
                    default: return false;
                }
                continue;
            }
            if (opcode == 0x81)
            {
                if (position >= code.Length) return false;
                var modrm = code[position++];
                if ((modrm & 0xc0) != 0xc0 || (modrm & 7) is 4 or 5 ||
                    !ReadImmediate(code, ref position, out var immediate)) return false;
                var register = modrm & 7;
                switch ((modrm >> 3) & 7)
                {
                    case 0: registers[register] = unchecked(registers[register] + immediate); break;
                    case 5: registers[register] = unchecked(registers[register] - immediate); break;
                    case 6: registers[register] ^= immediate; break;
                    default: return false;
                }
                continue;
            }
            if (opcode is 0x89 or 0x01 or 0x29 or 0x31)
            {
                if (!ReadRegisters(code, ref position, out var destination, out var source)) return false;
                registers[destination] = opcode switch
                {
                    0x89 => registers[source],
                    0x01 => unchecked(registers[destination] + registers[source]),
                    0x29 => unchecked(registers[destination] - registers[source]),
                    _ => registers[destination] ^ registers[source]
                };
                continue;
            }
            return false;
        }
        return false;
    }

    private static bool ReadRegisters(ReadOnlySpan<byte> code, ref int position,
        out int destination, out int source)
    {
        destination = source = 0;
        if (position >= code.Length) return false;
        var modrm = code[position++];
        if ((modrm & 0xc0) != 0xc0) return false;
        destination = modrm & 7;
        source = (modrm >> 3) & 7;
        return destination is not (4 or 5) && source is not (4 or 5);
    }

    private static bool ReadImmediate(ReadOnlySpan<byte> code, ref int position, out int value)
    {
        value = 0;
        if (position > code.Length - 4) return false;
        value = BinaryPrimitives.ReadInt32LittleEndian(code.Slice(position, 4));
        position += 4;
        return true;
    }
}
