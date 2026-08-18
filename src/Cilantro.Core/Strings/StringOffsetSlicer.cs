using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Strings;

internal static class StringOffsetSlicer
{
    private const int MaximumSliceInstructions = 512;
    private const int MaximumDepth = 64;

    internal static bool TryEvaluate(
        MethodDef method,
        int callIndex,
        IReadOnlyDictionary<uint, int> instanceFields,
        out int value,
        out string diagnostic)
    {
        value = 0;
        diagnostic = string.Empty;
        var budget = MaximumSliceInstructions;
        var index = callIndex - 1;
        var activeLocals = new HashSet<int>();
        if (!TryReadInteger(method, ref index, instanceFields, activeLocals, 0,
                ref budget, out value, out diagnostic))
            return false;
        return true;
    }

    private static bool TryReadInteger(
        MethodDef method,
        ref int index,
        IReadOnlyDictionary<uint, int> instanceFields,
        HashSet<int> activeLocals,
        int depth,
        ref int budget,
        out int value,
        out string diagnostic)
    {
        value = 0;
        diagnostic = string.Empty;
        if (depth >= MaximumDepth || budget-- <= 0)
            return Failure("slice bound was exceeded", out diagnostic);
        SkipNops(method, ref index);
        if (index < 0)
            return Failure("the producer ran before the method entry", out diagnostic);

        var instruction = method.Body.Instructions[index--];
        if (instruction.IsLdcI4())
        {
            value = instruction.GetLdcI4Value();
            return true;
        }
        if (TryGetLoadedLocal(instruction, out var localIndex))
        {
            if (!activeLocals.Add(localIndex))
                return Failure($"local V_{localIndex} is cyclic", out diagnostic);
            var definitions = FindPriorLocalDefinitions(method, index, localIndex);
            var values = new HashSet<int>();
            foreach (var definition in definitions)
            {
                var producer = definition - 1;
                var localBudget = budget;
                if (!TryReadInteger(method, ref producer, instanceFields, activeLocals,
                        depth + 1, ref localBudget, out var localValue, out diagnostic))
                {
                    activeLocals.Remove(localIndex);
                    return false;
                }
                values.Add(localValue);
            }
            activeLocals.Remove(localIndex);
            if (values.Count != 1)
                return Failure(
                    $"local V_{localIndex} has {values.Count} distinct reaching constants",
                    out diagnostic);
            value = values.Single();
            return true;
        }
        if (instruction.OpCode.Code == Code.Ldfld &&
            instruction.Operand is IField field)
        {
            if (!instanceFields.TryGetValue(field.MDToken.Raw, out value))
                return Failure(
                    $"instance field {field.MDToken} has no unique VM-initialized integer",
                    out diagnostic);
            if (!TryConsumeObject(method, ref index, depth + 1, ref budget, out diagnostic))
                return false;
            return true;
        }
        if (instruction.OpCode.Code is Code.Conv_I4 or Code.Conv_U4)
            return TryReadInteger(method, ref index, instanceFields, activeLocals,
                depth + 1, ref budget, out value, out diagnostic);
        if (instruction.OpCode.Code is Code.Neg or Code.Not)
        {
            if (!TryReadInteger(method, ref index, instanceFields, activeLocals,
                    depth + 1, ref budget, out var operand, out diagnostic))
                return false;
            value = instruction.OpCode.Code == Code.Neg
                ? unchecked(-operand)
                : ~operand;
            return true;
        }
        if (instruction.OpCode.Code is Code.Add or Code.Sub or Code.Xor or
            Code.And or Code.Or or Code.Mul or Code.Shl or Code.Shr or Code.Shr_Un)
        {
            if (!TryReadInteger(method, ref index, instanceFields, activeLocals,
                    depth + 1, ref budget, out var right, out diagnostic) ||
                !TryReadInteger(method, ref index, instanceFields, activeLocals,
                    depth + 1, ref budget, out var left, out diagnostic))
                return false;
            value = instruction.OpCode.Code switch
            {
                Code.Add => unchecked(left + right),
                Code.Sub => unchecked(left - right),
                Code.Xor => left ^ right,
                Code.And => left & right,
                Code.Or => left | right,
                Code.Mul => unchecked(left * right),
                Code.Shl => left << (right & 31),
                Code.Shr => left >> (right & 31),
                Code.Shr_Un => unchecked((int)((uint)left >> (right & 31))),
                _ => 0
            };
            return true;
        }
        return Failure(
            $"unsupported producer {instruction.OpCode.Code} at IL_{instruction.Offset:X4}",
            out diagnostic);
    }

    private static bool TryConsumeObject(
        MethodDef method,
        ref int index,
        int depth,
        ref int budget,
        out string diagnostic)
    {
        diagnostic = string.Empty;
        if (depth >= MaximumDepth || budget-- <= 0)
            return Failure("object slice bound was exceeded", out diagnostic);
        SkipNops(method, ref index);
        if (index < 0)
            return Failure("the object producer ran before method entry", out diagnostic);
        var instruction = method.Body.Instructions[index--];
        if (instruction.OpCode.Code is Code.Ldsfld or Code.Ldnull ||
            instruction.IsLdarg() || instruction.IsLdloc())
            return true;
        return Failure(
            $"unsupported object producer {instruction.OpCode.Code} at IL_{instruction.Offset:X4}",
            out diagnostic);
    }

    private static List<int> FindPriorLocalDefinitions(
        MethodDef method,
        int beforeIndex,
        int localIndex)
    {
        var definitions = new List<int>();
        for (var index = beforeIndex; index >= 0 &&
             beforeIndex - index < MaximumSliceInstructions; index--)
        {
            if (TryGetStoredLocal(method.Body.Instructions[index], out var candidate) &&
                candidate == localIndex)
                definitions.Add(index);
        }
        return definitions;
    }

    private static void SkipNops(MethodDef method, ref int index)
    {
        while (index >= 0 && method.Body.Instructions[index].OpCode.Code == Code.Nop)
            index--;
    }

    private static bool TryGetLoadedLocal(Instruction instruction, out int index)
    {
        index = instruction.OpCode.Code switch
        {
            Code.Ldloc_0 => 0,
            Code.Ldloc_1 => 1,
            Code.Ldloc_2 => 2,
            Code.Ldloc_3 => 3,
            Code.Ldloc or Code.Ldloc_S when instruction.Operand is Local local => local.Index,
            _ => -1
        };
        return index >= 0;
    }

    private static bool TryGetStoredLocal(Instruction instruction, out int index)
    {
        index = instruction.OpCode.Code switch
        {
            Code.Stloc_0 => 0,
            Code.Stloc_1 => 1,
            Code.Stloc_2 => 2,
            Code.Stloc_3 => 3,
            Code.Stloc or Code.Stloc_S when instruction.Operand is Local local => local.Index,
            _ => -1
        };
        return index >= 0;
    }

    private static bool Failure(string message, out string diagnostic)
    {
        diagnostic = message;
        return false;
    }
}
