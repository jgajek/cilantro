using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Passes;

/// <summary>
/// Replaces calls to helpers that answer the same thing every time with the answer.
/// </summary>
/// <remarks>
/// Shared rather than owned by one pass because the same folding is wanted twice, at two different
/// points in a run. Most of it happens early, where collapsing Reactor's opaque predicates is what
/// lets the control-flow passes see the branches underneath. The rest cannot happen until much
/// later: a body built back from a virtualized method does not exist until the rebuild, by which
/// time every folding pass has been and gone, so that body arrives full of calls to helpers the
/// rest of the assembly stopped calling a long time earlier.
/// </remarks>
internal static class ConstantHelperFolding
{
    /// <summary>Finds every method in the module that is really a constant.</summary>
    internal static IReadOnlyDictionary<uint, MethodBehaviour.Constant> Catalog(ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(module);
        return module.GetTypes()
            .SelectMany(type => type.Methods)
            .Select(method => (Method: method, Value: MethodBehaviour.AsConstant(method)))
            .Where(item => item.Value is not null)
            .ToDictionary(item => item.Method.MDToken.Raw, item => item.Value!.Value);
    }

    /// <summary>
    /// Rewrites every call to a cataloged constant helper in the given bodies, capturing each
    /// instruction so the caller can put the whole thing back if verification refuses it.
    /// </summary>
    internal static int Fold(
        IEnumerable<MethodDef> bodies,
        IReadOnlyDictionary<uint, MethodBehaviour.Constant> catalog,
        InstructionMutationTransaction transaction,
        Action<MethodDef, Instruction, MethodBehaviour.Constant> record)
    {
        ArgumentNullException.ThrowIfNull(bodies);
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(record);

        var folded = 0;
        foreach (var method in bodies.Where(method => method.HasBody))
        {
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.OpCode.FlowControl != FlowControl.Call ||
                    instruction.Operand is not IMethod called ||
                    !catalog.TryGetValue(called.MDToken.Raw, out var value))
                {
                    continue;
                }

                transaction.Capture(instruction);
                instruction.OpCode = value switch
                {
                    MethodBehaviour.Constant.True => OpCodes.Ldc_I4_1,
                    MethodBehaviour.Constant.False => OpCodes.Ldc_I4_0,
                    MethodBehaviour.Constant.Null => OpCodes.Ldnull,
                    _ => instruction.OpCode
                };
                instruction.Operand = null;
                folded++;
                record(method, instruction, value);
            }
        }

        return folded;
    }
}
