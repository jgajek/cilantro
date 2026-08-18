using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Strings;

/// <summary>
/// Resolves the closure of thin forwarders that stand in for a protected value resolver.
/// </summary>
/// <remarks>
/// Reactor does not always call its resolver directly. Some call sites go through a generated
/// forwarder whose entire body is <c>ldarg.0; call resolver; ret</c>, which hides the real
/// argument one frame up and leaves the offset as a parameter that no local slice can prove.
/// Treating such a forwarder as an alias of the resolver moves the proof back to the sites that
/// supply a concrete offset.
///
/// Only shapes that are provably pass-through qualify: one integer parameter that is loaded
/// exactly once, a single call to an already-known alias, no exception handlers, and no other
/// observable behavior. Anything else stays outside the set, so its call sites remain unproven
/// rather than being rewritten on an assumption.
/// </remarks>
public static class ResolverAliasAnalysis
{
    public static IReadOnlyCollection<MethodDef> Resolve(ModuleDef module, MethodDef resolver)
    {
        var members = new HashSet<MethodDef> { resolver };
        var candidates = module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method != resolver && IsForwarderShape(method))
            .ToArray();
        // A forwarder may target another forwarder, so grow the set until it stops changing.
        bool added;
        do
        {
            added = false;
            foreach (var candidate in candidates)
            {
                if (members.Contains(candidate))
                    continue;
                if (!TryGetForwardedTarget(candidate, out var target) || !members.Contains(target))
                    continue;
                members.Add(candidate);
                added = true;
            }
        } while (added);
        return members;
    }

    /// <summary>
    /// Enumerates the call sites that must be proven, which excludes the forwarding call inside
    /// each alias because its argument is the alias's own parameter.
    /// </summary>
    public static bool IsInternalForwardingCall(
        MethodDef containingMethod,
        IReadOnlyCollection<MethodDef> aliasSet) =>
        aliasSet.Contains(containingMethod);

    private static bool IsForwarderShape(MethodDef method) =>
        method.HasBody &&
        method.IsStatic &&
        method.Body.ExceptionHandlers.Count == 0 &&
        method.MethodSig?.Params.Count == 1 &&
        method.MethodSig.Params[0].ElementType == ElementType.I4 &&
        method.ReturnType.ElementType is ElementType.String or ElementType.Object;

    private static bool TryGetForwardedTarget(MethodDef method, out MethodDef target)
    {
        target = null!;
        if (!IsForwarderShape(method))
            return false;

        var meaningful = method.Body.Instructions
            .Where(instruction => instruction.OpCode.Code != Code.Nop)
            .ToArray();
        if (meaningful.Length < 3 || meaningful[^1].OpCode.Code != Code.Ret)
            return false;
        if (!IsLoadOfOnlyArgument(meaningful[0], method))
            return false;
        if (meaningful[1].OpCode.Code is not (Code.Call or Code.Callvirt) ||
            meaningful[1].Operand is not IMethod called ||
            called.ResolveMethodDef() is not { } resolved)
            return false;
        // Between the call and the return only a reference-preserving cast is tolerated.
        for (var index = 2; index < meaningful.Length - 1; index++)
        {
            if (meaningful[index].OpCode.Code is not (Code.Castclass or Code.Isinst))
                return false;
        }
        // The parameter must not be read anywhere else, otherwise the body is doing more than
        // forwarding and the argument cannot be attributed to the single call.
        var argumentLoads = method.Body.Instructions
            .Count(instruction => IsLoadOfOnlyArgument(instruction, method));
        if (argumentLoads != 1)
            return false;
        target = resolved;
        return true;
    }

    private static bool IsLoadOfOnlyArgument(Instruction instruction, MethodDef method) =>
        instruction.OpCode.Code switch
        {
            Code.Ldarg_0 => true,
            Code.Ldarg or Code.Ldarg_S =>
                instruction.Operand is Parameter parameter &&
                parameter.Index == method.Parameters[0].Index,
            _ => false
        };
}
