using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>
/// Finds the date-based trial guards a Reactor loader injects, so an interpretation can pass them
/// the way a registered copy would rather than tripping on the clock the run injected.
/// </summary>
/// <remarks>
/// A trial guard reads the wall clock, subtracts an instant baked into the assembly, and throws when
/// the gap is wider than the trial it allows. Nothing about that is a behaviour of the program a
/// paid-up copy runs: the throw is reached only because the interpreter hands the clock an arbitrary
/// fixed instant, which for any real build sits years from the baked-in date. Left to run, the guard
/// ends the interpretation two operations into the loader and takes the string table down with it.
///
/// The shape proven here is narrow on purpose. A guard is an argument-free <c>static void</c> method
/// that both reads the host clock and constructs a <see cref="System.DateTime"/> from constants, and
/// then throws. The clock read is usually behind one of the module's delegate proxies, so the proxy
/// map is consulted to see through it; the constant instant and the throw are in the method's own
/// body. Requiring all three keeps an ordinary method that merely reads the time, or merely throws,
/// from being mistaken for a guard. What is returned is only ever neutralised in interpretation, so
/// a false positive costs a skipped call in a recovery run and never an edit to the module.
/// </remarks>
public static class TrialGuardAnalysis
{
    private static readonly HashSet<string> ClockReads = new(StringComparer.Ordinal)
    {
        "System.DateTime System.DateTime::get_Now()",
        "System.DateTime System.DateTime::get_UtcNow()",
        "System.DateTime System.DateTime::get_Today()",
    };

    /// <summary>
    /// The method tokens of every date-based trial guard the module contains, seeing through the
    /// given proxy bindings to the clock reads they hide.
    /// </summary>
    public static HashSet<uint> Find(
        ModuleDef module,
        IReadOnlyList<(uint FieldToken, uint TargetToken)> proxies)
    {
        ArgumentNullException.ThrowIfNull(module);
        var clockProxies = new HashSet<uint>();
        foreach (var (fieldToken, targetToken) in proxies ?? [])
        {
            if (module.ResolveToken(targetToken) is IMethod target &&
                ClockReads.Contains(target.FullName))
            {
                clockProxies.Add(fieldToken);
            }
        }

        var found = new HashSet<uint>();
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
        {
            if (IsGuard(method, clockProxies))
                found.Add(method.MDToken.Raw);
        }
        return found;
    }

    private static bool IsGuard(MethodDef method, HashSet<uint> clockProxies)
    {
        if (!method.IsStatic ||
            method.MethodSig?.Params.Count != 0 ||
            method.ReturnType.ElementType != ElementType.Void ||
            !method.HasBody)
        {
            return false;
        }

        var readsClock = false;
        var buildsInstant = false;
        var throws = false;
        foreach (var instruction in method.Body.Instructions)
        {
            switch (instruction.OpCode.Code)
            {
                case Code.Ldsfld or Code.Ldsflda
                    when instruction.Operand is IField field &&
                        clockProxies.Contains(field.MDToken.Raw):
                    readsClock = true;
                    break;
                case Code.Call or Code.Callvirt
                    when instruction.Operand is IMethod called &&
                        ClockReads.Contains(called.FullName):
                    readsClock = true;
                    break;
                case Code.Newobj
                    when instruction.Operand is IMethod made &&
                        made.DeclaringType?.FullName == "System.DateTime":
                    buildsInstant = true;
                    break;
                case Code.Throw:
                    throws = true;
                    break;
            }
        }

        return readsClock && buildsInstant && throws;
    }
}
