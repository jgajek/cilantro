using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Proxy;

/// <summary>
/// Puts back the narrowing a proxy adapter was doing, once the call goes straight to its target.
/// </summary>
/// <remarks>
/// Reactor's adapters are written against `object` where the target wants something in particular:
/// a call to `ILGenerator::Emit(OpCode)` reaches its adapter as `XheaEjYKBi(object, OpCode, ...)`,
/// and the method holding the call site has often had its own parameter widened to `object` to
/// match. The adapter is what makes that verifiable — the delegate behind it has the real signature,
/// so the conversion happens on the way in — and replacing the adapter call with a direct one takes
/// the conversion away with it. The result runs, since the value really is of the target's type, and
/// no verifier accepts it: `StackUnexpected`, on twenty-five methods of one payload.
///
/// So the conversion is emitted where the adapter was doing it. A `castclass` throws exactly where
/// the delegate's own invocation would have thrown, which makes this a substitution rather than an
/// assumption. Where the value the target wants is deeper on the stack than the top, the arguments
/// above it are put into temporaries and pushed straight back, which is the only way to reach it.
/// </remarks>
/// <summary>
/// A call site whose adapter has been bypassed, and the conversion that owes it.
/// </summary>
public sealed record ProxyNarrowingSite(
    MethodDef Method,
    Instruction Call,
    ProxyArgumentNarrowing.Reconciliation Narrowing);

public static class ProxyArgumentNarrowing
{
    /// <summary>One argument of a call site, and the conversion that reconciles it.</summary>
    public sealed record Conversion(int Position, OpCode How, ITypeDefOrRef Operand);

    /// <summary>
    /// What a direct call needs doing to its arguments: what each is standing on the stack as, and
    /// which of them the target wants narrower.
    /// </summary>
    public sealed record Reconciliation(
        IReadOnlyList<TypeSig> Given,
        IReadOnlyList<Conversion> Conversions);

    /// <summary>
    /// What the direct call needs doing to its arguments, or null where the adapter cannot be
    /// bypassed at all.
    /// </summary>
    /// <remarks>
    /// The widening runs both ways. Where the adapter took an object and the target wants something
    /// in particular, the conversion the adapter was doing has to be put back. Where the adapter
    /// took the particular thing and the target's own parameter is an object — which is most of
    /// what one payload's eighty-eight remaining sites turned out to be — nothing needs emitting for
    /// a reference and a box for a value, since widening to object is what the stack already does.
    ///
    /// Null is a refusal rather than a failure: the site keeps its adapter and stays as Reactor
    /// wrote it, which is worse to read and no less correct. It is returned where the adapter's
    /// parameters do not line up with the target's one for one, and where neither side of a
    /// difference is an object — a byref against a value, a pointer, a generic parameter — none of
    /// which a conversion in front of the call can reconcile.
    /// </remarks>
    public static Reconciliation? Plan(MethodDef adapter, IMethod target)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(target);
        if (target.MethodSig is not { } signature ||
            adapter.MethodSig is not { } adapterSignature ||
            !adapter.IsStatic)
        {
            return null;
        }

        // The adapter's last parameter is the proxy type itself, which the call site loads and the
        // rewrite drops; everything before it is an argument the target is getting.
        var given = adapterSignature.Params.SkipLast(1).ToArray();

        var wanted = new List<TypeSig>();
        if (signature.HasThis)
        {
            if (target.DeclaringType?.ToTypeSig() is not { } receiver)
                return null;

            // An instance call on a value type is made through a managed pointer to it, and the
            // adapter standing in for one takes that pointer rather than the value: the seventeen
            // sites of one probe that reach `Int32::ToString` do so through an `int32&`. Asking for
            // the value there would refuse every one of them over a difference that is not one.
            //
            // Whether it is a value type is answerable on sight for the corlib primitives, and for
            // anything else only if the reference resolves. Where it does not — `TimeSpan` and
            // `RuntimeMethodHandle`, on that same probe — the adapter having taken the receiver by
            // reference is itself the answer, nothing passing a class that way.
            var byReference = new ByRefSig(receiver);
            wanted.Add(
                IsValue(receiver) || (given.Length != 0 && given[0]?.FullName == byReference.FullName)
                    ? byReference
                    : receiver);
        }
        wanted.AddRange(signature.Params);
        if (given.Length != wanted.Count)
            return null;

        var conversions = new List<Conversion>();
        for (var position = 0; position < given.Length; position++)
        {
            var have = given[position];
            var want = wanted[position];
            if (have is null || want is null)
                return null;
            if (have.FullName == want.FullName)
                continue;
            if (have.IsByRef || have.IsPointer || have.IsGenericParameter ||
                want.IsByRef || want.IsPointer || want.IsGenericParameter)
            {
                return null;
            }

            if (want.FullName == "System.Object")
            {
                if (!IsValue(have))
                    continue;
                conversions.Add(new Conversion(position, OpCodes.Box, have.ToTypeDefOrRef()));
                continue;
            }
            if (have.FullName != "System.Object")
                return null;

            conversions.Add(new Conversion(
                position,
                IsValue(want) ? OpCodes.Unbox_Any : OpCodes.Castclass,
                want.ToTypeDefOrRef()));
        }

        return new Reconciliation(given, conversions);
    }

    /// <summary>
    /// Whether a type is one whose values live on the stack rather than as references to a heap.
    /// </summary>
    /// <remarks>
    /// Answerable on sight for the corlib primitives, and otherwise only where the reference
    /// resolves; a reference that does not is read as a class, which is what it usually is.
    /// </remarks>
    private static bool IsValue(TypeSig type) =>
        type.IsValueType || type.ToTypeDefOrRef()?.ResolveTypeDef()?.IsValueType == true;

    /// <summary>
    /// Emits the conversions in front of the call, spilling only as far down the stack as it must.
    /// </summary>
    public static void Apply(MethodDef method, Instruction call, Reconciliation narrowing)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(call);
        ArgumentNullException.ThrowIfNull(narrowing);
        if (narrowing.Conversions.Count == 0)
            return;

        var instructions = method.Body.Instructions;
        var at = instructions.IndexOf(call);
        if (at < 0)
            throw new ArgumentException("The call is not in the method it is being narrowed in.");

        var conversions = narrowing.Conversions.ToDictionary(conversion => conversion.Position);
        var deepest = narrowing.Conversions.Min(conversion => conversion.Position);
        var emitted = new List<Instruction>();

        // The argument on top of the stack is the last one, and needs no room made for it. Anything
        // above the deepest conversion comes off so that conversion can be reached, and goes back
        // in the order it came off.
        var spilled = new List<(int Position, Local Slot)>();
        for (var position = narrowing.Given.Count - 1; position > deepest; position--)
        {
            var slot = new Local(narrowing.Given[position]);
            method.Body.Variables.Add(slot);

            // A method that had no locals to zero was under no obligation to say it zeroed them,
            // and giving it one without saying so is unverifiable however little the temporary is
            // read before it is written (ECMA-335 III.1.8.1.1).
            method.Body.InitLocals = true;
            spilled.Add((position, slot));
            emitted.Add(OpCodes.Stloc.ToInstruction(slot));
        }

        Convert(deepest);
        for (var index = spilled.Count - 1; index >= 0; index--)
        {
            emitted.Add(OpCodes.Ldloc.ToInstruction(spilled[index].Slot));
            Convert(spilled[index].Position);
        }

        for (var index = 0; index < emitted.Count; index++)
            instructions.Insert(at + index, emitted[index]);
        method.Body.UpdateInstructionOffsets();
        return;

        void Convert(int position)
        {
            if (!conversions.TryGetValue(position, out var conversion))
                return;
            emitted.Add(new Instruction(conversion.How, conversion.Operand));
        }
    }
}
