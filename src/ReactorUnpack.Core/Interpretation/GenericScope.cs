using dnlib.DotNet;

namespace ReactorUnpack.Core.Interpretation;

/// <summary>
/// What the generic parameters of the method being interpreted stand for.
/// </summary>
/// <remarks>
/// <para>
/// A generic method's body names its parameters rather than the types they were given: the body of
/// <c>Deserialize&lt;T&gt;</c> says <c>typeof(T)</c>, and which type that is was decided at the call
/// site and recorded there. Without carrying the decision into the frame, the machine reaches a type
/// called "T" that has no definition anywhere and can answer nothing about itself, which stops the
/// interpretation on code that is doing nothing unusual — every generic helper that reflects over its
/// own parameter, and every serializer reached through one.
/// </para>
/// <para>
/// So a frame knows what its parameters stand for, and a call resolves the arguments it passes
/// through the scope it is making them in: a helper that forwards its own <c>T</c> to another generic
/// method passes on the type it was given rather than the name it knows it by. A call whose target
/// takes no parameters of its own produces no scope, because a frame that inherited its caller's
/// would substitute its caller's types into names that mean something else.
/// </para>
/// </remarks>
internal sealed record GenericScope(IList<TypeSig>? Type, IList<TypeSig>? Method)
{
    /// <summary>
    /// The scope a call into <paramref name="target"/> runs under, seen from
    /// <paramref name="enclosing"/>.
    /// </summary>
    public static GenericScope? For(IMethod? target, GenericScope? enclosing)
    {
        var type = target?.DeclaringType is TypeSpec { TypeSig: GenericInstSig owner }
            ? Bind(owner.GenericArguments, enclosing)
            : null;
        var method = target is MethodSpec { GenericInstMethodSig: { } instantiation }
            ? Bind(instantiation.GenericArguments, enclosing)
            : null;
        return type is null && method is null ? null : new GenericScope(type, method);
    }

    /// <summary>
    /// The type this signature names once its generic parameters are what they stand for, or the
    /// signature unchanged when it names none.
    /// </summary>
    public TypeSig? Bind(TypeSig? signature) =>
        signature is null || !signature.ContainsGenericParameter
            ? signature
            : Substitute(signature);

    private static IList<TypeSig>? Bind(IList<TypeSig>? arguments, GenericScope? enclosing)
    {
        if (arguments is null || arguments.Count == 0)
            return null;
        if (enclosing is null)
            return arguments;
        return [.. arguments.Select(argument => enclosing.Bind(argument) ?? argument)];
    }

    /// <summary>
    /// Rewrites a signature with the parameters replaced, keeping everything wrapped around them.
    /// </summary>
    /// <remarks>
    /// A parameter can sit anywhere in a signature — an array of it, a reference to it, another
    /// generic type over it — so the rewrite follows the shape rather than looking only at the top.
    /// A shape not handled here is left alone, which leaves the interpretation where it would have
    /// been without any of this rather than putting a wrong type in its way.
    /// </remarks>
    private TypeSig? Substitute(TypeSig signature) => signature switch
    {
        GenericMVar parameter => At(Method, parameter.Number) ?? signature,
        GenericVar parameter => At(Type, parameter.Number) ?? signature,
        SZArraySig array when Bind(array.Next) is { } element => new SZArraySig(element),
        ArraySig array when Bind(array.Next) is { } element =>
            new ArraySig(element, array.Rank, array.Sizes, array.LowerBounds),
        ByRefSig reference when Bind(reference.Next) is { } referenced =>
            new ByRefSig(referenced),
        PtrSig pointer when Bind(pointer.Next) is { } pointed => new PtrSig(pointed),
        PinnedSig pinned when Bind(pinned.Next) is { } held => new PinnedSig(held),
        GenericInstSig instance => Rebuild(instance),
        _ => signature
    };

    private GenericInstSig Rebuild(GenericInstSig instance)
    {
        var arguments = instance.GenericArguments
            .Select(argument => Bind(argument) ?? argument)
            .ToList();
        return new GenericInstSig(instance.GenericType, arguments);
    }

    private static TypeSig? At(IList<TypeSig>? arguments, uint number) =>
        arguments is not null && number < arguments.Count ? arguments[(int)number] : null;
}
