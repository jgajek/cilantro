using System.Globalization;
using dnlib.DotNet;

namespace ReactorUnpack.Core.Interpretation;

/// <summary>
/// Hands out the attributes written on a member as objects a program can read.
/// </summary>
/// <remarks>
/// <para>
/// An attribute in a file is a constructor to call and a list of values to call it with, and the
/// runtime turns that into an object the first time somebody asks for it. Doing the same here is
/// how a library that is driven by attributes can be interpreted at all: a serializer asks each
/// type what it was annotated with and decides from the answers which fields go on the wire in
/// which order, and there is no way to reach its decisions except by giving it the annotations.
/// </para>
/// <para>
/// Everything in the answer comes out of the file. The constructor that runs is the one the
/// attribute's own metadata names, the arguments are the constants recorded next to it, and the
/// named values are assigned to the fields and properties they name. Nothing here supplies a
/// value the file did not, so an attribute whose type cannot be found or whose constructor cannot
/// be interpreted stops the call instead of producing an object that is missing what it was
/// written with.
/// </para>
/// <para>
/// Inheritance is answered from the base chain when the caller asks for it, and only when the
/// whole chain is present to read. A partial walk would report that a type carries no annotation
/// when the truth is that the annotation is on a base class in an assembly nobody supplied, and a
/// serializer told that would silently produce a different wire format.
/// </para>
/// </remarks>
internal static class AttributeModel
{
    /// <summary>
    /// The attributes on <paramref name="described"/>, as an array of constructed objects.
    /// </summary>
    /// <param name="context">The machine to build the objects in.</param>
    /// <param name="described">Metadata for the member being asked about.</param>
    /// <param name="inherit">Whether attributes on what the member inherits from count too.</param>
    /// <param name="ofType">The full name of the only attribute type wanted, if any.</param>
    public static IntrinsicResult Instances(
        IntrinsicContext context,
        object described,
        bool inherit,
        string? ofType)
    {
        if (context.Call is not { } call)
            return IntrinsicResult.Invalid("Attributes cannot be built without a way to call.");
        if (Holder(described) is null)
            return Framework(context, described, inherit, ofType);
        if (!TryCollect(described, inherit, out var written, out var refusal))
            return refusal;

        var heap = context.State.Heap;
        var wanted = ofType is null
            ? written
            : [.. written.Where(attribute => attribute.AttributeType?.FullName == ofType)];
        if (!heap.TryAllocateArray(null, wanted.Count, out var array))
            return IntrinsicResult.Invalid("Could not allocate the attribute array.");
        for (var index = 0; index < wanted.Count; index++)
        {
            var built = Build(context, call, wanted[index]);
            if (built.Status != StaticExecutionStatus.Completed)
                return built;
            if (!heap.TryWriteArray(array, index, built.Value))
                return IntrinsicResult.Invalid("Could not store a built attribute.");
        }

        return IntrinsicResult.Completed(array);
    }

    /// <summary>
    /// Whether <paramref name="described"/> carries an attribute of the named type.
    /// </summary>
    /// <remarks>
    /// This is the same question as the one above with the objects left unbuilt, and asking it
    /// this way means a member annotated with something whose constructor cannot be interpreted
    /// can still be reported as annotated, which is all the caller wanted to know.
    /// </remarks>
    public static IntrinsicResult Defines(
        IntrinsicContext context,
        object described,
        bool inherit,
        string ofType)
    {
        if (Holder(described) is null)
        {
            if (Present(context, described) is not { } present)
                return IntrinsicResult.Invalid(
                    $"{Spelling(described)} has no definition to read attributes from.");
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                Written(present, inherit).Any(item => item.AttributeType.FullName == ofType)
                    ? 1
                    : 0));
        }

        if (!TryCollect(described, inherit, out var written, out var refusal))
            return refusal;
        return IntrinsicResult.Completed(StaticValue.FromInt32(
            written.Any(attribute => attribute.AttributeType?.FullName == ofType) ? 1 : 0));
    }

    /// <summary>
    /// The attributes on a type nobody supplied a file for, read from the framework in hand.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A program that walks its own types reaches the framework's at the top of every chain and asks
    /// them the same questions. There is no file here to read the answer out of, and the framework
    /// this runs on has the same types the protected program was built against, so what it says a
    /// type is annotated with is the answer — read from its metadata without instantiating anything.
    /// </para>
    /// <para>
    /// What comes back is each attribute's type and nothing else. The values it was written with
    /// live in a framework constructor there is no body here to run, so an object is handed over
    /// that knows what it is and refuses to say more, which lets a program that is matching on the
    /// type carry on and stops one that wants the values.
    /// </para>
    /// </remarks>
    private static IntrinsicResult Framework(
        IntrinsicContext context,
        object described,
        bool inherit,
        string? ofType)
    {
        if (Present(context, described) is not { } present)
            return IntrinsicResult.Invalid(
                $"{Spelling(described)} has no definition to read attributes from.");
        var heap = context.State.Heap;
        var wanted = Written(present, inherit)
            .Where(item => ofType is null || item.AttributeType.FullName == ofType)
            .ToList();
        if (!heap.TryAllocateArray(null, wanted.Count, out var array))
            return IntrinsicResult.Invalid("Could not allocate the attribute array.");
        for (var index = 0; index < wanted.Count; index++)
        {
            if (wanted[index].AttributeType.FullName is not { } named ||
                !heap.TryAllocateObject(named, out var instance) ||
                !heap.TryWriteArray(array, index, instance))
            {
                return IntrinsicResult.Invalid("Could not model an attribute.");
            }
        }

        return IntrinsicResult.Completed(array);
    }

    private static IEnumerable<System.Reflection.CustomAttributeData> Written(
        Type present,
        bool inherit)
    {
        for (var type = present; type is not null; type = inherit ? type.BaseType : null)
        {
            foreach (var written in type.GetCustomAttributesData())
            {
                if (type == present || Inheritable(written))
                    yield return written;
            }
        }
    }

    /// <summary>Whether a framework attribute is one a derived type would also report.</summary>
    private static bool Inheritable(System.Reflection.CustomAttributeData written) =>
        written.AttributeType.GetCustomAttributes(typeof(AttributeUsageAttribute), false)
            .OfType<AttributeUsageAttribute>()
            .All(usage => usage.Inherited);

    /// <summary>The framework type a described type names, where the framework in hand has one.</summary>
    /// <remarks>
    /// A generic constructed over a type from a file is not a type the framework can be handed, and
    /// what it is annotated with is what its declaration is annotated with, so the declaration is
    /// what answers for it.
    /// </remarks>
    private static Type? Present(IntrinsicContext context, object described)
    {
        var spelled = described switch
        {
            IType named => named.FullName,
            string name => name,
            _ => null
        };
        if (spelled is null)
            return null;
        var subject = context.State.ModuleMetadata;
        return LoaderFrameworkIntrinsic.WellKnown(spelled, subject) ??
            LoaderFrameworkIntrinsic.Declaring(spelled, subject);
    }

    private static string Spelling(object described) =>
        described is IType named ? named.FullName : described.ToString() ?? "the member";

    /// <summary>
    /// Gathers what is written on a member, walking what it inherits from when asked to.
    /// </summary>
    private static bool TryCollect(
        object described,
        bool inherit,
        out List<CustomAttribute> written,
        out IntrinsicResult refusal)
    {
        written = [];
        refusal = IntrinsicResult.Completed();
        var holder = Holder(described);
        if (holder is null)
        {
            refusal = IntrinsicResult.Invalid(
                $"{described} has no definition to read attributes from.");
            return false;
        }

        written.AddRange(holder.CustomAttributes);
        if (!inherit)
            return true;

        // Only a type's base chain and a method's overrides inherit anything; a field or a
        // parameter has nothing above it, so asking to inherit there changes no answer.
        if (holder is not TypeDef type)
            return true;

        for (var above = type.BaseType; above is not null;)
        {
            if (above.ResolveTypeDef() is not { } resolved)
            {
                refusal = IntrinsicResult.Invalid(
                    $"{type.FullName} inherits from {above.FullName}, which is not available, so" +
                    " what it inherits cannot be read.");
                return false;
            }

            // The runtime only carries an attribute down when the attribute says it may, and only
            // one of each kind when it says it does not permit several.
            foreach (var candidate in resolved.CustomAttributes)
            {
                if (!Inheritable(candidate, out var multiple))
                    continue;
                if (!multiple && written.Any(seen =>
                        seen.AttributeType?.FullName == candidate.AttributeType?.FullName))
                {
                    continue;
                }

                written.Add(candidate);
            }

            above = resolved.BaseType;
        }

        return true;
    }

    /// <summary>
    /// What a piece of metadata's attributes hang off, following it to its definition if need be.
    /// </summary>
    private static IHasCustomAttribute? Holder(object described) => described switch
    {
        TypeDef or MethodDef or FieldDef or PropertyDef or EventDef or ParamDef or ModuleDef
            or AssemblyDef => (IHasCustomAttribute)described,
        MemberRef { IsMethodRef: true } method => method.ResolveMethod() as IHasCustomAttribute,
        MemberRef { IsFieldRef: true } field => field.ResolveField(),
        Parameter { ParamDef: { } declared } => declared,
        ITypeDefOrRef reference => reference.ResolveTypeDef(),
        TypeSig signature => signature.ToTypeDefOrRef()?.ResolveTypeDef(),
        _ => null
    };

    /// <summary>
    /// Reads an attribute's own usage rules, which decide whether a derived type sees it.
    /// </summary>
    /// <remarks>
    /// The defaults are the framework's: an attribute is inherited unless it says otherwise, and
    /// only one of a kind may appear unless it says otherwise. When the attribute type itself is
    /// unavailable the rules cannot be read, and the safe reading is the one that does not invent
    /// an annotation on a derived type, so it is left behind.
    /// </remarks>
    private static bool Inheritable(CustomAttribute attribute, out bool multiple)
    {
        multiple = false;
        if (attribute.AttributeType?.ResolveTypeDef() is not { } declared)
            return false;
        var usage = declared.CustomAttributes
            .FirstOrDefault(item => item.AttributeType?.FullName == "System.AttributeUsageAttribute");
        if (usage is null)
            return true;
        var inherited = true;
        foreach (var named in usage.NamedArguments)
        {
            if (named.Argument.Value is not bool flag)
                continue;
            if (named.Name == "Inherited")
                inherited = flag;
            else if (named.Name == "AllowMultiple")
                multiple = flag;
        }

        return inherited;
    }

    /// <summary>
    /// Builds one attribute by running its constructor and then assigning what it was named with.
    /// </summary>
    private static IntrinsicResult Build(
        IntrinsicContext context,
        MethodInvoker call,
        CustomAttribute attribute)
    {
        var heap = context.State.Heap;
        if (attribute.AttributeType?.ResolveTypeDef() is not { } declared)
        {
            // The file names the attribute's type even when no file defines it, so what is here is
            // an attribute of a known type whose values live in a constructor there is no body to
            // run. Handing over an object that knows what it is lets a program matching on the type
            // carry on, and one that wants the values is refused where it asks for them.
            if (attribute.AttributeType?.FullName is not { } named ||
                !heap.TryAllocateObject(named, out var bare))
                return IntrinsicResult.Invalid(
                    $"The attribute type {attribute.AttributeType?.FullName} cannot be modeled.");
            return IntrinsicResult.Completed(bare);
        }
        if (attribute.Constructor?.ResolveMethodDef() is not { } constructor)
            return IntrinsicResult.Invalid(
                $"The constructor of {declared.FullName} is not available.");
        if (!heap.TryAllocateObject(declared.FullName, out var instance))
            return IntrinsicResult.Invalid($"Could not allocate a {declared.FullName}.");
        heap.TrySetModelValue(instance, "Metadata", declared);

        var supplied = new List<StaticValue> { instance };
        foreach (var argument in attribute.ConstructorArguments)
        {
            if (!TryValue(context, argument, out var value))
                return IntrinsicResult.Invalid(
                    $"An argument of {declared.FullName} is written as something unmodeled" +
                    $" ({argument.Type?.FullName}).");
            supplied.Add(value);
        }

        var constructed = call(constructor, supplied);
        if (constructed.Status != StaticExecutionStatus.Completed)
            return constructed;

        foreach (var named in attribute.NamedArguments)
        {
            if (!TryValue(context, named.Argument, out var value))
                return IntrinsicResult.Invalid(
                    $"{declared.FullName}.{named.Name} is written as something unmodeled" +
                    $" ({named.Argument.Type?.FullName}).");
            var assigned = Assign(context, call, declared, instance, named, value);
            if (assigned.Status != StaticExecutionStatus.Completed)
                return assigned;
        }

        return IntrinsicResult.Completed(instance);
    }

    /// <summary>
    /// Stores a named value where the attribute says it goes, through a setter when there is one.
    /// </summary>
    /// <remarks>
    /// A named property is set by calling its setter rather than by writing behind it, because a
    /// setter can do work — validate, normalise, set a second field that says it was set — and the
    /// object the caller goes on to read is only right if that work happened.
    /// </remarks>
    private static IntrinsicResult Assign(
        IntrinsicContext context,
        MethodInvoker call,
        TypeDef declared,
        StaticValue instance,
        CANamedArgument named,
        StaticValue value)
    {
        var wanted = named.Name.String;
        for (var type = declared; type is not null; type = type.BaseType?.ResolveTypeDef())
        {
            if (named.IsField)
            {
                if (type.FindField(wanted) is not { } field)
                    continue;
                return context.State.Heap.TryWriteField(instance, field, value)
                    ? IntrinsicResult.Completed()
                    : IntrinsicResult.Invalid($"{declared.FullName}.{wanted} could not be set.");
            }

            if (type.FindProperty(wanted) is not { SetMethod: { } setter })
                continue;
            return call(setter, [instance, value]);
        }

        return IntrinsicResult.Invalid(
            $"{declared.FullName} has no {(named.IsField ? "field" : "property")} named {wanted}.");
    }

    /// <summary>
    /// The value an attribute argument stands for, in the machine's own terms.
    /// </summary>
    /// <remarks>
    /// The recorded forms are the ones the format allows: the primitives, a string, a type, an
    /// enumeration value written as its underlying number, and an array of any of those. A boxed
    /// argument carries its own type alongside the value, and it is boxed here for the same reason
    /// the runtime boxes it — the field it lands in is declared as an object.
    /// </remarks>
    private static bool TryValue(
        IntrinsicContext context,
        CAArgument argument,
        out StaticValue value)
    {
        var heap = context.State.Heap;
        value = StaticValue.Null;
        switch (argument.Value)
        {
            case null:
                return true;
            case bool flag:
                value = StaticValue.FromInt32(flag ? 1 : 0);
                return true;
            case char character:
                value = StaticValue.FromInt32(character);
                return true;
            case sbyte or byte or short or ushort or int:
                value = StaticValue.FromInt32(Convert.ToInt32(
                    argument.Value,
                    CultureInfo.InvariantCulture));
                return true;
            case uint number:
                value = StaticValue.FromInt32(unchecked((int)number));
                return true;
            case long or ulong:
                value = StaticValue.FromInt64(unchecked((long)Convert.ToUInt64(
                    argument.Value,
                    CultureInfo.InvariantCulture)));
                return true;
            case float single:
                value = StaticValue.FromFloat32(single);
                return true;
            case double every:
                value = StaticValue.FromFloat64(every);
                return true;
            case UTF8String text:
                return heap.TryAllocateString(text.String, out value);
            case string text:
                return heap.TryAllocateString(text, out value);
            case TypeSig named:
            {
                if (!heap.TryAllocateType(named.FullName, out value))
                    return false;
                heap.TrySetModelValue(value, "Metadata", named);
                return true;
            }

            case IList<CAArgument> elements:
            {
                var element = (argument.Type as SZArraySig)?.Next;
                if (!heap.TryAllocateArray(element, elements.Count, out value))
                    return false;
                for (var index = 0; index < elements.Count; index++)
                {
                    if (!TryValue(context, elements[index], out var item) ||
                        !heap.TryWriteArray(value, index, item))
                    {
                        return false;
                    }
                }

                return true;
            }

            case CAArgument boxed:
            {
                if (!TryValue(context, boxed, out var inner))
                    return false;
                if (boxed.Type?.IsPrimitive != true ||
                    inner.Kind == StaticValueKind.HeapReference)
                {
                    value = inner;
                    return true;
                }

                return heap.TryAllocateBox(boxed.Type.FullName, inner, out value);
            }

            default:
                return false;
        }
    }
}
