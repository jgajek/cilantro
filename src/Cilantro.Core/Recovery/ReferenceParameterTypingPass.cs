using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Restores erased reference stack types from unanimous closed callers.</summary>
public sealed class ReferenceParameterTypingPass : ArrayParameterTypingPass
{
    public override string Name => "reference-parameter-typing";
    public override IReadOnlyCollection<string> Dependencies => ["array-parameter-typing"];
    protected override string TypeLabel => "reference";
    protected override string ChangeKind => "restore-reference-parameter-stack-type";

    protected override TypeSig PreferConsumerType(Parameter parameter, TypeSig common, IReadOnlyList<TypeSig> inputs)
    {
        // Two concrete subclasses can share both a base class and an interface
        // which that base does not implement. Consumer signatures propose the
        // interface; every closed caller/writer must independently prove it.
        var method = parameter.Method;
        var il = method.Body.Instructions;
        TypeSig? wanted = null;
        for (var n = 0; n < il.Count; n++)
        {
            if (!il[n].IsLdarg() || il[n].GetParameter(method.Parameters) != parameter) continue;
            var at = n + 1;
            while (at < il.Count && il[at].OpCode.Code is Code.Nop or Code.Castclass) at++;
            if (at == il.Count || il[at].OpCode.Code is not (Code.Call or Code.Callvirt or Code.Newobj) ||
                il[at].Operand is not IMethod called || called.MethodSig is not { } signature) return common;
            var expected = signature.Params.Count > 0 ? signature.Params[^1] :
                signature.HasThis && il[at].OpCode.Code != Code.Newobj ? called.DeclaringType.ToTypeSig() : null;
            if (expected is null || expected.ContainsGenericParameter ||
                expected.ToTypeDefOrRef()?.ResolveTypeDef() is not { IsInterface: true, HasGenericParameters: false } ||
                wanted is not null && !new SigComparer().Equals(wanted, expected)) return common;
            wanted = expected;
        }
        if (wanted is not null && Ancestors(common).Any(type => new SigComparer().Equals(type, wanted))) return common;
        return wanted is not null && inputs.Count > 0 && inputs.All(input =>
            Ancestors(input).Any(type => new SigComparer().Equals(type, wanted))) ? wanted : common;
    }

    protected override bool AcceptsType(TypeSig type) =>
        type.ElementType == ElementType.String || type is ClassSig ||
        type is GenericInstSig { GenericType: ClassSig, ContainsGenericParameter: false };

    protected override TypeSig? MergeTypes(TypeSig first, TypeSig second)
    {
        if (base.MergeTypes(first, second) is { } exact) return exact;
        var other = Ancestors(second).ToArray();
        return Ancestors(first).FirstOrDefault(candidate => other.Any(type => new SigComparer().Equals(candidate, type)));
    }

    internal static IEnumerable<TypeSig> Ancestors(TypeSig source)
    {
        var seen = new HashSet<ITypeDefOrRef>();
        var pending = new Queue<TypeSig>();
        pending.Enqueue(source);
        while (pending.Count != 0 && seen.Count < 128)
        {
            var type = pending.Dequeue();
            if (type.ContainsGenericParameter || type.FullName == "System.Object" ||
                type.ToTypeDefOrRef() is not { } reference || reference is TypeSpec || !seen.Add(reference) ||
                type is not ClassSig && type.ElementType != ElementType.String) continue;
            yield return type;
            if (reference.ResolveTypeDef() is not { IsValueType: false, HasGenericParameters: false } definition) continue;
            if (definition.BaseType is { } parent) pending.Enqueue(parent.ToTypeSig());
            // Implemented interfaces are guaranteed receiver types too. Follow only
            // closed, non-generic declarations; substitutions need separate proof.
            foreach (var implemented in definition.Interfaces)
                pending.Enqueue(implemented.Interface.ToTypeSig());
        }
    }

    protected override bool ConsumesRecoveredType(MethodDef method) =>
        method.Body.Variables.Any(v => AcceptsType(v.Type)) || AcceptsType(method.ReturnType) ||
        method.Body.Instructions.Any(i =>
            i.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj &&
            i.Operand is IMethod call && call.MethodSig is { } signature &&
            (signature.Params.Any(AcceptsType) || i.OpCode.Code != Code.Newobj && signature.HasThis &&
                AcceptsType(call.DeclaringType.ToTypeSig())) ||
            i.OpCode.Code is Code.Ldfld or Code.Ldflda or Code.Stfld && i.Operand is IField field &&
                AcceptsType(field.DeclaringType.ToTypeSig()));
}
