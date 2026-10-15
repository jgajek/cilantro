using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Collects exact allocations stored in a private readonly instance field by
/// directly called constructors. This is an observed IL-use proof; callers must separately
/// close reflection, serialization, external construction and field-owner exposure.</summary>
internal static class ReadonlyConstructorValues
{
    internal sealed record Construction(IMethod Constructor, TypeSig ValueType);
    internal sealed record Result(bool Proven, IReadOnlyList<TypeSig> Types, string Reason)
    {
        internal IReadOnlyList<Construction> Constructions { get; init; } = [];
    }
    internal static Result Analyze(FieldDef field)
    {
        Result Failed([System.Runtime.CompilerServices.CallerLineNumber] int line = 0) => new(false, [], $"Unresolved construction check at line {line}.");
        if (!field.IsPrivate || !field.IsInitOnly || field.IsStatic || field.Module is null) return Failed();
        var bodies = field.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        var constructors = field.DeclaringType.Methods.Where(m => m.IsInstanceConstructor).ToArray();
        if (constructors.Length == 0) return Failed();
        var parameters = new Dictionary<MethodDef, int>();
        foreach (var constructor in constructors)
        {
            if (!constructor.HasBody || constructor.Body.HasExceptionHandlers ||
                constructor.Body.Instructions.Any(i => i.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch ||
                    i.OpCode.Code == Code.Ret && i != constructor.Body.Instructions.Last() ||
                    i.GetParameter(constructor.Parameters)?.IsHiddenThisParameter == true && !i.IsLdarg())) return Failed();
            var writes = constructor.Body.Instructions.Where(i => i.Operand is IField f && ResolveField(f) == field &&
                i.OpCode.Code == Code.Stfld).ToArray();
            if (writes.Length != 1) return Failed();
            var flow = EvaluationStackOrigins.Analyze(constructor);
            if (!flow.Valid || !flow.Inputs.TryGetValue(writes[0], out var inputs) || inputs.Length != 2 ||
                inputs.Any(s => s.Count != 1)) return Failed();
            var receiver = inputs[0].Single(); var value = inputs[1].Single();
            if (receiver?.IsLdarg() != true || receiver.GetParameter(constructor.Parameters)?.IsHiddenThisParameter != true ||
                value?.IsLdarg() != true || value.GetParameter(constructor.Parameters) is not { IsHiddenThisParameter: false } parameter ||
                constructor.Body.Instructions.Any(i => i.GetParameter(constructor.Parameters) == parameter && !i.IsLdarg())) return Failed();
            parameters.Add(constructor, parameter.Index - 1);
        }
        var types = new List<TypeSig>();
        var constructions = new List<Construction>();
        var visited = new HashSet<MethodDef>();
        foreach (var body in bodies)
        {
            EvaluationStackOrigins.Result? flow = null;
            foreach (var instruction in body.Body.Instructions)
            {
                if (instruction.OpCode.Code == Code.Ldstr && instruction.Operand is string name &&
                    (name == field.Name.String || name == field.FullName)) return Failed();
                if (instruction.Operand is IField reference && ResolveField(reference) == field &&
                    instruction.OpCode.Code != Code.Ldfld &&
                    !(instruction.OpCode.Code == Code.Stfld && parameters.ContainsKey(body))) return Failed();
                if (instruction.Operand is not IMethod method || method.Name != ".ctor" || ResolveMethod(method) is not { } target ||
                    !parameters.TryGetValue(target, out var slot)) continue;
                if (instruction.OpCode.Code != Code.Newobj || method.DeclaringType.ToTypeSig().ContainsGenericParameter) return Failed();
                flow ??= EvaluationStackOrigins.Analyze(body);
                if (!flow.Valid || !flow.Inputs.TryGetValue(instruction, out var inputs) || slot < 0 || slot >= inputs.Length ||
                    inputs[slot].Count != 1 || inputs[slot].Single() is not { OpCode.Code: Code.Newobj, Operand: IMethod allocation } ||
                    allocation.DeclaringType.ToTypeSig() is not { ContainsGenericParameter: false } type ||
                    allocation.DeclaringType.ScopeType.ResolveTypeDef()?.Module != field.Module) return Failed();
                types.Add(type); constructions.Add(new(method, type)); visited.Add(target);
            }
        }
        return types.Count != 0 && visited.Count == constructors.Length ? new(true, types, "All observed constructor inputs are exact allocations.") { Constructions = constructions } : Failed();
    }
    internal static MethodDef? ResolveMethod(IMethod reference)
    {
        if (reference.ResolveMethodDef() is { } direct) return direct;
        var owner = reference.DeclaringType.ScopeType.ResolveTypeDef();
        if (owner is null) return null;
        var scope = Interpretation.GenericScope.For(reference, null);
        var matches = owner.Methods.Where(m => m.Name == reference.Name && Matches(m)).Take(2).ToArray();
        return matches.Length == 1 ? matches[0] : null;
        bool Matches(MethodDef method)
        {
            var signature = method.MethodSig.Clone();
            var expected = reference.MethodSig.Clone();
            if (scope is not null)
            {
                signature.RetType = scope.Bind(signature.RetType)!;
                expected.RetType = scope.Bind(expected.RetType)!;
                for (var i = 0; i < expected.Params.Count; i++) expected.Params[i] = scope.Bind(expected.Params[i])!;
                for (var i = 0; i < signature.Params.Count; i++) signature.Params[i] = scope.Bind(signature.Params[i])!;
            }
            return new SigComparer().Equals(signature, expected);
        }
    }
    internal static FieldDef? ResolveField(IField reference)
    {
        if (reference.ResolveFieldDef() is { } direct) return direct;
        var owner = reference.DeclaringType.ScopeType.ResolveTypeDef();
        if (owner is null || reference.FieldSig is null) return null;
        var scope = new Interpretation.GenericScope((reference.DeclaringType.ToTypeSig() as GenericInstSig)?.GenericArguments, null);
        var matches = owner.Fields.Where(f => f.Name == reference.Name &&
            new SigComparer().Equals(scope.Bind(f.FieldSig.Type), reference.FieldSig.Type)).Take(2).ToArray();
        return matches.Length == 1 ? matches[0] : null;
    }
}
