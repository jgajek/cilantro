using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Identifies a uniquely assigned, private static delegate binding; it does not prove initialization has run.</summary>
internal static class ReadonlyDelegateBinding
{
    internal static MethodDef? Target(FieldDef field)
    {
        if (!field.IsStatic || !field.IsInitOnly || MemberVisibility.IsExternallyVisible(field.DeclaringType) ||
            field.DeclaringType.HasGenericParameters || field.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() is not { } delegateType ||
            delegateType.Module != field.Module || delegateType.HasGenericParameters ||
            delegateType.BaseType?.FullName != "System.MulticastDelegate" ||
            field.DeclaringType.FindStaticConstructor() is not { HasBody: true } initializer ||
            initializer.Body.ExceptionHandlers.Count != 0) return null;
        var il = InitializerPath(initializer);
        // Only straight-line initialization qualifies. A conditional binding must not
        // become a single target just because one interpretation took that branch.
        if (il is null) return null;
        var stores = il.Select((instruction, index) => (instruction, index)).Where(p =>
            p.instruction.OpCode.Code == Code.Stsfld && p.instruction.Operand is IField f && f.ResolveFieldDef() == field).ToArray();
        if (stores.Length != 1 || stores[0].index < 3) return null;
        var at = stores[0].index;
        if (il[at - 3].OpCode.Code != Code.Ldnull || il[at - 2].OpCode.Code != Code.Ldftn ||
            il[at - 2].Operand is not IMethod reference || reference is MethodSpec ||
            reference.ResolveMethodDef() is not { IsStatic: true, HasBody: true } target ||
            target.HasGenericParameters || target.DeclaringType.HasGenericParameters || target.Module != field.Module ||
            il[at - 1].OpCode.Code != Code.Newobj || il[at - 1].Operand is not IMethod constructor ||
            constructor.Name != ".ctor" || constructor.DeclaringType.ResolveTypeDef() != delegateType ||
            constructor.ResolveMethodDef() is not { IsRuntime: true, IsStatic: false } ||
            constructor.MethodSig?.Params.Count != 2 || constructor.MethodSig.Params[0].ElementType != ElementType.Object ||
            constructor.MethodSig.Params[1].ElementType != ElementType.I) return null;
        var invokes = delegateType.Methods.Where(m => m.Name == "Invoke").ToArray();
        if (invokes.Length != 1 || constructor.MethodSig.HasThis != true ||
            constructor.MethodSig.RetType.ElementType != ElementType.Void ||
            constructor.MethodSig.ParamsAfterSentinel?.Count > 0 || target.MethodSig.ParamsAfterSentinel?.Count > 0) return null;
        var invoke = invokes[0];
        if (!invoke.IsRuntime || !invoke.IsVirtual || invoke.IsStatic || invoke.HasGenericParameters ||
            invoke.MethodSig is not { HasThis: true } signature || signature.Params.Count != target.MethodSig.Params.Count ||
            !new SigComparer().Equals(signature.RetType, target.ReturnType) ||
            !signature.Params.Zip(target.MethodSig.Params).All(p => new SigComparer().Equals(p.First, p.Second))) return null;
        foreach (var method in field.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.OpCode.Code == Code.Ldtoken && instruction.Operand is ITypeDefOrRef type &&
                    type.ResolveTypeDef() == field.DeclaringType) return null;
                if (instruction.Operand is IField used && used.ResolveFieldDef() == field &&
                    !ReferenceEquals(instruction, stores[0].instruction) && instruction.OpCode.Code != Code.Ldsfld) return null;
            }
        return target;
    }

    private static Instruction[]? InitializerPath(MethodDef method)
    {
        var instructions = method.Body.Instructions;
        var positions = instructions.Select((instruction, index) => (instruction, index))
            .ToDictionary(p => p.instruction, p => p.index);
        var seen = new HashSet<Instruction>();
        var path = new List<Instruction>();
        for (var at = 0; at < instructions.Count; at++)
        {
            var instruction = instructions[at];
            if (!seen.Add(instruction)) return null;
            if (instruction.OpCode.Code is Code.Br or Code.Br_S)
            {
                if (instruction.Operand is not Instruction target || !positions.TryGetValue(target, out var next)) return null;
                at = next - 1;
                continue;
            }
            if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Throw) return null;
            if (instruction.OpCode.Code != Code.Nop) path.Add(instruction);
            if (instruction.OpCode.Code == Code.Ret) return [.. path];
        }
        return null;
    }

    internal static FieldDef? Receiver(MethodDef method, Instruction call)
    {
        if (call.OpCode.Code != Code.Callvirt || call.Operand is not IMethod { Name.String: "Invoke", MethodSig.Params.Count: 0 } invoked)
            return null;
        var block = ControlFlowGraph.Build(method).BlockOf(call);
        var previous = block.Instructions.TakeWhile(i => i != call).LastOrDefault(i => i.OpCode.Code != Code.Nop);
        return previous?.OpCode.Code == Code.Ldsfld && previous.Operand is IField reference &&
            reference.ResolveFieldDef() is { } field && field.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() == invoked.DeclaringType.ResolveTypeDef()
            ? field : null;
    }
}
