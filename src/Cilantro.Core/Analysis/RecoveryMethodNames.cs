using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Separates unused data labels from strings that could name recovered methods.</summary>
internal static class RecoveryMethodNames
{
    internal static HashSet<string> Collect(ModuleDef module, MethodDef[] methods, IReadOnlySet<TypeDef> exposed)
    {
        var bodies = methods.Where(m => m.HasBody).ToArray();
        var literals = bodies.SelectMany(m => m.Body.Instructions).Where(i => i.OpCode.Code == Code.Ldstr)
            .Select(i => (string)i.Operand).ToHashSet(StringComparer.Ordinal);
        var methodUses = bodies.SelectMany(m => m.Body.Instructions).Select(i => i.Operand).OfType<IMethod>()
            .Select(m => m.ResolveMethodDef()).Where(m => m is not null).ToHashSet();
        var fieldUses = bodies.SelectMany(m => m.Body.Instructions.Where(i => i.Operand is IField)
            .Select(i => (Method: m, Instruction: i, Field: ((IField)i.Operand).ResolveFieldDef()))).ToLookup(u => u.Field);
        var fields = new Dictionary<FieldDef, bool>();
        var parameters = new Dictionary<Parameter, bool>();
        var graphs = new Dictionary<MethodDef, ControlFlowGraph>();
        ControlFlowGraph Graph(MethodDef method)
        {
            if (!graphs.TryGetValue(method, out var graph)) graphs[method] = graph = ControlFlowGraph.Build(method);
            return graph;
        }
        bool DataField(FieldDef field)
        {
            if (fields.TryGetValue(field, out var known)) return known;
            fields[field] = false;
            if (field.Module != module || !field.IsPrivate || !field.IsInitOnly || field.IsStatic ||
                field.FieldSig.Type.ElementType != ElementType.String || exposed.Contains(field.DeclaringType)) return false;
            foreach (var use in fieldUses[field])
            {
                if (use.Instruction.OpCode.Code == Code.Stfld && use.Method.IsInstanceConstructor &&
                    use.Method.DeclaringType == field.DeclaringType) continue;
                var reader = use.Method;
                // Only a direct, non-virtual getter with no observed caller may
                // expose the label. Arbitrary external API consumers are outside
                // application recovery's scope; actual metadata/handle uses are not.
                if (use.Instruction.OpCode.Code != Code.Ldfld || reader.IsStatic || reader.IsVirtual ||
                    reader.Overrides.Count != 0 || reader.Body.ExceptionHandlers.Count != 0 || methodUses.Contains(reader) ||
                    literals.Contains(reader.Name.String) || literals.Contains(reader.FullName) ||
                    !reader.DeclaringType.Properties.Any(p => p.GetMethods.Contains(reader))) return false;
                var il = reader.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                if (il.Length != 3 || !il[0].IsLdarg() || il[0].GetParameter(reader.Parameters)?.Index != 0 ||
                    il[1] != use.Instruction || il[2].OpCode.Code != Code.Ret) return false;
            }
            return fields[field] = true;
        }
        bool DataParameter(Parameter parameter)
        {
            if (parameters.TryGetValue(parameter, out var known)) return known;
            parameters[parameter] = false;
            var ctor = parameter.Method;
            if (!ctor.HasBody || !ctor.IsInstanceConstructor || ctor.Body.ExceptionHandlers.Count != 0 ||
                ctor.DeclaringType.HasGenericParameters || exposed.Contains(ctor.DeclaringType)) return false;
            var reads = 0;
            foreach (var block in Graph(ctor).Blocks)
            {
                var il = block.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                for (var n = 0; n < il.Length; n++)
                {
                    if (il[n].GetParameter(ctor.Parameters) != parameter) continue;
                    if (!il[n].IsLdarg() || n == 0 || n + 1 >= il.Length || !il[n - 1].IsLdarg() ||
                        il[n - 1].GetParameter(ctor.Parameters)?.Index != 0 || il[n + 1].OpCode.Code != Code.Stfld ||
                        il[n + 1].Operand is not IField reference || reference.ResolveFieldDef() is not { } field ||
                        !DataField(field)) return false;
                    reads++;
                }
            }
            return parameters[parameter] = reads != 0;
        }
        bool DataLabel(MethodDef method, Instruction literal)
        {
            var il = Graph(method).BlockOf(literal).Instructions;
            var at = 0; while (at < il.Count && il[at] != literal) at++;
            var trailing = 0;
            for (var n = at + 1; n < il.Count; n++)
            {
                var next = il[n];
                if (next.OpCode.Code == Code.Nop) continue;
                if (next.IsLdcI4() || next.OpCode.Code is Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8 or Code.Ldnull or Code.Ldstr)
                { trailing++; continue; }
                if (next.OpCode.Code != Code.Newobj || next.Operand is not MethodDef ctor || ctor.Module != module ||
                    ctor.MethodSig is not { HasThis: true } signature) return false;
                var slot = signature.Params.Count - trailing - 1;
                return slot >= 0 && signature.Params[slot].ElementType == ElementType.String &&
                    DataParameter(ctor.Parameters[slot + 1]);
            }
            return false;
        }
        var dynamicNames = new DynamicMethodNameUses(module);
        var relevant = methods.SelectMany(m => new[] { m.Name.String, m.FullName }).ToHashSet(StringComparer.Ordinal);
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var method in bodies)
        foreach (var literal in method.Body.Instructions.Where(i => i.OpCode.Code == Code.Ldstr && relevant.Contains((string)i.Operand)))
            if (!DataLabel(method, literal) && !dynamicNames.IsCreationName(method, literal)) names.Add((string)literal.Operand);
        return names;
    }
}
