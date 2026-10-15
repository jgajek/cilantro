using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>A Reactor integer pool whose initialization and direct object flow are closed.</summary>
/// <remarks>
/// This is protector cleanup, not a general immutable-field theorem. As with removal of
/// isolated VM types, computed reflection over the identified protector metadata is outside
/// the cleanup contract. Explicit handles, names, numeric tokens, aliases and additional
/// writers still refuse cleanup. FieldWriteSafety's general reflection rule is unchanged.
/// </remarks>
internal sealed record ReactorGuardPool(TypeDef Owner, FieldDef Root, MethodDef Initializer,
    IReadOnlyDictionary<FieldDef, int> Values, IReadOnlyList<(MethodDef Method, Instruction Root, Instruction Read)> Reads,
    IReadOnlySet<MethodDef> InitializerChain)
{
    internal static IReadOnlyList<ReactorGuardPool> Find(ModuleDef module, bool includeUnused = false)
    {
        var methods = module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        var reachability = ModuleReachability.Compute(module);
        // Token arithmetic can name declarations without a handle or a string. Keep the
        // same conservative boundary used by declaration cleanup.
        foreach (var method in methods.Where(reachability.IsReachable))
        {
            var uses = method.Body.Instructions.Where(i => i.Operand is IMethod c && NumericTokenUses.IsResolution(c)).ToArray();
            if (uses.Length != 0 && uses.Any(i => !NumericTokenUses.MemberRoundTrips(method).Contains(i))) return [];
        }
        var pools = new List<ReactorGuardPool>();
        foreach (var owner in module.GetTypes())
        {
            if (!owner.IsSealed || owner.HasGenericParameters || owner.HasInterfaces || owner.HasNestedTypes ||
                MemberVisibility.IsExternallyVisible(owner) || owner.BaseType?.FullName != "System.Object") continue;
            var integers = owner.Fields.Where(f => !f.IsStatic && f.FieldType.ElementType == ElementType.I4).ToArray();
            // The recovered initializer and Reactor's hashed state-field family identify
            // the protector pool. An arbitrary application constant holder is not eligible.
            if (integers.Length < 16 || !integers.Any(f => f.Name.String.StartsWith("m_", StringComparison.Ordinal) &&
                f.Name.String.Length >= 32 && f.Name.String[2..].All(Uri.IsHexDigit))) continue;
            if (owner.Fields.Any(f => !integers.Contains(f) && (!f.IsStatic || f.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() != owner))) continue;
            foreach (var initializer in owner.Methods.Where(m => m.HasBody && m.IsStatic && !m.HasGenericParameters && m.MethodSig.Params.Count == 0 &&
                m.ReturnType.ElementType == ElementType.Void &&
                (IsOrdinaryPool(owner) || m.CustomAttributes.Any(a => a.TypeFullName == "Cilantro.RebuiltFromReadingAttribute"))))
            {
                var sequence = Linear(initializer);
                if (sequence is null || sequence.Length < 3 || sequence[0].OpCode.Code != Code.Newobj ||
                    sequence[0].Operand is not IMethod ctorReference || ctorReference.ResolveMethodDef() is not { } ctor ||
                    ctor.DeclaringType != owner || !ctor.IsInstanceConstructor || ctor.MethodSig.Params.Count != 0 || sequence[1].OpCode.Code != Code.Stsfld ||
                    sequence[1].Operand is not IField rootReference || rootReference.ResolveFieldDef() is not { } root ||
                    root.DeclaringType != owner || !root.IsStatic || root.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() != owner) continue;
                var construction = Linear(ctor);
                if (construction is not { Length: 3 } || construction[0].OpCode.Code != Code.Ldarg_0 ||
                    construction[1].OpCode.Code != Code.Call || construction[1].Operand is not IMethod baseCtor ||
                    baseCtor.FullName != "System.Void System.Object::.ctor()" || construction[2].OpCode.Code != Code.Ret) continue;
                var values = new Dictionary<FieldDef, int>();
                var valid = true;
                for (var at = 2; at < sequence.Length - 1;)
                {
                    if (sequence[at++].Operand is not IField load || load.ResolveFieldDef() != root || sequence[at - 1].OpCode.Code != Code.Ldsfld)
                    { valid = false; break; }
                    if (at < sequence.Length && sequence[at].OpCode.Code == Code.Castclass && sequence[at].Operand is ITypeDefOrRef cast && cast.ResolveTypeDef() == owner) at++;
                    if (at + 1 >= sequence.Length || !sequence[at].IsLdcI4() || sequence[at + 1].OpCode.Code != Code.Stfld ||
                        sequence[at + 1].Operand is not IField stored || stored.ResolveFieldDef() is not { } field ||
                        !integers.Contains(field) || !values.TryAdd(field, sequence[at].GetLdcI4Value()))
                    { valid = false; break; }
                    at += 2;
                }
                if (!valid || sequence[^1].OpCode.Code != Code.Ret || values.Count != integers.Length) continue;
                var cctor = owner.FindStaticConstructor();
                if (cctor is null) continue;
                var chain = new HashSet<MethodDef> { initializer };
                var child = initializer;
                while (child != cctor)
                {
                    var callers = methods.Where(m => m.Body.Instructions.Any(i => i.Operand is IMethod c && c.ResolveMethodDef() == child)).ToArray();
                    if (callers.Length != 1 || callers[0].DeclaringType != owner || !callers[0].IsStatic || callers[0].HasGenericParameters ||
                        callers[0].MethodSig.Params.Count != 0 || callers[0].ReturnType.ElementType != ElementType.Void ||
                        !chain.Add(callers[0]) || Linear(callers[0]) is not { } body ||
                        body.Count(i => i.OpCode.Code == Code.Call && i.Operand is IMethod c && c.ResolveMethodDef() == child) != 1)
                    { valid = false; break; }
                    child = callers[0];
                }
                if (!valid) continue;
                var reads = new List<(MethodDef, Instruction, Instruction)>();
                var readInstructions = new HashSet<Instruction>();
                var names = owner.Fields.Select(f => f.Name.String).Append(owner.FullName).ToHashSet(StringComparer.Ordinal);
                foreach (var method in methods)
                {
                    var il = method.Body.Instructions;
                    var entries = il.SelectMany(i => i.Operand is Instruction t ? new[] { t } : i.Operand as IList<Instruction> ?? []).ToHashSet();
                    foreach (var eh in method.Body.ExceptionHandlers)
                    { entries.Add(eh.TryStart); entries.Add(eh.HandlerStart); if (eh.FilterStart is { } filter) entries.Add(filter);
                      if (eh.TryEnd is { } end) entries.Add(end); if (eh.HandlerEnd is { } handlerEnd) entries.Add(handlerEnd); }
                    for (var at = 0; at < il.Count; at++)
                    {
                        var instruction = il[at];
                        if (instruction.Operand is string text && names.Any(n => text.Contains(n, StringComparison.Ordinal))) { valid = false; break; }
                        if (instruction.OpCode.Code == Code.Ldtoken && (instruction.Operand is ITypeDefOrRef t && t.ResolveTypeDef() == owner ||
                            instruction.Operand is IField f && f.DeclaringType.ResolveTypeDef() == owner ||
                            instruction.Operand is IMethod m && m.DeclaringType.ResolveTypeDef() == owner)) { valid = false; break; }
                        if (instruction.Operand is IMethod called && called.ResolveMethodDef() == ctor && method != initializer) { valid = false; break; }
                        if (instruction.Operand is IMethod initializerCall && initializerCall.ResolveMethodDef() == cctor) { valid = false; break; }
                        if (instruction.OpCode.Code is Code.Ldftn or Code.Ldvirtftn && instruction.Operand is IMethod function &&
                            function.ResolveMethodDef() is { } definitionMethod && chain.Contains(definitionMethod)) { valid = false; break; }
                        if (method == initializer) continue;
                        if (instruction.Operand is not IField reference || reference.ResolveFieldDef() is not { } referenced) continue;
                        if (referenced == root)
                        {
                            var next = at + 1;
                            while (next < il.Count && il[next].OpCode.Code == Code.Nop && !entries.Contains(il[next])) next++;
                            if (instruction.OpCode.Code != Code.Ldsfld || next >= il.Count || entries.Contains(il[next]) ||
                                il[next].OpCode.Code != Code.Ldfld || il[next].Operand is not IField member ||
                                member.ResolveFieldDef() is not { } definition || !values.ContainsKey(definition) ||
                                at > 0 && il[at - 1].OpCode.OpCodeType == OpCodeType.Prefix)
                            { valid = false; break; }
                            reads.Add((method, instruction, il[next]));
                            readInstructions.Add(il[next]);
                        }
                        else if (values.ContainsKey(referenced) && (instruction.OpCode.Code != Code.Ldfld ||
                            !readInstructions.Contains(instruction))) { valid = false; break; }
                    }
                    if (!valid) break;
                }
                if (valid && (includeUnused || reads.Count != 0)) pools.Add(new(owner, root, initializer, values, reads, chain));
            }
        }
        return pools;
    }

    // Ordinary Reactor pools do not carry a VM reconstruction marker. Require both
    // the generated module/GUID owner and the complete hashed integer-field family;
    // the construction, use and exposure proofs above still apply independently.
    internal static bool IsOrdinaryPool(TypeDef owner)
    {
        var name = owner.Name.String;
        var integers = owner.Fields.Where(f => !f.IsStatic && f.FieldType.ElementType == ElementType.I4).ToArray();
        return owner.Namespace.String.Length == 0 && name.StartsWith("<Module>{", StringComparison.Ordinal) &&
            Guid.TryParseExact(name[8..], "B", out _) && integers.Length >= 16 &&
            integers.All(f => f.Name.String.Length == 34 && f.Name.String.StartsWith("m_", StringComparison.Ordinal) &&
                f.Name.String[2..].All(Uri.IsHexDigit));
    }

    // Follow the actual branch chain, rejecting conditional paths, loops, EH and dead
    // instructions with hidden stores/callers. This is not a snapshot of one execution.
    private static Instruction[]? Linear(MethodDef method)
    {
        if (!method.HasBody || method.Body.HasExceptionHandlers || method.Body.Instructions.Count == 0) return null;
        var il = method.Body.Instructions;
        var indices = il.Select((i, n) => (i, n)).ToDictionary(p => p.i, p => p.n);
        var seen = new HashSet<Instruction>();
        var result = new List<Instruction>();
        for (var at = 0; at < il.Count;)
        {
            var i = il[at];
            if (!seen.Add(i)) return null;
            if (i.OpCode.Code is Code.Br or Code.Br_S && i.Operand is Instruction target)
            { if (!indices.TryGetValue(target, out at)) return null; continue; }
            if (i.OpCode.FlowControl is FlowControl.Cond_Branch or FlowControl.Throw) return null;
            if (i.OpCode.Code != Code.Nop) result.Add(i);
            if (i.OpCode.Code == Code.Ret) break;
            at++;
        }
        if (!il.All(i => seen.Contains(i) || i.OpCode.Code == Code.Nop) || result.LastOrDefault()?.OpCode.Code != Code.Ret) return null;
        // Unflattening can leave discarded dispatcher literals and folded null
        // predicates. Only erase balanced literal/pop pairs on the unique proven
        // execution path; calls, loads, stores and all other effects stay visible.
        var normalized = new List<Instruction>();
        foreach (var instruction in result)
        {
            if (instruction.OpCode.Code == Code.Pop && normalized.Count != 0 &&
                (normalized[^1].IsLdcI4() || normalized[^1].OpCode.Code == Code.Ldnull))
                normalized.RemoveAt(normalized.Count - 1);
            else normalized.Add(instruction);
        }
        return normalized.ToArray();
    }
}
