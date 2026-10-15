using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Passes;

/// <summary>Removes identity-preserving upcasts of the instance receiver and proven reference locals.</summary>
public sealed class ThisCastCompletionPass : DeobfuscationPass
{
    public override string Name => "this-cast-completion";
    public override IReadOnlyCollection<string> Dependencies => ["reference-field-typing"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        using var edit = new BodyMutationBatch();
        var changed = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods).Where(m =>
                     m.HasBody && !m.DeclaringType.IsValueType))
        {
            var receiver = method.Parameters.FirstOrDefault(p => p.IsHiddenThisParameter);
            if (receiver is not null && method.Body.Instructions.Any(i =>
                    i.OpCode.Code is Code.Starg or Code.Starg_S or Code.Ldarga or Code.Ldarga_S && i.Operand == receiver)) receiver = null;
            if (!method.Body.Instructions.Any(i => i.OpCode.Code == Code.Castclass)) continue;
            var graph = ControlFlowGraph.Build(method);
            var locals = ProvenLocals(method, graph);
            foreach (var block in graph.Blocks)
            {
                // Keep proven types only within this block; other stack values remain unknown.
                var stack = new List<TypeDef?>();
                foreach (var instruction in block.Instructions)
                {
                    if (instruction.OpCode.Code == Code.Nop) continue;
                    if (instruction.OpCode.Code == Code.Dup)
                    { stack.Add(stack.Count != 0 ? stack[^1] : null); continue; }
                    instruction.CalculateStackUsage(out var pushes, out var pops);
                    if (pops < 0 || pops > stack.Count) { stack.Clear(); continue; }
                    var provenType = pops != 0 ? stack[^1] : null;
                    stack.RemoveRange(stack.Count - pops, pops);
                    TypeDef? producedType = receiver is not null && instruction.IsLdarg() && instruction.GetParameter(method.Parameters) == receiver ? method.DeclaringType : null;
                    if (instruction.IsLdloc() && instruction.GetLocal(method.Body.Variables) is { } local && locals.TryGetValue(local, out var localType)) producedType = localType;
                    if (instruction.OpCode.Code == Code.Castclass && provenType is not null &&
                        instruction.Operand is ITypeDefOrRef target && IsAncestor(provenType, target))
                    {
                        edit.Capture(method);
                        instruction.OpCode = OpCodes.Nop; instruction.Operand = null;
                        edit.RecordChange(context, new(Name, "remove-proven-upcast", method.FullName,
                            $"Removed redundant cast to {target.FullName}; the proven {provenType.FullName} value already has that ancestor."));
                        producedType = provenType;
                        changed++;
                    }
                    for (var n = 0; n < pushes; n++) stack.Add(producedType);
                }
            }
        }
        if (changed == 0) return (PassStatus.Success, 0, ["No redundant proven-reference upcasts found."]);
        if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                CilantroPipeline.BuildRewriteAllowance(context)).Passed)
            return (PassStatus.Failed, 0, ["Proven-reference upcast removal failed verification and was rolled back."]);
        edit.Commit();
        return (PassStatus.Success, changed, [$"Removed {changed} redundant proven-reference upcast(s)."]);
    }

    private static Dictionary<Local, TypeDef> ProvenLocals(MethodDef method, ControlFlowGraph graph)
    {
        var result = new Dictionary<Local, TypeDef>();
        if (!method.Body.InitLocals) return result;
        var uses = method.Body.Instructions.Select(i => (Instruction: i, Local: i.GetLocal(method.Body.Variables))).Where(u => u.Local is not null).ToLookup(u => u.Local, u => u.Instruction);
        foreach (var local in method.Body.Variables)
        {
            if (local.Type is not ClassSig signature || signature.ContainsGenericParameter ||
                signature.TypeDefOrRef.ResolveTypeDef() is not { IsValueType: false, HasGenericParameters: false } type) continue;
            var valid = true;
            foreach (var instruction in uses[local])
            {
                if (instruction.IsLdloc()) continue;
                if (!instruction.IsStloc()) { valid = false; break; }
                var block = graph.BlockOf(instruction).Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                var at = Array.IndexOf(block, instruction);
                if (at < 1) { valid = false; break; }
                var producer = block[at - 1];
                if (producer.OpCode.Code == Code.Ldnull) continue;
                if (producer.OpCode.Code != Code.Castclass || producer.Operand is not ITypeDefOrRef cast ||
                    !new SigComparer().Equals(cast.ToTypeSig(), local.Type)) { valid = false; break; }
            }
            if (valid) result.Add(local, type);
        }
        return result;
    }
    private static bool IsAncestor(TypeDef owner, ITypeDefOrRef target)
    {
        var seen = new HashSet<ITypeDefOrRef>();
        var comparer = new SigComparer();
        for (ITypeDefOrRef? type = owner; type is not null && seen.Add(type) && seen.Count < 128;)
        {
            if (type is TypeSpec) return false;
            // A generic receiver still has its declared non-generic ancestors.
            // Do not confuse the open generic definition with an instantiated self
            // type, and stop at TypeSpec bases until substitution is supported.
            if (!(ReferenceEquals(type, owner) && owner.HasGenericParameters) && comparer.Equals(type, target)) return true;
            if (type.ResolveTypeDef() is not { IsValueType: false } definition ||
                definition.HasGenericParameters && !ReferenceEquals(definition, owner)) return false;
            type = definition.BaseType;
        }
        return false;
    }
}
