using Cilantro.Core.Verification;
using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Passes;

/// <summary>Removes empty instruction scaffolding after semantic recovery has finished.</summary>
public class IlCompactionPass : DeobfuscationPass
{
    public override string Name => "il-compaction";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["control-flow-finalization"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var removed = 0;
        var methods = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            using var edit = new BodyMutationTransaction(method);
            var before = EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count;
            var count = Compact(method);
            if (count == 0) { edit.Commit(); continue; }
            if (EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count > before) continue;
            edit.Commit();
            removed += count; methods++;
            context.AddChange(new(Name, "compact-instructions", method.FullName,
                $"Removed {count} no-op or fall-through branch instructions; retained exception boundaries and switch entries."));
        }
        return (PassStatus.Success, removed, [$"Removed {removed} empty instructions from {methods} methods."]);
    }

    internal static int Compact(MethodDef method)
    {
        var body = method.Body;
        var instructions = body.Instructions.ToArray();
        var positions = instructions.Select((instruction, index) => (instruction, index)).ToDictionary(p => p.instruction, p => p.index);
        var anchors = new HashSet<Instruction>();
        foreach (var handler in body.ExceptionHandlers)
        foreach (var boundary in new[] { handler.TryStart, handler.TryEnd, handler.HandlerStart, handler.HandlerEnd, handler.FilterStart })
        {
            if (boundary is null) continue;
            anchors.Add(boundary);
            // Never redirect a target across a region boundary, even when a body
            // already has malformed fall-through at that boundary.
            if (positions.TryGetValue(boundary, out var index) && index > 0) anchors.Add(instructions[index - 1]);
        }
        var replacement = new Dictionary<Instruction, Instruction>();
        var kept = new HashSet<Instruction>();
        Instruction? next = null;
        for (var at = instructions.Length - 1; at >= 0; at--)
        {
            var instruction = instructions[at];
            var target = instruction.Operand is Instruction raw ? replacement.GetValueOrDefault(raw, raw) : null;
            var empty = instruction.OpCode.Code == Code.Nop ||
                instruction.OpCode.Code is Code.Br or Code.Br_S && target == next;
            if (next is not null && empty && !anchors.Contains(instruction) && instruction.SequencePoint is null)
                replacement[instruction] = next;
            else
            {
                replacement[instruction] = instruction;
                kept.Add(instruction); next = instruction;
            }
        }
        if (kept.Count == instructions.Length) return 0;
        foreach (var instruction in instructions.Where(kept.Contains))
        {
            if (instruction.Operand is Instruction target && replacement.TryGetValue(target, out var mapped)) instruction.Operand = mapped;
            else if (instruction.Operand is IList<Instruction> targets)
                instruction.Operand = targets.Select(t => replacement.GetValueOrDefault(t, t)).ToArray();
        }
        body.Instructions.Clear();
        foreach (var instruction in instructions.Where(kept.Contains)) body.Instructions.Add(instruction);
        body.SimplifyBranches(); body.OptimizeBranches(); body.UpdateInstructionOffsets();
        return instructions.Length - kept.Count;
    }
}
