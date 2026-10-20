using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Encodes reviewed CIL by ordered successor edges, independent of physical block placement.</summary>
internal sealed record CanonicalRuntimeBody(bool InitLocals, string[] Locals, string[] Instructions, string[] Handlers)
{
    internal static CanonicalRuntimeBody Read(MethodDef method, Func<Instruction, string> operand,
        Func<TypeSig, string> signature, Func<ITypeDefOrRef?, string> owner)
    {
        var il = method.Body.Instructions;
        if (il.Count == 0 || il.Count > 16_384) throw new InvalidOperationException("Canonical checker body exceeds its bounds.");
        var positions = il.Select((instruction, index) => (instruction, index)).ToDictionary(item => item.instruction, item => item.index);
        var aliases = new Dictionary<Instruction, Instruction>();
        Instruction? Next(Instruction instruction) => il.ElementAtOrDefault(positions[instruction] + 1);
        Instruction? Skip(Instruction? at)
        {
            var seen = new HashSet<Instruction>();
            while (at is not null)
            {
                if (aliases.TryGetValue(at, out var cached)) { at = cached; break; }
                if (!seen.Add(at)) throw new InvalidOperationException("Checker contains an empty transfer cycle.");
                var next = at.OpCode.Code is Code.Br or Code.Br_S ? at.Operand as Instruction :
                    at.OpCode.Code == Code.Nop ? Next(at) : null;
                // Empty transfers cannot throw. Exception membership is recorded
                // for every retained instruction, including the actual targets.
                // Keeping an empty boundary node would make equivalent try-entry
                // fall-through and branch layouts produce different graphs.
                if (next is null || !positions.ContainsKey(next)) break;
                at = next;
            }
            if (at is not null) foreach (var instruction in seen) aliases[instruction] = at;
            return at;
        }
        var ordered = new List<Instruction>();
        var indexes = new Dictionary<Instruction, int>();
        var pending = new Queue<Instruction>();
        void Add(Instruction? instruction)
        {
            instruction = Skip(instruction);
            if (instruction is null || indexes.ContainsKey(instruction)) return;
            indexes.Add(instruction, ordered.Count); ordered.Add(instruction); pending.Enqueue(instruction);
        }
        IEnumerable<Instruction> Edges(Instruction instruction)
        {
            if (instruction.Operand is Instruction branch) yield return Skip(branch)!;
            if (instruction.Operand is IList<Instruction> branches)
                foreach (var target in branches) yield return Skip(target)!;
            if (instruction.OpCode.FlowControl is not (FlowControl.Branch or FlowControl.Return or FlowControl.Throw) && Skip(Next(instruction)) is { } fallThrough)
                yield return fallThrough;
        }
        Add(il[0]);
        foreach (var handler in method.Body.ExceptionHandlers) { Add(handler.HandlerStart); Add(handler.FilterStart); }
        while (pending.TryDequeue(out var instruction)) foreach (var target in Edges(instruction)) Add(target);
        if (il.Any(instruction => Skip(instruction) == instruction && !indexes.ContainsKey(instruction)))
            throw new InvalidOperationException("Unreachable checker instructions remain after normalization: " + method.FullName);
        var locals = new List<Local>();
        int LocalIndex(Local local)
        {
            if (!locals.Contains(local)) locals.Add(local);
            return locals.IndexOf(local);
        }
        string Value(Instruction instruction) => instruction.Operand switch
        {
            Instruction or IList<Instruction> => "edge",
            Local local => "local:" + LocalIndex(local),
            _ => operand(instruction)
        };
        var instructions = ordered.Select(instruction => JsonSerializer.Serialize(new
        {
            Code = instruction.OpCode.Code.ToString(), Operand = Value(instruction), Successors = Edges(instruction).Select(target => indexes[target]).ToArray()
        })).ToArray();
        int[] Region(Instruction? start, Instruction? end) => ordered.Select((instruction, index) => (instruction, index))
            .Where(item => start is not null && positions[item.instruction] >= positions[start] &&
                (end is null || positions[item.instruction] < positions[end])).Select(item => item.index).ToArray();
        int Entry(Instruction? instruction) => Skip(instruction) is { } entry ? indexes.GetValueOrDefault(entry, -1) : -1;
        var handlers = method.Body.ExceptionHandlers.Select(handler => JsonSerializer.Serialize(new
        {
            handler.HandlerType, Catch = owner(handler.CatchType), Try = Region(handler.TryStart, handler.TryEnd),
            Handler = Region(handler.HandlerStart, handler.HandlerEnd), HandlerEntry = Entry(handler.HandlerStart),
            Filter = handler.FilterStart is null ? [] : Region(handler.FilterStart, handler.HandlerStart), FilterEntry = Entry(handler.FilterStart)
        })).ToArray();
        return new(locals.Count > 0 && method.Body.InitLocals, locals.Select(local => signature(local.Type)).ToArray(), instructions, handlers);
    }
}
