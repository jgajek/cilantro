using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Passes;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Replaces calls to methods that only ever hand back one string with the string itself.
/// </summary>
/// <remarks>
/// Reactor's string table is not the only way a protected assembly hides its strings. Alongside it,
/// the samples carry a decoder per string: a static method that loads a scrambled literal, walks it
/// a character at a time, and returns the result. Nothing about that is protector-specific and no
/// table indexes it, so the string-table recovery never sees it, and what is left in the listing is
/// a call to a method with a random name where a string should be.
///
/// It is also load-bearing rather than cosmetic. A resource is attributed to a role by finding its
/// name in the code that reads it, and a module that spells its resource names this way has no such
/// literal anywhere, so every resource stays unattributed and nothing downstream can tell an
/// unextracted payload from a module that carries none.
///
/// What makes a call replaceable is the same account the machine gives everywhere else: the method
/// is interpreted twice, both runs complete, both produce the same string, and the effects record
/// for the frame is empty — no static field written, no handler registered, no image patched. An
/// empty account is meaningful because the machine refuses every call it does not model, so a frame
/// that ran to completion did nothing outside the modeled surface. A method that leaves a mark is
/// left alone even when its result is constant, because removing the call would remove the mark
/// with it.
///
/// The two runs happen on two separately built machines that take the candidates in opposite
/// orders. Standing up a machine means running the loader's initialization, which costs more than
/// every decoder in a module put together, so one machine per candidate is not affordable. Opposite
/// orders buy back what sharing a machine would otherwise cost: a method whose answer depended on
/// what ran before it is exactly the method the two orders disagree about.
/// </remarks>
public sealed class ConstantStringPass : DeobfuscationPass
{
    private const int MaximumSteps = 4_000_000;

    /// <summary>How many methods are worth examining before the search stops paying for itself.</summary>
    private const int MaximumCandidates = 512;

    /// <summary>
    /// How long a body may be and still look like a decoder rather than a program.
    /// </summary>
    private const int MaximumBodySize = 512;

    /// <summary>How many refusals are worth spelling out before the list stops informing.</summary>
    private const int MaximumReasonsReported = 8;

    public override string Name => "constant-strings";

    public override IReadOnlyCollection<string> Dependencies => ["string-recovery"];

    public override bool GatesEmission => false;

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        // An ordinary assembly is full of methods that return a fixed string, and folding those
        // would be an edit made for no reason. The point here is a protector hiding strings, so
        // the pass only runs where one was found.
        if (!context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var facts) ||
            facts is null ||
            !facts.IsReactor6)
        {
            return (PassStatus.Success, 0,
                ["No Reactor structure was detected, so no string decoder was looked for."]);
        }

        var candidates = Candidates(context.Module);
        if (candidates.Length == 0)
            return (PassStatus.Success, 0, ["No method has the shape of a single-string decoder."]);

        if (!BootstrapMachine.TryRunInitializers(context, MaximumSteps, out var forwards, out var why) ||
            forwards is null ||
            !BootstrapMachine.TryRunInitializers(context, MaximumSteps, out var backwards, out why) ||
            backwards is null)
        {
            return (PassStatus.Success, 0,
                [$"No machine could be stood up to examine the decoders: {why}"]);
        }

        var ahead = Read(forwards, candidates);
        var behind = Read(backwards, [.. candidates.Reverse()]);
        var proven = new Dictionary<uint, string>();
        var refused = new List<string>();
        foreach (var candidate in candidates)
        {
            var token = candidate.MDToken.Raw;
            var first = ahead[token];
            var second = behind[token];
            if (first.Text is null)
                refused.Add($"{candidate.MDToken}: {first.Why}");
            else if (!string.Equals(first.Text, second.Text, StringComparison.Ordinal))
                refused.Add($"{candidate.MDToken}: it answered differently the second time");
            else if (first.Marked || second.Marked)
                refused.Add(
                    $"{candidate.MDToken}: it leaves something behind that removing the call " +
                    "would remove too");
            else
                proven[token] = first.Text;
        }

        if (proven.Count == 0)
        {
            return (PassStatus.Success, 0,
            [
                $"None of the {candidates.Length} candidate decoder(s) was proven to return a " +
                "fixed string.",
                .. refused.Take(MaximumReasonsReported)
            ]);
        }

        var throughFields = Delegates(context.Module, proven);
        var changes = 0;
        using var transaction = new InstructionMutationTransaction();
        foreach (var method in context.Module.GetTypes().SelectMany(type => type.Methods)
                     .Where(method => method.HasBody))
        {
            var instructions = method.Body.Instructions;
            var targeted = Targeted(method);
            for (var index = 0; index < instructions.Count; index++)
            {
                var instruction = instructions[index];
                var text = Folded(instruction, proven);
                if (text is not null)
                {
                    transaction.Capture(instruction);
                    instruction.OpCode = OpCodes.Ldstr;
                    instruction.Operand = text;
                }
                else if (index + 1 < instructions.Count &&
                    instruction.OpCode.Code == Code.Ldsfld &&
                    instruction.Operand is IField held &&
                    throughFields.TryGetValue(held.MDToken.Raw, out text) &&
                    IsDelegateInvoke(instructions[index + 1]) &&
                    !targeted.Contains(instructions[index + 1]))
                {
                    // The delegate is loaded and called on the spot, so the pair is one expression:
                    // the load leaves nothing behind once the call it feeds is a literal.
                    transaction.Capture(instruction);
                    transaction.Capture(instructions[index + 1]);
                    instruction.OpCode = OpCodes.Nop;
                    instruction.Operand = null;
                    instructions[index + 1].OpCode = OpCodes.Ldstr;
                    instructions[index + 1].Operand = text;
                    index++;
                }
                else
                {
                    continue;
                }

                changes++;
                context.AddChange(new ChangeRecord(
                    Name,
                    "fold-constant-string",
                    $"{method.MDToken} IL_{instruction.Offset:X4}",
                    text));
            }
        }

        var verification = AssemblyVerifier.Verify(context.Module);
        if (!verification.Passed)
        {
            transaction.Rollback();
            return (PassStatus.Failed, 0,
                ["Constant string rewrite failed verification and was rolled back."]);
        }

        transaction.Commit();
        foreach (var (token, text) in proven.OrderBy(entry => entry.Key))
        {
            context.AddEvidence(new Evidence(
                "constant-string",
                $"{token:X8} returns \"{text}\".",
                $"{token:X8}",
                1.0));
        }

        return (PassStatus.Success, changes,
        [
            $"Proved {proven.Count} of {candidates.Length} candidate decoder(s) constant and " +
            $"replaced {changes} call(s) with the string.",
            refused.Count == 0
                ? "Every candidate was proven."
                : $"{refused.Count} candidate(s) were left alone: " +
                    string.Join(" | ", refused.Take(MaximumReasonsReported))
        ]);
    }

    /// <summary>
    /// Methods shaped like a decoder: no arguments, a string out, and a literal to work from.
    /// </summary>
    /// <remarks>
    /// Requiring a literal in the body is what keeps the cost bounded. Any argument-free method
    /// returning a string could in principle be constant, but interpreting all of them would mean
    /// running arbitrary program code to find out, where a decoder is recognizable ahead of time by
    /// carrying the thing it decodes.
    /// </remarks>
    private static MethodDef[] Candidates(ModuleDef module) =>
        [.. module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method is
                {
                    HasBody: true,
                    IsStatic: true,
                    HasGenericParameters: false
                } &&
                method.MethodSig?.Params.Count == 0 &&
                method.ReturnType.FullName == "System.String" &&
                method.Body.Instructions.Count <= MaximumBodySize &&
                method.Body.Instructions.Any(instruction =>
                    instruction.OpCode.Code == Code.Ldstr))
            .OrderBy(method => method.MDToken.Raw)
            .Take(MaximumCandidates)];

    /// <summary>
    /// Runs a candidate twice from separately built states and keeps the answer only if both runs
    /// agree, both complete, and neither leaves anything behind.
    /// </summary>
    private static string? Folded(Instruction instruction, Dictionary<uint, string> proven) =>
        instruction.OpCode.Code == Code.Call &&
        instruction.Operand is IMethod called &&
        proven.TryGetValue(called.MDToken.Raw, out var text)
            ? text
            : null;

    private static bool IsDelegateInvoke(Instruction instruction) =>
        instruction.OpCode.Code is Code.Callvirt or Code.Call &&
        instruction.Operand is IMethod invoked &&
        invoked.Name == "Invoke" &&
        invoked.MethodSig?.Params.Count == 0;

    /// <summary>Instructions some branch or handler in the method points at.</summary>
    private static HashSet<Instruction> Targeted(MethodDef method)
    {
        var targeted = new HashSet<Instruction>();
        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.Operand is Instruction single)
                targeted.Add(single);
            else if (instruction.Operand is IList<Instruction> many)
                targeted.UnionWith(many.Where(target => target is not null));
        }
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            foreach (var edge in new[]
                     {
                         handler.TryStart, handler.TryEnd, handler.HandlerStart,
                         handler.HandlerEnd, handler.FilterStart
                     })
            {
                if (edge is not null)
                    targeted.Add(edge);
            }
        }

        return targeted;
    }

    /// <summary>
    /// Static delegate fields that can only ever hold one of the proven decoders.
    /// </summary>
    /// <remarks>
    /// The samples do not always call the decoder. Sometimes they bind it to a delegate in a type
    /// initializer and call through the field, which hides the call behind an indirection the
    /// listing cannot see through. A field written exactly once, in one place, with a delegate over
    /// a null target and a known method, holds that method and nothing else for the life of the
    /// program, so calling through it is calling the decoder.
    /// </remarks>
    private static Dictionary<uint, string> Delegates(
        ModuleDef module,
        Dictionary<uint, string> proven)
    {
        var bound = new Dictionary<uint, string>();
        var written = new Dictionary<uint, int>();
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods)
                     .Where(method => method.HasBody))
        {
            var instructions = method.Body.Instructions;
            for (var index = 0; index < instructions.Count; index++)
            {
                if (instructions[index].OpCode.Code != Code.Stsfld ||
                    instructions[index].Operand is not IField field)
                {
                    continue;
                }

                var token = field.MDToken.Raw;
                written[token] = written.GetValueOrDefault(token) + 1;
                if (index < 3 ||
                    instructions[index - 1].OpCode.Code != Code.Newobj ||
                    instructions[index - 2].OpCode.Code != Code.Ldftn ||
                    instructions[index - 2].Operand is not IMethod target ||
                    instructions[index - 3].OpCode.Code != Code.Ldnull ||
                    !proven.TryGetValue(target.MDToken.Raw, out var text))
                {
                    continue;
                }

                bound[token] = text;
            }
        }

        return bound.Where(entry => written[entry.Key] == 1)
            .ToDictionary(entry => entry.Key, entry => entry.Value);
    }

    /// <summary>What one machine made of each candidate, in the order it was asked.</summary>
    private static Dictionary<uint, Answer> Read(StaticMachine machine, MethodDef[] candidates)
    {
        var answers = new Dictionary<uint, Answer>();
        foreach (var candidate in candidates)
        {
            var answered = machine.Execute(candidate);
            if (!answered.Succeeded)
            {
                answers[candidate.MDToken.Raw] = new Answer(
                    null, false, answered.Diagnostic ?? "the interpretation did not complete");
                continue;
            }
            if (!machine.State.Heap.TryGetString(answered.Value, out var read) || read is null)
            {
                answers[candidate.MDToken.Raw] = new Answer(
                    null, false, "what it returned was not a readable string");
                continue;
            }

            var effects = machine.State.LoaderEvidence.EffectsOf(candidate.MDToken.Raw);
            answers[candidate.MDToken.Raw] = new Answer(
                read,
                effects.WroteStaticField || effects.WroteMappedImage ||
                    effects.Registrations.Count != 0,
                string.Empty);
        }

        return answers;
    }

    private sealed record Answer(string? Text, bool Marked, string Why);
}
