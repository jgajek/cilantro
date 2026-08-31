using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

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
///
/// The other shape a hidden string takes is one decoder for the whole module, asked for a string by
/// number: the startup path builds a table of every string the program uses, and each call site
/// pushes its index and calls the decoder. Such a decoder carries no literal of its own — the table
/// it reads is somewhere else entirely, sometimes behind code the module generates as it starts —
/// so the account of what makes a call replaceable has to be made per call rather than per method.
/// It is the same account: the index is a literal in the caller's own body, so the decoder is asked
/// exactly the questions the program asks it, and an answer is kept only when both machines give it
/// and the frame left nothing behind. Only indexes that appear literally are asked, which is what
/// keeps a table with no bound on its size from being enumerated.
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

    /// <summary>
    /// How many answers a keyed decoder is worth asking for, across the whole module.
    /// </summary>
    private const int MaximumAnswers = 2048;

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
            !facts.IsReactor)
        {
            return (PassStatus.Success, 0,
                ["No Reactor structure was detected, so no string decoder was looked for."]);
        }

        var candidates = Candidates(context.Module);
        var asked = Asked(context.Module, Keyed(context.Module));
        if (candidates.Length == 0 && asked.Count == 0)
            return (PassStatus.Success, 0, ["No method has the shape of a string decoder."]);

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

        var answers = Agreed(
            Read(forwards, context.Module, asked),
            Read(backwards, context.Module, Reversed(asked)),
            refused);
        if (proven.Count == 0 && answers.Count == 0)
        {
            return (PassStatus.Success, 0,
            [
                $"None of the {candidates.Length + asked.Count} candidate decoder(s) was proven " +
                "to return a fixed string.",
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
                else if (index > 0 &&
                    Asks(instructions[index - 1], instruction, out var decoder, out var key) &&
                    answers.TryGetValue((decoder, key), out text) &&
                    !targeted.Contains(instruction))
                {
                    // The key is pushed and consumed on the spot, so the pair is one expression.
                    // Blanking the push keeps every offset and every branch target where it was,
                    // and a jump that lands on it still leaves one string behind.
                    transaction.Capture(instructions[index - 1]);
                    transaction.Capture(instruction);
                    instructions[index - 1].OpCode = OpCodes.Nop;
                    instructions[index - 1].Operand = null;
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
        context.SetFact("strings.constantSites", changes);
        foreach (var (token, text) in proven.OrderBy(entry => entry.Key))
        {
            context.AddEvidence(new Evidence(
                "constant-string",
                $"{token:X8} returns \"{text}\".",
                $"{token:X8}",
                1.0));
        }

        // A keyed decoder answers as many strings as the program asks it for, and listing them one
        // by one would bury the rest of the report. The strings themselves are in the change log,
        // each against the call site it replaced.
        foreach (var group in answers.GroupBy(entry => entry.Key.Token).OrderBy(group => group.Key))
        {
            context.AddEvidence(new Evidence(
                "constant-string-table",
                $"{group.Key:X8} answers {group.Count()} requested key(s) with a fixed string.",
                $"{group.Key:X8}",
                1.0));
        }

        return (PassStatus.Success, changes,
        [
            $"Proved {proven.Count} of {candidates.Length} candidate decoder(s) constant, read " +
            $"{answers.Count} string(s) out of {asked.Count} keyed decoder(s), and replaced " +
            $"{changes} call(s) with the string.",
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
    /// Methods shaped like a table decoder: a number in, a string out.
    /// </summary>
    /// <remarks>
    /// There is no literal to require here, because a decoder of this shape does not carry the
    /// strings it hands out. What bounds the cost instead is that only the keys the module names
    /// literally are ever asked for, so a decoder nothing calls with a constant costs nothing.
    /// </remarks>
    private static MethodDef[] Keyed(ModuleDef module) =>
        [.. module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method is
                {
                    HasBody: true,
                    IsStatic: true,
                    HasGenericParameters: false
                } &&
                method.MethodSig?.Params.Count == 1 &&
                method.MethodSig.Params[0].ElementType == ElementType.I4 &&
                method.ReturnType.FullName == "System.String" &&
                method.Body.Instructions.Count <= MaximumBodySize)
            .OrderBy(method => method.MDToken.Raw)
            .Take(MaximumCandidates)];

    /// <summary>The keys each keyed decoder is asked for literally, in the order they appear.</summary>
    private static Dictionary<uint, List<int>> Asked(ModuleDef module, MethodDef[] keyed)
    {
        var wanted = keyed.ToDictionary(method => method.MDToken.Raw, _ => new List<int>());
        var budget = MaximumAnswers;
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods)
                     .Where(method => method.HasBody))
        {
            var instructions = method.Body.Instructions;
            for (var index = 1; index < instructions.Count && budget > 0; index++)
            {
                if (!Asks(instructions[index - 1], instructions[index], out var token, out var key) ||
                    !wanted.TryGetValue(token, out var keys) ||
                    keys.Contains(key))
                {
                    continue;
                }

                keys.Add(key);
                budget--;
            }
        }

        return wanted.Where(entry => entry.Value.Count != 0)
            .ToDictionary(entry => entry.Key, entry => entry.Value);
    }

    private static Dictionary<uint, List<int>> Reversed(Dictionary<uint, List<int>> asked) =>
        asked.Reverse().ToDictionary(
            entry => entry.Key,
            entry => Enumerable.Reverse(entry.Value).ToList());

    /// <summary>
    /// Whether one instruction pushes a literal key that the next hands to a keyed decoder.
    /// </summary>
    private static bool Asks(
        Instruction pushed,
        Instruction called,
        out uint decoder,
        out int key)
    {
        decoder = 0;
        key = 0;
        if (!pushed.IsLdcI4() ||
            called.OpCode.Code != Code.Call ||
            called.Operand is not IMethod target ||
            target.MethodSig?.Params.Count != 1)
        {
            return false;
        }

        decoder = target.MDToken.Raw;
        key = pushed.GetLdcI4Value();
        return true;
    }

    /// <summary>
    /// The answers both machines gave, for the keys where they gave the same one and the frame left
    /// nothing behind.
    /// </summary>
    private static Dictionary<(uint Token, int Key), string> Agreed(
        Dictionary<(uint Token, int Key), Answer> ahead,
        Dictionary<(uint Token, int Key), Answer> behind,
        List<string> refused)
    {
        var agreed = new Dictionary<(uint Token, int Key), string>();
        var unreadable = new Dictionary<uint, int>();
        foreach (var (asked, first) in ahead)
        {
            var second = behind[asked];
            if (first.Text is null || second.Text is null)
                unreadable[asked.Token] = unreadable.GetValueOrDefault(asked.Token) + 1;
            else if (!string.Equals(first.Text, second.Text, StringComparison.Ordinal))
                refused.Add($"{asked.Token:X8}({asked.Key}): it answered differently the second time");
            else if (first.Marked || second.Marked)
                refused.Add(
                    $"{asked.Token:X8}: it leaves something behind that removing the call " +
                    "would remove too");
            else
                agreed[asked] = first.Text;
        }

        // One decoder with a few keys it will not answer is ordinary — a program asks for indexes
        // it never reaches. Counting them per decoder says that without filling the report.
        foreach (var (token, count) in unreadable.OrderBy(entry => entry.Key))
            refused.Add($"{token:X8}: {count} of its key(s) yielded no readable string");
        return agreed;
    }

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
            answers[candidate.MDToken.Raw] = Ask(machine, candidate, []);
        return answers;
    }

    /// <summary>What one machine made of each key it was asked for, in the order it was asked.</summary>
    private static Dictionary<(uint Token, int Key), Answer> Read(
        StaticMachine machine,
        ModuleDef module,
        Dictionary<uint, List<int>> asked)
    {
        var decoders = module.GetTypes().SelectMany(type => type.Methods)
            .Where(method => asked.ContainsKey(method.MDToken.Raw))
            .ToDictionary(method => method.MDToken.Raw);
        var answers = new Dictionary<(uint Token, int Key), Answer>();
        foreach (var (token, keys) in asked)
        {
            var decoder = decoders[token];
            var settled = Settled(machine, decoder);
            foreach (var key in keys)
            {
                answers[(token, key)] = settled
                    ? Ask(machine, decoder, [StaticValue.FromInt32(key)])
                    : new Answer(
                        null,
                        false,
                        "initializing its type does more than set that type up, so the call has " +
                        "to stay to trigger it");
            }
        }

        return answers;
    }

    /// <summary>
    /// Initializes the decoder's type, and reports whether doing so only set that type up.
    /// </summary>
    /// <remarks>
    /// A type initializer runs once, triggered by whoever gets there first, so charging it to the
    /// first call that happened to be interpreted would refuse every decoder for something no call
    /// of it is responsible for. Running it up front puts those writes where they belong and leaves
    /// each call answering for itself.
    ///
    /// Whether it can be left untriggered is a separate question, and it is the reason the account
    /// is read here. Folding every call away can mean nothing triggers the initializer at all. For
    /// the type's own fields that is exactly what the runtime's rules make harmless, since anything
    /// that reads one runs the initializer first. An initializer that reaches further — patching the
    /// image, handing the runtime a handler, writing somebody else's field — is doing work the
    /// program depends on happening, and the call that triggers it has to stay.
    /// </remarks>
    private static bool Settled(StaticMachine machine, MethodDef decoder)
    {
        if (decoder.DeclaringType?.FindStaticConstructor() is not { HasBody: true } initializer)
            return true;
        if (machine.State.GetTypeInitializationStatus(decoder.DeclaringType) ==
            TypeInitializationStatus.Uninitialized)
        {
            machine.Execute(initializer);
        }

        var effects = machine.State.LoaderEvidence.EffectsOf(initializer.MDToken.Raw);
        var own = $"{decoder.DeclaringType.FullName}::";
        return !effects.WroteMappedImage &&
            effects.Registrations.Count == 0 &&
            effects.StaticFieldsWritten.All(field =>
                field.Contains(own, StringComparison.Ordinal));
    }

    /// <summary>
    /// Interprets one decoder and reports its answer, together with whether the call left anything
    /// behind that removing it would take with it.
    /// </summary>
    private static Answer Ask(
        StaticMachine machine,
        MethodDef decoder,
        IReadOnlyList<StaticValue> arguments)
    {
        // The loader calls these decoders too, and the machine remembers what every call under this
        // method touched. Setting that aside for the duration is what makes the account below about
        // this call rather than about the module's startup.
        using var alone = machine.State.Evidence.SetAside(decoder.MDToken.Raw);
        var answered = machine.Execute(decoder, arguments);
        if (!answered.Succeeded)
            return new Answer(null, false, answered.Diagnostic ?? "the interpretation did not complete");
        if (!machine.State.Heap.TryGetString(answered.Value, out var read) || read is null)
            return new Answer(null, false, "what it returned was not a readable string");
        var effects = machine.State.LoaderEvidence.EffectsOf(decoder.MDToken.Raw);
        return new Answer(
            read,
            effects.WroteStaticField || effects.WroteMappedImage ||
                effects.Registrations.Count != 0,
            string.Empty);
    }

    private sealed record Answer(string? Text, bool Marked, string Why);
}
