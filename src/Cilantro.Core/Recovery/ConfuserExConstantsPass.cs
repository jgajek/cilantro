using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>
/// One value ConfuserEx moved out of the metadata, and the call sites that asked for it.
/// </summary>
public sealed record RecoveredConstant(
    string Kind,
    uint Decrypter,
    uint Id,
    int Length,
    string? Text,
    string? Base64,
    IReadOnlyList<string> Sites);

/// <summary>
/// Recovers the constants ConfuserEx packed into a decrypted buffer, by asking the module's own
/// getters for them and putting the strings back where they were read.
/// </summary>
/// <remarks>
/// ConfuserEx empties the string heap: every literal is moved into one compressed, encrypted
/// buffer, and each use becomes a number handed to a generic getter that reads the buffer and
/// returns the value at that offset as whatever type the call site asked for. What is left in a
/// listing is arithmetic and a call to a method with an invisible name, and the module's #US stream
/// is four bytes long.
///
/// The buffer's format, its compression and the key are all decided per build, so the only reliable
/// account of them is the one the module carries. The getters are interpreted rather than
/// reimplemented, and they are asked exactly the questions the program asks: only numbers that
/// appear literally at a call site, so a buffer of unknown size is never enumerated.
///
/// The account of what makes an answer usable is the one the rest of the tool gives. Two machines,
/// built separately and asked in opposite orders, must return the same value, and the getter's
/// frame must leave nothing behind — a decrypter that writes state is not one whose call can be
/// removed. Strings are then put back all at once or not at all, with the module verified before
/// anything is kept.
///
/// Only strings are written back into the code. The rest are reported rather than rebuilt: a byte
/// array would have to be re-emitted as field data and an initializer call, which is a larger
/// change to the module than reading its contents justifies, and the contents are what an analyst
/// is after.
/// </remarks>
public sealed class ConfuserExConstantsPass : DeobfuscationPass
{
    public override string Name => "confuserex-constants";
    public override IReadOnlyCollection<string> Dependencies => ["confuserex-antitamper"];

    /// <summary>
    /// A literal that could not be read leaves the module readable, so this does not hold back the
    /// cleaned copy the way a half-decrypted image would.
    /// </summary>
    public override bool GatesEmission => false;

    /// <summary>
    /// Reading the buffer means running the decompressor the module carries, one interpreted
    /// instruction per byte it produces, so the budget is sized for the buffer rather than the code.
    /// </summary>
    private const int Steps = 64_000_000;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<ConfuserExStructureFacts>("confuserex.structure", out var facts) ||
            facts is null || !facts.IsConfuserExProtected)
        {
            return (PassStatus.Success, 0, ["Not ConfuserEx-protected; no constants table to read."]);
        }

        var getters = Getters(context.Module);
        if (getters.Count == 0)
            return (PassStatus.Success, 0, ["This build carries no ConfuserEx constants getter."]);

        var buffers = Buffers(getters);
        var initializers = Initializers(context.Module, buffers);
        if (initializers.Count == 0)
        {
            return (PassStatus.Unsupported, 0,
            [
                $"{getters.Count} constants getter(s) read {buffers.Count} buffer(s), but nothing " +
                "in the module fills them, so there is no table to read."
            ]);
        }

        var sites = Sites(context.Module, getters);
        if (sites.Proven.Count == 0)
        {
            return (PassStatus.Unsupported, 0,
            [
                $"Nothing could be asked of the getters: of {sites.Total} constants call site(s), " +
                $"{sites.Unproven} do not state their number literally and {sites.Unhandled} ask " +
                "for neither a string nor an array."
            ]);
        }

        context.AddEvidence(new Evidence(
            "capability",
            "constants-table",
            $"{getters.Count} getter(s) over {buffers.Count} buffer(s)",
            0.95));

        var asks = sites.Proven
            .Select(site => (site.Getter, site.Id, site.Spec, site.Kind))
            .Distinct()
            .ToArray();

        // Two machines rather than one asked twice: an answer that depended on what ran before it is
        // exactly the answer the two orders disagree about.
        if (!TryPrepare(context, initializers, out var forwards, out var why) || forwards is null)
            return (PassStatus.Unsupported, 0, [$"The constants table could not be built: {why}"]);
        if (!TryPrepare(context, initializers, out var backwards, out why) || backwards is null)
            return (PassStatus.Unsupported, 0, [$"The constants table could not be built: {why}"]);

        var ahead = Read(forwards, asks);
        var behind = Read(backwards, asks.Reverse());
        var refused = new List<string>();
        var agreed = Agreed(ahead, behind, refused);

        var constants = Constants(sites.Proven, agreed);
        context.SetFact("confuserex.constants", constants);

        var replacements = sites.Proven
            .Where(site => site.Kind == ConstantKind.String &&
                agreed.TryGetValue((site.Getter.MDToken.Raw, site.Id), out var answer) &&
                answer.Text is not null)
            .Select(site => (site, Text: agreed[(site.Getter.MDToken.Raw, site.Id)].Text!))
            .ToArray();

        var (status, changes, notes) = Restore(context, replacements, sites.StringSites);
        if (status == PassStatus.Failed)
            return (status, changes, notes);

        var strings = constants.Count(item => item.Kind == "string");
        var arrays = constants.Count - strings;
        context.AddEvidence(new Evidence(
            "confuserex-constants",
            $"Two interpretations agreed on {agreed.Count} of {asks.Length} constant(s) read from " +
            $"the module's own getters: {strings} string(s) and {arrays} array(s).",
            $"{getters.Count} getter(s)",
            0.95));

        var unanswered = asks.Length - agreed.Count;
        var incomplete = unanswered > 0 || sites.Unproven > 0 || sites.Unhandled > 0;
        return (incomplete ? PassStatus.Partial : PassStatus.Success, changes,
        [
            .. notes,
            $"Read {constants.Count} constant(s) from {getters.Count} getter(s): " +
            $"{strings} string(s), {arrays} array(s).",
            arrays > 0
                ? $"{arrays} array constant(s) are reported rather than rewritten, because " +
                  "re-emitting them as field data changes more of the module than reading them does."
                : "No array constants were found.",
            .. sites.Unproven > 0
                ? new[]
                {
                    $"{sites.Unproven} call site(s) do not state their number literally and were " +
                    "left alone."
                }
                : [],
            .. sites.Unhandled > 0
                ? new[]
                {
                    $"{sites.Unhandled} call site(s) ask the getters for neither a string nor an " +
                    "array, and this pass has no way to write down what they hold."
                }
                : [],
            .. refused.Take(10)
        ]);
    }

    // ---- what the module says about itself -------------------------------------------------

    /// <summary>
    /// The generic getters: one number in, whatever the call site asked for out. The shape is the
    /// protector's, but nothing here depends on the name, which is deliberately unreadable.
    /// </summary>
    private static IReadOnlyList<MethodDef> Getters(ModuleDef module) =>
        [.. module.GlobalType.Methods.Where(method =>
            method.IsStatic &&
            method.HasBody &&
            method.GenericParameters.Count == 1 &&
            method.MethodSig?.Params.Count == 1 &&
            method.MethodSig.Params[0].ElementType is ElementType.U4 or ElementType.I4 &&
            method.MethodSig.RetType.ElementType == ElementType.MVar)];

    private static IReadOnlyCollection<FieldDef> Buffers(IReadOnlyList<MethodDef> getters) =>
        [.. getters
            .SelectMany(getter => getter.Body.Instructions)
            .Where(instruction => instruction.OpCode.Code == Code.Ldsfld)
            .Select(instruction => (instruction.Operand as IField)?.ResolveFieldDef())
            .Where(field => field is { FieldType.IsSZArray: true })
            .Distinct()!];

    /// <summary>
    /// Whatever fills the buffers the getters read, found by asking who writes them rather than by
    /// recognizing a shape the next build is free to change.
    /// </summary>
    private static IReadOnlyList<MethodDef> Initializers(
        ModuleDef module, IReadOnlyCollection<FieldDef> buffers) =>
        [.. module.GlobalType.Methods.Where(method =>
            method.HasBody &&
            method.Body.Instructions.Any(instruction =>
                instruction.OpCode.Code == Code.Stsfld &&
                (instruction.Operand as IField)?.ResolveFieldDef() is { } field &&
                buffers.Contains(field)))];

    private enum ConstantKind { String, Bytes, Other }

    private sealed record Site(
        MethodDef Caller,
        Instruction Call,
        Instruction Push,
        MethodSpec Spec,
        MethodDef Getter,
        uint Id,
        ConstantKind Kind);

    /// <param name="Proven">The sites whose number is stated literally, and so can be asked for.</param>
    /// <param name="Unproven">Sites of a kind this pass reads, whose number it could not establish.</param>
    /// <param name="Unhandled">Sites asking for neither a string nor an array, which this pass does not read.</param>
    /// <param name="StringSites">Every string site seen, asked or not, so that coverage is measured rather than assumed.</param>
    private sealed record SiteSurvey(
        IReadOnlyList<Site> Proven,
        int Unproven,
        int Unhandled,
        int StringSites,
        int Total);

    private static SiteSurvey Sites(ModuleDef module, IReadOnlyList<MethodDef> getters)
    {
        var wanted = getters.ToHashSet();
        var found = new List<Site>();
        var unproven = 0;
        var unhandled = 0;
        var stringSites = 0;
        var total = 0;
        foreach (var type in module.GetTypes())
        foreach (var method in type.Methods)
        {
            if (!method.HasBody)
                continue;
            var instructions = method.Body.Instructions;
            for (var index = 0; index < instructions.Count; index++)
            {
                if (instructions[index].OpCode.Code is not (Code.Call or Code.Callvirt) ||
                    instructions[index].Operand is not MethodSpec spec ||
                    spec.Method?.ResolveMethodDef() is not { } target ||
                    !wanted.Contains(target))
                {
                    continue;
                }
                total++;

                // The type asked for is on the call itself, so it is known even where the number is
                // not. A site asking for something this pass has no way to render is set aside here
                // rather than asked and then reported as unreadable, which would say the getter
                // failed when it was never asked a question it could answer.
                var kind = Kind(spec);
                if (kind == ConstantKind.Other)
                {
                    unhandled++;
                    continue;
                }
                if (kind == ConstantKind.String)
                    stringSites++;
                if (!ArgumentTrace.TryFind(method, instructions[index], out var push, out var id))
                {
                    unproven++;
                    continue;
                }
                found.Add(new Site(method, instructions[index], push!, spec, target, id, kind));
            }
        }

        // Blanking a push is only sound while it feeds one call. The trace cannot reach the same
        // push from two calls, but the rewrite's correctness rests on that rather than checking it,
        // so it is checked: where it ever did happen, both sites are left alone.
        var shared = found
            .GroupBy(site => site.Push)
            .Where(group => group.Count() > 1)
            .ToArray();
        if (shared.Length == 0)
            return new SiteSurvey(found, unproven, unhandled, stringSites, total);

        var contested = shared.Select(group => group.Key).ToHashSet();
        return new SiteSurvey(
            [.. found.Where(site => !contested.Contains(site.Push))],
            unproven + shared.Sum(group => group.Count()),
            unhandled,
            stringSites,
            total);
    }

    private static ConstantKind Kind(MethodSpec spec)
    {
        var asked = spec.GenericInstMethodSig?.GenericArguments is { Count: 1 } arguments
            ? arguments[0]
            : null;
        if (asked is null)
            return ConstantKind.Other;
        if (asked.ElementType == ElementType.String)
            return ConstantKind.String;
        return asked.IsSZArray ? ConstantKind.Bytes : ConstantKind.Other;
    }

    // ---- asking the module -----------------------------------------------------------------

    /// <summary>
    /// A machine with the constants buffer built, which means running the initializer that fills it.
    /// </summary>
    /// <remarks>
    /// The initializer is run directly rather than through the module initializer that calls it.
    /// Its siblings under that initializer are the anti-tamper and anti-debug stages, which have
    /// already been interpreted once by the time this runs and would either be interpreted a second
    /// time or stop the run before reaching the constants at all. Running it directly means saying
    /// what is true while it runs: the module initializer is in progress, so the getters' reads of
    /// the module's own statics do not start it again.
    /// </remarks>
    private static bool TryPrepare(
        ArtifactContext context,
        IReadOnlyList<MethodDef> initializers,
        out StaticMachine? machine,
        out string diagnostic)
    {
        if (!BootstrapMachine.TrySeed(context, Steps, out machine, out diagnostic) || machine is null)
            return false;

        machine.State.TryBeginTypeInitialization(context.Module.GlobalType);
        foreach (var initializer in initializers)
        {
            var ran = machine.Execute(initializer);
            if (ran.Succeeded)
                continue;
            diagnostic =
                $"{initializer.MDToken} stopped after {ran.Steps} steps: {ran.Status}" +
                (ran.Diagnostic is { Length: > 0 } detail ? $" ({detail})" : string.Empty);
            machine = null;
            return false;
        }

        return true;
    }

    private sealed record Answer(string? Text, byte[]? Bytes, bool Marked, string Why);

    private static Dictionary<(uint Getter, uint Id), Answer> Read(
        StaticMachine machine,
        IEnumerable<(MethodDef Getter, uint Id, MethodSpec Spec, ConstantKind Kind)> asks)
    {
        var answers = new Dictionary<(uint, uint), Answer>();
        foreach (var ask in asks)
        {
            var key = (ask.Getter.MDToken.Raw, ask.Id);
            if (answers.ContainsKey(key))
                continue;
            answers[key] = Ask(machine, ask.Getter, ask.Spec, ask.Id, ask.Kind);
        }

        return answers;
    }

    private static Answer Ask(
        StaticMachine machine,
        MethodDef getter,
        MethodSpec spec,
        uint id,
        ConstantKind kind)
    {
        using var alone = machine.State.Evidence.SetAside(getter.MDToken.Raw);
        var answered = machine.Invoke(spec, [StaticValue.FromInt32(unchecked((int)id))]);
        if (!answered.Succeeded)
        {
            return new Answer(null, null, false,
                answered.Diagnostic ?? answered.Status.ToString());
        }

        var effects = machine.State.LoaderEvidence.EffectsOf(getter.MDToken.Raw);
        var marked = effects.WroteStaticField || effects.WroteMappedImage ||
            effects.Registrations.Count != 0;
        if (kind == ConstantKind.String)
        {
            return machine.State.Heap.TryGetString(answered.Value, out var text) && text is not null
                ? new Answer(text, null, marked, string.Empty)
                : new Answer(null, null, marked, "what it returned was not a readable string");
        }

        var bytes = machine.State.Heap.GetBytesSnapshot(answered.Value);
        return bytes is not null
            ? new Answer(null, bytes, marked, string.Empty)
            : new Answer(null, null, marked, "what it returned could not be read as bytes");
    }

    private static Dictionary<(uint Getter, uint Id), Answer> Agreed(
        Dictionary<(uint Getter, uint Id), Answer> ahead,
        Dictionary<(uint Getter, uint Id), Answer> behind,
        List<string> refused)
    {
        var agreed = new Dictionary<(uint, uint), Answer>();
        var unreadable = new Dictionary<uint, List<string>>();
        foreach (var (asked, first) in ahead)
        {
            var second = behind[asked];
            if (first.Text is null && first.Bytes is null)
            {
                if (!unreadable.TryGetValue(asked.Getter, out var why))
                    unreadable[asked.Getter] = why = [];
                why.Add(first.Why);
            }
            else if (!Same(first, second))
            {
                refused.Add(
                    $"{asked.Getter:X8}(0x{asked.Id:X8}): it answered differently the second time");
            }
            else if (first.Marked || second.Marked)
            {
                refused.Add(
                    $"{asked.Getter:X8}(0x{asked.Id:X8}): it leaves something behind that removing " +
                    "the call would remove too");
            }
            else
            {
                agreed[asked] = first;
            }
        }

        // Naming the reason matters more here than counting: every number a getter is asked stops
        // for the same cause, and a bare count leaves the one thing that would explain the run out
        // of the report.
        foreach (var (getter, why) in unreadable.OrderBy(entry => entry.Key))
        {
            var distinct = why.Select(Summarize).Where(reason => reason.Length != 0).Distinct().ToArray();
            refused.Add(distinct.Length == 0
                ? $"{getter:X8}: {why.Count} of its number(s) yielded nothing readable"
                : $"{getter:X8}: {why.Count} of its number(s) yielded nothing readable " +
                  $"({string.Join("; ", distinct.Take(2))})");
        }

        return agreed;
    }

    /// <summary>
    /// Reduces a machine diagnostic to the sentence that names the cause.
    /// </summary>
    /// <remarks>
    /// The interpreter's diagnostic carries the full provenance of every argument, which is what the
    /// blocker ledger wants and what a pass summary cannot carry: one of them runs to thousands of
    /// characters. The part worth repeating here is the failure itself, so the provenance is dropped
    /// and the remainder bounded.
    /// </remarks>
    private static string Summarize(string why)
    {
        if (string.IsNullOrEmpty(why))
            return string.Empty;
        var end = why.IndexOf(" | provenance:", StringComparison.Ordinal);
        var head = end < 0 ? why : why[..end];
        // The interpreter prefixes the failing member and offset; the sentence after the last "-> "
        // is the cause, and repeating the member here would only repeat what the ledger already has.
        var arrow = head.LastIndexOf("-> ", StringComparison.Ordinal);
        if (arrow >= 0)
            head = head[(arrow + 3)..];
        var colon = head.LastIndexOf(": ", StringComparison.Ordinal);
        if (colon >= 0)
            head = head[(colon + 2)..];
        head = head.Trim();
        return head.Length <= 120 ? head : head[..117] + "...";
    }

    private static bool Same(Answer first, Answer second) =>
        string.Equals(first.Text, second.Text, StringComparison.Ordinal) &&
        ((first.Bytes is null && second.Bytes is null) ||
            (first.Bytes is not null && second.Bytes is not null &&
                first.Bytes.AsSpan().SequenceEqual(second.Bytes)));

    private static IReadOnlyList<RecoveredConstant> Constants(
        IReadOnlyList<Site> sites,
        Dictionary<(uint Getter, uint Id), Answer> agreed)
    {
        return
        [
            .. sites
                .Where(site => agreed.ContainsKey((site.Getter.MDToken.Raw, site.Id)))
                .GroupBy(site => (site.Getter.MDToken.Raw, site.Id))
                .OrderBy(group => group.Key.Raw).ThenBy(group => group.Key.Id)
                .Select(group =>
                {
                    var answer = agreed[group.Key];
                    return new RecoveredConstant(
                        answer.Text is not null ? "string" : "byte[]",
                        group.Key.Raw,
                        group.Key.Id,
                        answer.Text?.Length ?? answer.Bytes?.Length ?? 0,
                        answer.Text,
                        answer.Bytes is null ? null : Convert.ToBase64String(answer.Bytes),
                        [.. group.Select(site =>
                            $"{site.Caller.MDToken} IL_{site.Call.Offset:X4}")]);
                })
        ];
    }

    // ---- putting the strings back ----------------------------------------------------------

    /// <summary>
    /// Turns every proven string call into the string it hands back, all of them or none.
    /// </summary>
    /// <remarks>
    /// The number is pushed where the protector left it and the call is reached from there by a
    /// jump, so the push is blanked in place and the call becomes the literal. Inserting a pop
    /// before the call, which is what a rewrite of an adjacent pair would do, would be stepped over
    /// by the jump that lands on the call itself and leave the number on the stack.
    /// </remarks>
    private static (PassStatus, int, IReadOnlyList<string>) Restore(
        ArtifactContext context,
        IReadOnlyList<(Site Site, string Text)> replacements,
        int stringSites)
    {
        // Counted whether or not anything was put back, because the point of the pair is to say how
        // much of what was there was recovered, and a pass that rewrote nothing has an answer too.
        context.TryGetFact<int>("strings.callSites", out var countedBefore);
        context.TryGetFact<int>("strings.replacedSites", out var restoredBefore);
        context.SetFact("strings.callSites", countedBefore + stringSites);

        if (replacements.Count == 0)
            return (PassStatus.Success, 0, ["No string call site could be proven."]);

        var transactions = replacements
            .Select(item => item.Site.Caller)
            .Distinct()
            .ToDictionary(method => method, method => new BodyMutationTransaction(method));
        try
        {
            foreach (var (site, text) in replacements)
            {
                if (!site.Caller.Body.Instructions.Contains(site.Call) ||
                    !site.Caller.Body.Instructions.Contains(site.Push))
                {
                    throw new InvalidOperationException(
                        "A constants call site disappeared during rewrite.");
                }
                site.Push.OpCode = OpCodes.Nop;
                site.Push.Operand = null;
                site.Call.OpCode = OpCodes.Ldstr;
                site.Call.Operand = text;
            }

            var verification = AssemblyVerifier.Verify(
                context.Module,
                context.OriginalIdentity,
                context.OriginalStructure);
            if (!verification.Passed)
                throw new InvalidOperationException(string.Join("; ", verification.Diagnostics));
            foreach (var transaction in transactions.Values)
                transaction.Commit();
        }
        catch (Exception exception)
        {
            foreach (var transaction in transactions.Values)
                transaction.Rollback();
            return (PassStatus.Failed, 0,
                [$"Atomic constants rewrite was rolled back: {exception.Message}"]);
        }
        finally
        {
            foreach (var transaction in transactions.Values)
                transaction.Dispose();
        }

        foreach (var (site, text) in replacements)
        {
            context.AddChange(new ChangeRecord(
                "confuserex-constants",
                "restore-string",
                $"{site.Caller.MDToken} IL_{site.Call.Offset:X4}",
                JsonSerializer.Serialize(text)));
        }

        context.SetFact("strings.replacedSites", restoredBefore + replacements.Count);
        return (PassStatus.Success, replacements.Count,
            [$"Atomically restored all {replacements.Count} proven string site(s)."]);
    }
}

/// <summary>
/// Finds the instruction that pushed a call's argument, following the jumps an obfuscator puts
/// between the two.
/// </summary>
/// <remarks>
/// A flattened body does not keep the push next to the call that consumes it: the number is pushed,
/// control jumps, and the call is somewhere else entirely. Reading the preceding instruction finds
/// a branch, and reading a slice by index finds whatever happens to be written above the call.
///
/// What is followed instead is the control flow, backwards, and only while there is one way in. A
/// call reached from two places was reached with two numbers, and taking either would be picking
/// one of the program's paths and calling it the program.
/// </remarks>
internal static class ArgumentTrace
{
    private const int Hops = 16;

    public static bool TryFind(
        MethodDef method,
        Instruction call,
        out Instruction? push,
        out uint value)
    {
        push = null;
        value = 0;
        var at = call;
        for (var hop = 0; hop < Hops; hop++)
        {
            if (!TrySolePredecessor(method, at, out var previous) || previous is null)
                return false;
            if (TryConstant(previous, out value))
            {
                push = previous;
                return true;
            }
            // Only something that leaves the stack as it found it can be stepped over; anything
            // else may be the push, and stepping past it would attribute the wrong number.
            if (previous.OpCode.Code is not (Code.Br or Code.Br_S or Code.Nop))
                return false;
            at = previous;
        }

        return false;
    }

    private static bool TrySolePredecessor(
        MethodDef method,
        Instruction target,
        out Instruction? found)
    {
        found = null;
        // Anywhere control can arrive without having come from an instruction is a second way in,
        // and the stack there is the handler's rather than the body's.
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            if (handler.TryStart == target || handler.HandlerStart == target ||
                handler.FilterStart == target)
            {
                return false;
            }
        }

        var instructions = method.Body.Instructions;
        var index = instructions.IndexOf(target);
        if (index < 0)
            return false;

        Instruction? sole = null;
        if (index > 0 && FallsThrough(instructions[index - 1]))
            sole = instructions[index - 1];
        foreach (var instruction in instructions)
        {
            var reaches = instruction.Operand switch
            {
                Instruction single => single == target,
                Instruction[] cases => Array.IndexOf(cases, target) >= 0,
                _ => false
            };
            if (!reaches || instruction == sole)
                continue;
            if (sole is not null)
                return false;
            sole = instruction;
        }

        found = sole;
        return sole is not null;
    }

    private static bool FallsThrough(Instruction instruction) =>
        instruction.OpCode.FlowControl is not (FlowControl.Branch or FlowControl.Return or
            FlowControl.Throw);

    private static bool TryConstant(Instruction instruction, out uint value)
    {
        value = 0;
        switch (instruction.OpCode.Code)
        {
            case Code.Ldc_I4: value = unchecked((uint)(int)instruction.Operand!); return true;
            case Code.Ldc_I4_S: value = unchecked((uint)(sbyte)instruction.Operand!); return true;
            case Code.Ldc_I4_0: value = 0; return true;
            case Code.Ldc_I4_1: value = 1; return true;
            case Code.Ldc_I4_2: value = 2; return true;
            case Code.Ldc_I4_3: value = 3; return true;
            case Code.Ldc_I4_4: value = 4; return true;
            case Code.Ldc_I4_5: value = 5; return true;
            case Code.Ldc_I4_6: value = 6; return true;
            case Code.Ldc_I4_7: value = 7; return true;
            case Code.Ldc_I4_8: value = 8; return true;
            case Code.Ldc_I4_M1: value = unchecked((uint)-1); return true;
            default: return false;
        }
    }
}
