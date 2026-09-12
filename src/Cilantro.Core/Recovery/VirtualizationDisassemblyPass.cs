using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Reads back the program behind each virtualized method, so the report can say what it contains.
/// </summary>
/// <remarks>
/// A virtualized method is the one part of a protected assembly that a decompiler shows as an empty
/// stub, and until its operations mean something the honest answer is that the tool cannot recover
/// it. That is not the same as having nothing to say. The engine's own decoder, run under the
/// machine, yields the whole program: how many operations it has, how many distinct operations the
/// build uses, and — because operands that are metadata tokens resolve against this module — which
/// methods, fields, and types the hidden code reaches for. That last part is most of what an
/// analyst wants from a method they cannot read.
///
/// Nothing here modifies the module. The listing is written next to the report, the stub is left
/// exactly as it was, and the pass does not gate emission, because a program that could not be read
/// back says nothing about whether the rest of the recovery is sound.
/// </remarks>
public sealed class VirtualizationDisassemblyPass : DeobfuscationPass
{
    public override string Name => "virtualization-disassembly";
    public override bool GatesEmission => false;

    // The engine only runs once its proxies resolve to direct calls, so this has to follow the pass
    // that restores them, and it has to precede the cleanup that would delete the engine. Naming the
    // loader elision instead named a pass that happened to be late rather than the one the
    // requirement is about, and reading the engine is what the late string reading depends on, so
    // that spelling put the resource passes behind a reading that could not run until they had.
    public override IReadOnlyCollection<string> Dependencies => ["delegate-proxy-analysis"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<VirtualizedMethod>>(
                "virtualization.methods", out var virtualized) ||
            virtualized is null ||
            virtualized.Count == 0)
        {
            return (PassStatus.Success, 0,
                ["No method was replaced by interpreter bytecode, so there is nothing to read."]);
        }

        var programs = new List<VirtualProgram>();
        var diagnostics = new List<string>();
        EnsureOtherProgramOperations(context, diagnostics);
        foreach (var method in virtualized)
        {
            var program = VirtualProgramRecovery.Recover(context, method, out var diagnostic);
            diagnostics.Add($"{method.Stub.Name}: {diagnostic}");
            if (program is not null)
                programs.Add(program);
        }

        context.SetFact<IReadOnlyList<VirtualProgram>>("virtualization.programs", programs);
        if (programs.Count == 0)
        {
            context.SetFact("virtualization.operations", 0);
            context.SetFact("virtualization.operationsRead", 0);
            context.SetFact("virtualization.operationsWalked", 0);
            context.SetFact("virtualization.depthDisagreements", 0);
            return (PassStatus.Partial, 0, diagnostics);
        }

        // The stub stays. Saying what a method contains is not the same as recovering it, and
        // rewriting anything on the strength of a listing would claim the stronger result.
        diagnostics.Add(
            $"{programs.Count} program(s) were read back; the stubs were left as they are, " +
            "because their operations have not been given meaning yet.");

        // Every program the file holds is found and read back before any of them is measured, and
        // then what each made of the engine is offered to the rest. Measuring first would report
        // each program as the reading it arrived with rather than as the reading it ends up with.
        ReportOtherInvocations(context, virtualized, diagnostics);
        ShareReadings(context, diagnostics);

        var operations = 0;
        var read = 0;
        var walked = 0;
        var disagreed = 0;
        foreach (var program in Stubbed(context, programs))
        {
            var named = program.Method.Stub.Name;
            var opcodes = program.Instructions.Select(item => item.Opcode).Distinct().Count();
            var reading = VirtualLift.Measure(program, context.Module);
            read += reading.Read;
            operations += reading.Operations;
            walked += reading.Walked;
            disagreed += reading.Disagreed;
            diagnostics.Add(
                $"{named}: {opcodes} distinct operation(s), " +
                $"{Named(program, context).Count} named reference(s) to this module.");
            diagnostics.Add(
                $"{named}: {reading.Read} of {reading.Operations} operation(s) read as " +
                $"IL, and the stack walk reaches {reading.Walked} of them" +
                (reading.Disagreed == 0
                    ? ", agreeing with itself everywhere."
                    : $", {reading.Disagreed} of them at two depths, which means a reading is wrong."));
        }

        context.SetFact("virtualization.operations", operations);
        context.SetFact("virtualization.operationsRead", read);
        context.SetFact("virtualization.operationsWalked", walked);
        context.SetFact("virtualization.depthDisagreements", disagreed);
        return (PassStatus.Success, 0, diagnostics);
    }

    /// <summary>The stub programs as they stand, the sharing having replaced them.</summary>
    private static IReadOnlyList<VirtualProgram> Stubbed(
        ArtifactContext context,
        IReadOnlyList<VirtualProgram> recovered) =>
        context.TryGetFact<IReadOnlyList<VirtualProgram>>(
            "virtualization.programs", out var shared) && shared is not null
            ? shared
            : recovered;

    /// <summary>
    /// Gives every program the file holds the readings of the engine's operations that any of them
    /// managed to make.
    /// </summary>
    /// <remarks>
    /// What an operation does is a property of the build and not of the program being run: the
    /// engine dispatches on numbers assigned once when the protector built the file, and both
    /// programs are handed to the same engine. So a reading one program established holds for the
    /// other, and where the other's own attempt came back with less, the better reading is the true
    /// one for it too.
    ///
    /// This is worth doing because the attempts are not equally lucky. The trials ask the engine to
    /// perform an operation in the state a particular run left behind, and an operation that could
    /// not be made to run there goes unread — while the same operation, reached from the other
    /// program's run, performs and is named. On the samples here the larger program reads six
    /// operations that the smaller one does not, and the smaller one reads none that the larger
    /// does not, so the sharing is all gain and in one direction.
    /// </remarks>
    private static void ShareReadings(ArtifactContext context, List<string> diagnostics)
    {
        var stubbed = context.TryGetFact<IReadOnlyList<VirtualProgram>>(
            "virtualization.programs", out var first) && first is not null ? first : [];
        var elsewhere = context.TryGetFact<IReadOnlyList<VirtualProgram>>(
            "virtualization.otherPrograms", out var second) && second is not null ? second : [];
        if (stubbed.Count + elsewhere.Count < 2)
            return;

        var shared = VirtualProgramRecovery.Shared(
            [.. stubbed, .. elsewhere], context.Module, out var gained);
        if (gained == 0)
        {
            diagnostics.Add(
                "Reading the programs alongside one another settled nothing further: each had " +
                "made of the engine's operations everything the others had.");
            return;
        }

        context.SetFact<IReadOnlyList<VirtualProgram>>(
            "virtualization.programs", shared.Take(stubbed.Count).ToArray());
        context.SetFact<IReadOnlyList<VirtualProgram>>(
            "virtualization.otherPrograms", shared.Skip(stubbed.Count).ToArray());
        diagnostics.Add(
            $"Reading the programs alongside one another settled {gained} operation(s) that the " +
            "program using them had not read on its own, the engine's numbering being the " +
            "build's rather than any one program's.");
    }

    /// <summary>
    /// Says which programs the interpreter is asked to run from somewhere other than a stub, so the
    /// count of methods replaced is not mistaken for the count of programs in the file.
    /// </summary>
    /// <remarks>
    /// This is the first point where the question can be asked. The entry has to be known, which
    /// takes a matched stub, and the calls to it have to be direct, which takes the proxies being
    /// resolved — and this pass already waits for both.
    ///
    /// What it finds on a Reactor file is the program a static constructor runs, which is the one
    /// that assigns the state every opaque predicate in the module reads. That is worth naming for
    /// two reasons. It is the difference between a report saying the file holds one program and
    /// saying it holds two. And it is why the flattening cannot be undone by reading the fields the
    /// predicates test: nothing here writes them, but this program does, through code it builds
    /// while it runs, so they are not the constants a search for writes would make them look like.
    /// </remarks>
    private static void ReportOtherInvocations(
        ArtifactContext context,
        IReadOnlyList<VirtualizedMethod> virtualized,
        List<string> diagnostics)
    {
        var invocations = VirtualizedMethodDetector.Invocations(context.Module, virtualized);
        context.SetFact<IReadOnlyList<VirtualInvocation>>("virtualization.invocations", invocations);
        var elsewhere = invocations.Where(invocation => !invocation.Replaced).ToArray();
        if (elsewhere.Length == 0)
        {
            diagnostics.Add(
                "The interpreter is asked for no program other than the ones whose stubs were " +
                "matched, so the file holds no virtualized code beyond them.");
            return;
        }

        diagnostics.Add(
            $"The interpreter is asked for {elsewhere.Length} further program(s) from " +
            "method(s) that do work of their own, so these are programs the file holds that no " +
            "stub stands for and no body can be built into.");

        // Kept apart from the programs the stubs name, because the rebuild reads those and writes
        // each one into the method it came from. Doing that here would put a program where a method
        // that also does other work used to be, and lose the other work.
        var read = new List<VirtualProgram>();
        foreach (var invocation in elsewhere)
        {
            context.AddEvidence(new Evidence(
                "virtualized-program",
                $"Program {invocation.ProgramId} of the interpreter at " +
                $"{invocation.Entry.DeclaringType?.Name}::{invocation.Entry.Name} is run from " +
                $"{(invocation.Caller.IsStaticConstructor ? "the type initializer" : "the body")} " +
                $"of this method, which does other work besides.",
                $"{invocation.Caller.MDToken} {invocation.Caller.FullName} " +
                $"IL_{invocation.Call.Offset:X4}",
                0.9));

            var program = VirtualProgramRecovery.Recover(
                context,
                new VirtualizedMethod(
                    invocation.Caller,
                    invocation.Entry,
                    invocation.ProgramId,
                    invocation.Caller.Parameters.Count),
                out var diagnostic);
            diagnostics.Add(
                $"{invocation.Caller.Name}: runs program {invocation.ProgramId} at " +
                $"IL_{invocation.Call.Offset:X4}. {diagnostic}");
            if (program is null)
                continue;
            read.Add(program);
            diagnostics.Add(
                $"{invocation.Caller.Name}: program {invocation.ProgramId} names " +
                $"{Named(program, context).Count} reference(s) to this module. What it assigns is " +
                "assigned by no instruction in the file, which is what puts the fields the " +
                "flattening tests beyond a search for what writes them.");
        }
        context.SetFact<IReadOnlyList<VirtualProgram>>("virtualization.otherPrograms", read);
    }

    /// <summary>
    /// Records the operations the string table's own program performs, so the reading of each
    /// virtualized method can name the engine operations its own program never uses.
    /// </summary>
    /// <remarks>
    /// The numbering an engine gives its operations is one thing across all of its programs, but a
    /// reading only ever sees the operations of the program it read: the loader initializer uses one
    /// set, and the string table's program another. The earlier string reading would have left this
    /// census behind, except that it runs before the proxies are resolved and so cannot yet run the
    /// engine to frame the program. By here the proxies are direct calls, so the program frames and
    /// its operations can be taken — and taken once, only where the earlier reading left nothing.
    /// </remarks>
    private static void EnsureOtherProgramOperations(
        ArtifactContext context,
        List<string> diagnostics)
    {
        if (context.TryGetFact<IReadOnlyDictionary<int, long?>>(
                "strings.vmOperations", out var already) &&
            already is { Count: > 0 })
        {
            return;
        }

        var proxies = ProxyLoaderTable.Read(context);
        foreach (var resolver in StringResolverCandidates.In(context.Module))
        {
            if (!Strings.StaticStringTableInterpreter.TryReadOperations(
                    context.Module, context.OriginalImage, resolver,
                    BootstrapMachine.Environment(context),
                    out var census, out var why, proxies) ||
                census.Count == 0)
            {
                continue;
            }
            context.SetFact("strings.vmOperations", census);
            diagnostics.Add(
                $"{resolver.DeclaringType.Name}::{resolver.Name}: {why} These are named alongside " +
                "this program's own so the later reading meets no operation it has no meaning for.");
            return;
        }
    }

    /// <summary>
    /// The module members a program's operands name, which is what the listing is read for.
    /// </summary>
    internal static IReadOnlyList<string> Named(VirtualProgram program, ArtifactContext context)
    {
        var named = new HashSet<string>(StringComparer.Ordinal);
        foreach (var instruction in program.Instructions)
        {
            if (instruction.Operand is not VirtualOperand.Number number ||
                number.Value is < int.MinValue or > int.MaxValue)
            {
                continue;
            }
            var token = (int)number.Value;
            if ((token >>> 24) is not (0x01 or 0x02 or 0x04 or 0x06 or 0x0A or 0x0B or 0x1B))
                continue;
            try
            {
                if (context.Module.ResolveToken(token) is { } resolved)
                    named.Add(resolved.ToString() ?? string.Empty);
            }
            catch (Exception exception) when (
                exception is ArgumentException or InvalidOperationException)
            {
                // A number that looks like a token but names nothing is just a number.
            }
        }
        return [.. named];
    }
}
