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
        var operations = 0;
        var read = 0;
        var walked = 0;
        var disagreed = 0;
        EnsureOtherProgramOperations(context, diagnostics);
        foreach (var method in virtualized)
        {
            var program = VirtualProgramRecovery.Recover(context, method, out var diagnostic);
            diagnostics.Add($"{method.Stub.Name}: {diagnostic}");
            if (program is null)
                continue;
            programs.Add(program);
            var opcodes = program.Instructions.Select(item => item.Opcode).Distinct().Count();
            var reading = VirtualLift.Measure(program, context.Module);
            read += reading.Read;
            operations += reading.Operations;
            walked += reading.Walked;
            disagreed += reading.Disagreed;
            diagnostics.Add(
                $"{method.Stub.Name}: {opcodes} distinct operation(s), " +
                $"{Named(program, context).Count} named reference(s) to this module.");
            diagnostics.Add(
                $"{method.Stub.Name}: {reading.Read} of {reading.Operations} operation(s) read as " +
                $"IL, and the stack walk reaches {reading.Walked} of them" +
                (reading.Disagreed == 0
                    ? ", agreeing with itself everywhere."
                    : $", {reading.Disagreed} of them at two depths, which means a reading is wrong."));
        }

        context.SetFact<IReadOnlyList<VirtualProgram>>("virtualization.programs", programs);
        context.SetFact("virtualization.operations", operations);
        context.SetFact("virtualization.operationsRead", read);
        context.SetFact("virtualization.operationsWalked", walked);
        context.SetFact("virtualization.depthDisagreements", disagreed);
        if (programs.Count == 0)
            return (PassStatus.Partial, 0, diagnostics);

        // The stub stays. Saying what a method contains is not the same as recovering it, and
        // rewriting anything on the strength of a listing would claim the stronger result.
        diagnostics.Add(
            $"{programs.Count} program(s) were read back; the stubs were left as they are, " +
            "because their operations have not been given meaning yet.");
        return (PassStatus.Success, 0, diagnostics);
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
