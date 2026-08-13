using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Passes;

namespace ReactorUnpack.Core.Recovery;

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

    // The engine only runs once its proxies resolve to direct calls, so this has to follow the
    // passes that restore them, and it has to precede the cleanup that would delete the engine.
    public override IReadOnlyCollection<string> Dependencies => ["loader-call-elision"];

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
