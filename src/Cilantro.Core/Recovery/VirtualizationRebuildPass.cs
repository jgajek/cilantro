using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Writes the bodies read back from the interpreter's programs into the methods they belong to.
/// </summary>
/// <remarks>
/// This is the one thing the tool puts into an assembly that it cannot prove. Everything else in the
/// cleaned copy is the protector's own output, recovered byte for byte; a body built from a reading
/// of a virtual program is the tool's account of what those operations meant. The reason it goes in
/// anyway is that the alternative served nobody: a second assembly, built from the sample as it
/// shipped, meant reading a virtualized method in a file where nothing else had been recovered —
/// encrypted strings, opaque branches, generated names — while the file with all of that fixed
/// showed the method as an empty stub.
///
/// So the reading is written where it is useful and marked where it is written. Every method built
/// here carries an attribute saying so, which a decompiler shows directly above the method, and the
/// run check either backs the bodies up or says it could not. A strict run does none of this and
/// leaves the stubs alone, because the cleaned copy of a strict run is the one that holds nothing
/// but what was proved.
///
/// The pass runs before cleanup for two reasons. A virtualized method is usually one nothing calls
/// by name, so cleanup would delete it and leave nowhere to put the body; and the bodies name the
/// helpers the hidden code called, which have to survive with them. Declaring the built methods as
/// roots settles both: they are reachable, so is everything they reach, and cleanup removes the rest
/// as before.
/// </remarks>
public sealed class VirtualizationRebuildPass : DeobfuscationPass
{
    public override string Name => "virtualization-rebuild";
    public override bool GatesEmission => false;

    // The programs come from the pass that reads the engine, and everything here has to be in place
    // before cleanup decides what nothing needs any more.
    public override IReadOnlyCollection<string> Dependencies => ["virtualization-disassembly"];

    /// <summary>The methods whose bodies this pass wrote, which cleanup keeps.</summary>
    internal const string RebuiltFact = "virtualization.rebuiltMethods";

    /// <summary>What running the built bodies established, for the report to pass on.</summary>
    internal const string CheckFact = "virtualization.check";

    /// <summary>What the building and the check had to say, in the order they said it.</summary>
    internal const string NotesFact = "virtualization.buildNotes";

    /// <summary>The declarations this pass added, which the identity gate is told about.</summary>
    internal const string AddedTypesFact = "virtualization.addedTypeCount";
    internal const string AddedMethodsFact = "virtualization.addedMethodCount";

    /// <summary>
    /// How many programs run from a method that does other work were given a method of their own.
    /// </summary>
    internal const string LiftedFact = "virtualization.liftedPrograms";

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.devirtualize", out var enabled) || !enabled)
        {
            return (PassStatus.Success, 0,
                ["Virtualized methods were left as stubs, this run not building them back."]);
        }

        if (!context.TryGetFact<IReadOnlyList<VirtualProgram>>(
                "virtualization.programs", out var programs) ||
            programs is null ||
            programs.Count == 0)
        {
            return (PassStatus.Success, 0,
                ["No virtualized program was read back, so there was nothing to build."]);
        }

        var said = new List<string>();
        var built = new List<(MethodDef Method, VirtualBody.Attempt Attempt)>();
        foreach (var program in programs)
        {
            var stub = program.Method.Stub;
            var attempt = VirtualBody.Build(program, context.Module, stub);
            if (attempt.Body is null)
            {
                said.Add($"{stub.Name}: no body was built, {attempt.Refused}.");
                continue;
            }
            built.Add((stub, attempt));
        }

        var liftable = Liftable(context).ToArray();
        if (built.Count == 0 && liftable.Length == 0)
        {
            context.SetFact(NotesFact, (IReadOnlyList<string>)said);
            context.SetFact(CheckFact, DevirtualizationCheck.NotMade);
            return (PassStatus.Success, 0, said);
        }

        // The marker type is only added once there is something to mark, so a run that built
        // nothing leaves the assembly with nothing of the tool's in it.
        var marker = ReadingMarker.Add(context.Module);
        var rebuilt = new HashSet<uint>();
        foreach (var (stub, attempt) in built)
        {
            stub.Body = attempt.Body;
            marker.Mark(stub);
            rebuilt.Add(stub.MDToken.Raw);
            said.Add($"{stub.Name}: {string.Join(" ", attempt.Notes)}");
            context.AddChange(new ChangeRecord(
                Name,
                "rebuild-virtualized-method",
                $"{stub.MDToken} {stub.FullName}",
                "Wrote a body read back from the interpreter's program, marked as a reading."));
        }

        var lifted = Lift(context, liftable, marker, said);
        DeclareEngineOrphaned(context, said);

        context.SetFact<IReadOnlySet<uint>>(RebuiltFact, rebuilt);
        context.SetFact(AddedTypesFact, 1);
        context.SetFact(AddedMethodsFact, ReadingMarker.AddedMethodCount + lifted);
        context.SetFact(LiftedFact, lifted);

        var ran = DevirtualizedRun.Compare(context, programs);
        said.AddRange(ran.Said);
        context.SetFact(CheckFact, ran.Verdict);
        context.SetFact(NotesFact, (IReadOnlyList<string>)said);
        context.AddEvidence(new Evidence(
            Name,
            $"Built {rebuilt.Count} virtualized method(s) back into code in the cleaned copy from " +
            $"the operations read out of the engine's programs, each marked with " +
            $"[{ReadingMarker.TypeName}] as the reading it is. {Verdict(ran.Verdict)}",
            null,
            ran.Verdict == DevirtualizationCheck.Agreed ? 1.0 : 0.5));
        return (PassStatus.Success, rebuilt.Count, said);
    }

    /// <summary>
    /// A program run from a method that does other work, together with the call that runs it, where
    /// the call is plain enough to be redirected at a method holding the program instead.
    /// </summary>
    /// <remarks>
    /// Such a program cannot be written into the method that runs it, because the method is not the
    /// program and writing it there would lose the other work. It can be given a method of its own,
    /// and the call pointed at that — which is worth doing for more than tidiness. On a Reactor file
    /// the interpreter survives cleanup for want of one caller, and this is that caller: the last
    /// thing in the module still asking the engine to run anything. Lifting it is what turns three
    /// quarters of the decompiled output into code nothing reaches.
    ///
    /// Three things have to hold for the redirect to be a swap rather than a rewrite. The program
    /// has to take no arguments, or a method taking none could not stand for it. The values pushed
    /// for the call have to be plain pushes, so that neutralizing them cannot disturb anything
    /// computed on the way. And the result has to be discarded, since a method returning nothing
    /// can only replace a call whose value was going nowhere. Where any of them fails the program
    /// stays listed and unbuilt, which is what it was before.
    /// </remarks>
    private static IEnumerable<(VirtualInvocation Invocation, VirtualProgram Program, int At)>
        Liftable(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<VirtualInvocation>>(
                "virtualization.invocations", out var invocations) ||
            !context.TryGetFact<IReadOnlyList<VirtualProgram>>(
                "virtualization.otherPrograms", out var elsewhere) ||
            invocations is null ||
            elsewhere is null)
        {
            yield break;
        }

        foreach (var invocation in invocations.Where(item => !item.Replaced))
        {
            var program = elsewhere.FirstOrDefault(item =>
                item.Method.ProgramId == invocation.ProgramId &&
                item.Method.Stub == invocation.Caller);
            if (program is null || invocation.Caller.Parameters.Count != 0)
                continue;
            var instructions = invocation.Caller.Body.Instructions;
            var at = instructions.IndexOf(invocation.Call);
            var slots = invocation.Call.Operand is IMethod called && called.MethodSig is { } signature
                ? signature.Params.Count + (signature.HasThis ? 1 : 0)
                : -1;
            if (at < 0 || slots < 0 || at < slots || at + 1 >= instructions.Count)
                continue;
            if (instructions[at + 1].OpCode.Code != Code.Pop)
                continue;
            yield return (invocation, program, at);
        }
    }

    /// <summary>
    /// Gives each liftable program a method of its own and points the call that ran it there.
    /// </summary>
    private int Lift(
        ArtifactContext context,
        IReadOnlyList<(VirtualInvocation Invocation, VirtualProgram Program, int At)> liftable,
        ReadingMarker marker,
        List<string> said)
    {
        var lifted = 0;
        foreach (var (invocation, program, at) in liftable)
        {
            var host = invocation.Caller.DeclaringType;
            var holder = new MethodDefUser(
                $"LiftedProgram{invocation.ProgramId}",
                MethodSig.CreateStatic(context.Module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig);
            host.Methods.Add(holder);

            // Built against the method that will hold it rather than the one that ran it, so the
            // reading is lowered to the signature it is about to live under.
            var attempt = VirtualBody.Build(program, context.Module, holder);
            if (attempt.Body is null)
            {
                host.Methods.Remove(holder);
                said.Add(
                    $"{invocation.Caller.Name}: program {invocation.ProgramId} was not given a " +
                    $"method of its own, {attempt.Refused}.");
                continue;
            }

            // A body written into a stub nothing calls is read and not run, so a reading that is
            // wrong in places is still worth having there. This one would be run: it is what a type
            // initializer does instead of asking the engine, and what it assigns is what the rest
            // of the module goes on. A reading that contradicts itself anywhere is not a thing to
            // put in the way of execution, however much of the file removing the engine would
            // clear, so it is listed and left alone.
            if (attempt.Distrusted > 0)
            {
                host.Methods.Remove(holder);
                said.Add(
                    $"{invocation.Caller.Name}: program {invocation.ProgramId} was not given a " +
                    $"method of its own, the reading being wrong around {attempt.Distrusted} of " +
                    "its operations and this being a body that would run rather than one to read.");
                continue;
            }

            // And a reading has to have reached the program, not merely failed to contradict itself
            // about it. An operation the walk never arrived at stands in the body as a throw, which
            // where the body is read says honestly how far the reading got, and where it is run
            // says the opposite: this is the work the engine used to do, so a body that performs
            // none of it does not replace that work but silently drops it, leaving the rest of the
            // module running on state nothing assigned. Verification would not notice, the body
            // being well-formed, and nor would a reader, the throws being unreachable.
            if (attempt.Unreached > 0)
            {
                host.Methods.Remove(holder);
                said.Add(
                    $"{invocation.Caller.Name}: program {invocation.ProgramId} was not given a " +
                    $"method of its own, the reading having arrived at only " +
                    $"{program.Instructions.Count - attempt.Unreached} of its " +
                    $"{program.Instructions.Count} operations and the rest being work this would " +
                    "drop rather than do.");
                continue;
            }

            holder.Body = attempt.Body;
            marker.Mark(holder);
            var instructions = invocation.Caller.Body.Instructions;
            using var transaction = new InstructionMutationTransaction();
            // The pushes the engine wanted go, the call becomes a call to the method holding the
            // program, and the pop of the result it no longer returns goes with them.
            var slots = at - Pushes(invocation.Call);
            for (var index = slots; index < at; index++)
            {
                transaction.Capture(instructions[index]);
                instructions[index].OpCode = OpCodes.Nop;
                instructions[index].Operand = null;
            }
            transaction.Capture(invocation.Call);
            invocation.Call.OpCode = OpCodes.Call;
            invocation.Call.Operand = holder;
            transaction.Capture(instructions[at + 1]);
            instructions[at + 1].OpCode = OpCodes.Nop;
            instructions[at + 1].Operand = null;

            var verification = AssemblyVerifier.Verify(context.Module);
            if (!verification.Passed)
            {
                transaction.Rollback();
                host.Methods.Remove(holder);
                said.Add(
                    $"{invocation.Caller.Name}: program {invocation.ProgramId} was built into a " +
                    "method of its own, but pointing the call at it did not verify, and was undone.");
                continue;
            }
            transaction.Commit();
            lifted++;
            said.Add(
                $"{holder.Name}: {string.Join(" ", attempt.Notes)} It holds program " +
                $"{invocation.ProgramId}, which {invocation.Caller.Name} ran through the engine, " +
                "and that call now comes here instead.");
            context.AddChange(new ChangeRecord(
                Name,
                "lift-virtualized-program",
                $"{invocation.Caller.MDToken} IL_{invocation.Call.Offset:X4}",
                $"Gave program {invocation.ProgramId} a method of its own and pointed the call " +
                "that ran it through the engine at that method instead."));
        }
        return lifted;
    }

    /// <summary>
    /// Says of the interpreter that this run is what left it unused, where nothing calls it any
    /// more.
    /// </summary>
    /// <remarks>
    /// Cleanup takes a type out only where it is unreachable and something recovery did accounts
    /// for its being so, and nothing accounted for the engine before. It could not: the calls to
    /// it went one at a time, and while any remained there was nothing to say. Once the last is
    /// gone the claim is plain, and it is exactly the claim cleanup wants — the engine is unused
    /// because this run replaced every call to it.
    ///
    /// What the entry calls is named with it. A decoder and a table of handlers exist for the
    /// engine and nothing else, so they lose their purpose in the same moment and on the same
    /// evidence. Naming more than is dead costs nothing: attribution is what permits a deletion
    /// reachability has already allowed, and never what causes one.
    /// </remarks>
    private static void DeclareEngineOrphaned(ArtifactContext context, List<string> said)
    {
        if (!context.TryGetFact<IReadOnlyList<VirtualInvocation>>(
                "virtualization.invocations", out var invocations) ||
            invocations is null)
        {
            return;
        }

        var entries = invocations
            .Select(invocation => invocation.Entry.ResolveMethodDef())
            .OfType<MethodDef>()
            .DistinctBy(entry => entry.MDToken.Raw)
            .ToArray();
        if (entries.Length == 0)
            return;

        var reached = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions)
            .Where(instruction =>
                instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Ldftn or Code.Ldvirtftn)
            .Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef())
            .OfType<MethodDef>()
            .Select(method => method.MDToken.Raw)
            .ToHashSet();

        var idle = entries.Where(entry => !reached.Contains(entry.MDToken.Raw)).ToArray();
        if (idle.Length == 0)
            return;

        RecoveryOrphans.DeclareSubtree(context, idle);
        said.Add(
            $"Nothing asks the interpreter for anything now: all {entries.Length} of the entry " +
            $"point(s) it was called through are unreferenced, {idle.Length} of them because this " +
            "run replaced what called them, so the engine and what it calls are said to have lost " +
            "their purpose.");
    }

    /// <summary>How many values a call to this method takes off the stack.</summary>
    private static int Pushes(Instruction call) =>
        call.Operand is IMethod called && called.MethodSig is { } signature
            ? signature.Params.Count + (signature.HasThis ? 1 : 0)
            : 0;

    private static string Verdict(DevirtualizationCheck check) => check switch
    {
        DevirtualizationCheck.Agreed =>
            "Running them unpacked what the sample unpacks as it shipped.",
        DevirtualizationCheck.Disagreed =>
            "Running them did not reproduce what the sample does, so the bodies are suspect.",
        _ => "The bodies were not checked by running them."
    };
}

/// <summary>
/// The attribute the tool puts on a method it built, and the means of putting it there.
/// </summary>
/// <remarks>
/// A reading written into the same file as recovered code has to say which it is, in the place the
/// reader is looking. The report says it too, but nobody opening a method in a decompiler is
/// reading the report, and the whole difference between a decrypted body and a built one is
/// invisible on the screen where it matters. An attribute is shown directly above the method by
/// every decompiler an analyst uses, which is why it is the marker rather than a naming convention
/// or a note beside the file.
///
/// The type is internal and takes its message as a constructor argument, so it adds nothing to the
/// assembly's public surface and carries the warning in full rather than in its name alone.
/// </remarks>
internal sealed class ReadingMarker
{
    internal const string Namespace = "Cilantro";
    internal const string TypeName = "RebuiltFromReading";

    /// <summary>What the attribute says first, whatever else is added to it later.</summary>
    /// <remarks>
    /// Kept separate because the message is written twice: once here, where the body goes in, and
    /// once at the end of the run, where what the body reaches and what still calls it are finally
    /// known. Both have to open with the same warning, and one copy of the words is how that stays
    /// true.
    /// </remarks>
    internal const string Warning =
        "CILantro built this body from its reading of the interpreter's program. It is not " +
        "the original code and was not recovered from the file; see the run's report.";

    private readonly MethodDef _constructor;

    private ReadingMarker(MethodDef constructor) => _constructor = constructor;

    /// <summary>How many methods this added, which the identity gate has to be told about.</summary>
    internal static int AddedMethodCount => 1;

    /// <summary>Whether a method's body is one this run wrote from a reading.</summary>
    internal static bool Marks(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        return method.CustomAttributes.Any(attribute =>
            attribute.AttributeType?.Name.String == $"{TypeName}Attribute");
    }

    /// <summary>Adds the attribute type to a module and returns the means of applying it.</summary>
    internal static ReadingMarker Add(ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(module);
        var attribute = module.CorLibTypes.GetTypeRef("System", "Attribute");
        var type = new TypeDefUser(Namespace, $"{TypeName}Attribute", attribute)
        {
            Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed |
                TypeAttributes.BeforeFieldInit
        };
        var signature = MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String);
        var constructor = new MethodDefUser(".ctor", signature)
        {
            Attributes = MethodAttributes.Assembly | MethodAttributes.HideBySig |
                MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
            ImplAttributes = MethodImplAttributes.IL | MethodImplAttributes.Managed,
            Body = new CilBody()
        };
        var baseConstructor = new MemberRefUser(
            module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), attribute);
        constructor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
        constructor.Body.Instructions.Add(OpCodes.Call.ToInstruction(baseConstructor));
        constructor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type.Methods.Add(constructor);
        module.Types.Add(type);
        return new ReadingMarker(constructor);
    }

    /// <summary>Says of a method that its body is a reading.</summary>
    internal void Mark(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        var argument = new CAArgument(method.Module.CorLibTypes.String, new UTF8String(Warning));
        method.CustomAttributes.Add(new CustomAttribute(_constructor, [argument]));
    }

    /// <summary>
    /// Replaces what an already-marked method's attribute says, leaving the attribute itself alone.
    /// </summary>
    /// <remarks>
    /// The marker goes on when the body does, which is before cleanup and renaming have settled the
    /// names and the callers the message wants to mention. Rather than delay the warning until those
    /// are known — and risk a run that ends early leaving a built body with nothing said about it —
    /// the warning goes on immediately and the rest is added to it here.
    /// </remarks>
    internal static void Redescribe(MethodDef method, string said)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(said);
        var marker = method.CustomAttributes.FirstOrDefault(attribute =>
            attribute.AttributeType?.Name.String == $"{TypeName}Attribute");
        if (marker is null || marker.ConstructorArguments.Count != 1)
            return;
        marker.ConstructorArguments[0] =
            new CAArgument(method.Module.CorLibTypes.String, new UTF8String(said));
    }
}
