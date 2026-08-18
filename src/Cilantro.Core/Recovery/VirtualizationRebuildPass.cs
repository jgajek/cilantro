using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;

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
    internal const string AddedMethodsFact = "virtualization.addedMethodTokens";

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

        if (built.Count == 0)
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

        context.SetFact<IReadOnlySet<uint>>(RebuiltFact, rebuilt);
        context.SetFact(AddedTypesFact, 1);
        context.SetFact<IReadOnlySet<uint>>(AddedMethodsFact, marker.AddedMethodTokens);

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

    /// <summary>What the attribute says, which is the whole of what a reader needs to know.</summary>
    private const string Said =
        "CILantro built this body from its reading of the interpreter's program. It is not " +
        "the original code and was not recovered from the file; see the run's report.";

    private readonly MethodDef _constructor;

    private ReadingMarker(MethodDef constructor)
    {
        _constructor = constructor;
        AddedMethodTokens = new HashSet<uint> { constructor.MDToken.Raw };
    }

    /// <summary>The methods this added, which the identity gate has to be told about.</summary>
    internal IReadOnlySet<uint> AddedMethodTokens { get; }

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
        var argument = new CAArgument(method.Module.CorLibTypes.String, new UTF8String(Said));
        method.CustomAttributes.Add(new CustomAttribute(_constructor, [argument]));
    }
}
