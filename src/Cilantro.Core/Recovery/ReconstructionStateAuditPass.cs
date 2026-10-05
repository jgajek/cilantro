using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Audits the final module, rather than assuming that a VM-owned root is private.</summary>
public sealed class ReconstructionStateAuditPass : DeobfuscationPass
{
    internal const string FieldsFact = "reconstruction.differingStaticFields";
    internal const string TrialsFact = "reconstruction.applicationTrials";
    internal sealed record TrialAudit(IReadOnlyList<RebuiltMethodTrial.Result> Trials, DevirtualizationCheck Payload);
    public override string Name => "reconstruction-state-audit";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["symbol-renaming"];

    internal sealed record FieldAudit(uint Token, string Name, bool Retained,
        bool ExternallyVisible, IReadOnlyList<string> References, bool Resolved);

    internal static IReadOnlyList<FieldAudit> Inspect(ModuleDefMD module, IReadOnlyList<uint> tokens)
    {
        var liveTypes = module.GetTypes().ToHashSet();
        var methods = liveTypes.SelectMany(type => type.Methods).Where(method => method.HasBody).ToArray();
        return tokens.Distinct().Select(token =>
        {
            var field = module.ResolveToken(token) as FieldDef;
            var retained = field is not null && field.DeclaringType is { } owner &&
                liveTypes.Contains(owner) && owner.Fields.Contains(field);
            var references = field is null ? [] : methods.Where(method => method.Body.Instructions.Any(
                    instruction => instruction.Operand is IField reference && reference.ResolveFieldDef() == field))
                .Select(method => $"{method.MDToken} {method.FullName}").ToArray();
            return new FieldAudit(token, field?.FullName ?? "unresolved original field", retained,
                retained && (field!.IsPublic || field.IsFamily || field.IsFamilyOrAssembly), references, field is not null);
        }).ToArray();
    }

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<uint>>(FieldsFact, out var tokens) || tokens is null || tokens.Count == 0)
            return (PassStatus.Success, 0, ["No differing static-field roots were recorded by reconstruction trials; this is not an equivalence verdict."]);
        var fields = Inspect(context.Module, tokens);
        foreach (var field in fields)
            context.AddEvidence(new Evidence("reconstruction-final-state-root",
                $"{field.Name}: {(!field.Resolved ? "unresolved; removal is not established" : field.Retained ? "retained" : "removed from the final module")}; " +
                $"public/protected field={field.ExternallyVisible}; surviving explicit references={field.References.Count}. " +
                string.Join("; ", field.References), $"0x{field.Token:X8}"));

        var reflection = context.Module.GetTypes().SelectMany(type => type.Methods)
            .Where(method => method.HasBody && method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called &&
                (called.DeclaringType?.FullName.StartsWith("System.Reflection.", StringComparison.Ordinal) == true ||
                 called.DeclaringType?.FullName == "System.Type" &&
                 called.Name.String is "GetField" or "GetFields" or "GetMember" or "GetMembers" or "InvokeMember")))
            .Select(method => $"{method.MDToken} {method.FullName}").ToArray();
        foreach (var method in reflection)
            context.AddEvidence(new Evidence("reconstruction-reflection-boundary",
                "Surviving reflection call requires target/escape analysis; its presence does not establish access to a differing root.", method));
        var note = $"Final-module audit of {fields.Count} differing static roots: " +
            $"{fields.Count(field => field.Resolved && !field.Retained)} removed, {fields.Count(field => field.Retained)} retained, " +
            $"{fields.Count(field => !field.Resolved)} unresolved, " +
            $"{fields.Count(field => field.References.Count > 0)} referenced by surviving IL, " +
            $"{fields.Count(field => field.ExternallyVisible)} public/protected. " +
            $"{reflection.Length} surviving method(s) contain reflection calls requiring further analysis. " +
            "This audit does not prove absence of reflective access, escaped handles, callbacks or later external calls; the reconstruction disagreement is unchanged.";
        context.AddEvidence(new Evidence("reconstruction-final-state-audit", note));
        if (context.TryGetFact<TrialAudit>(TrialsFact, out var trials) && trials is not null)
        {
            var liveMethods = context.Module.GetTypes().SelectMany(type => type.Methods).ToHashSet();
            var removedGates = trials.Trials.Where(trial => trial.ProtectorGateToken is not null)
                .Select(trial => trial.ProtectorGateToken!.Value).Where(token =>
                    context.Module.ResolveToken(token) is MethodDef method && !liveMethods.Contains(method)).ToHashSet();
            var application = AssessApplication(trials, fields, removedGates);
            context.AddEvidence(new Evidence("reconstruction-application-contract", application));
        }
        return (PassStatus.Partial, 0, [note]);
    }

    internal static string AssessApplication(TrialAudit audit, IReadOnlyList<FieldAudit> fields, IReadOnlySet<uint>? removedGates = null)
    {
        var differing = audit.Trials.Where(trial => trial.Verdict == DevirtualizationCheck.Disagreed).ToArray();
        bool RemovedGate(RebuiltMethodTrial.Result trial) => trial.ProtectorGateToken is { } gate && removedGates?.Contains(gate) == true;
        var bypassedGates = differing.Count(RemovedGate);
        var applicationDifferences = differing.Count(trial => !trial.NonVmStateMatched && !RemovedGate(trial));
        var inconclusive = audit.Trials.Count(trial => trial.Verdict == DevirtualizationCheck.NotMade);
        var boundaryOpen = differing.Any(trial => !RemovedGate(trial) && (trial.VmStateShared != false || trial.VmMetadataEscaped != false || trial.ResolverBehaviorUnproven)) ||
            audit.Trials.Any(trial => trial.ResolverBehaviorUnproven) || fields.Count == 0 ||
            fields.Any(field => !field.Resolved || field.Retained || field.References.Count != 0);
        var state = applicationDifferences != 0 || audit.Payload == DevirtualizationCheck.Disagreed
            ? "Application comparison differed"
            : differing.Length == 0 || boundaryOpen
                ? "Application comparison incomplete"
                : "Bounded application comparison matched";
        return $"{state}: {audit.Trials.Count - inconclusive} completed method trials, {inconclusive} inconclusive fixtures, " +
            $"{applicationDifferences} application-state differences; {bypassedGates} confirmed removed debugger-gate bypasses; payload comparison {audit.Payload}. " +
            "Contract: preserve captured application return/exception, arguments (including retained first-call references), non-VM static state, " +
            "modeled host effects and payload bytes where compared; deliberate removal of protector metadata, isolated VM caches and the identified VM-wrapper debugger gate is allowed. " +
            (boundaryOpen ? "VM aliases, escaped VM metadata, resolver behavior or final field removal remain unresolved. " : "") +
            "This is evidence for the exercised inputs and paths, not a claim about arbitrary callbacks or every input. The full-state verdict is retained separately.";
    }
}
