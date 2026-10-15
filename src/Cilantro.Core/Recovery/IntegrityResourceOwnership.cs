using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

internal sealed record IntegrityResourceOwnership(MethodDef Checker, RecoveredResourceOrigin Resource)
{
    // The verdict pass has already required agreement between two complete cold
    // startups. Preserve that evidence before its verified RSA call disappears.
    internal static void CaptureVerifiedVerdict(ArtifactContext context, MethodDef checker, LoaderInterpretationEvidence evidence)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            checker.Rid == 0 || !checker.HasBody || !checker.IsStatic || checker.IsConstructor ||
            checker.HasGenericParameters || checker.DeclaringType.HasGenericParameters ||
            checker.MethodSig.Params.Count != 0 || checker.ReturnType.ElementType != ElementType.Void ||
            MemberVisibility.IsExternallyVisible(checker) || checker.DeclaringType.IsGlobalModuleType ||
            !checker.DeclaringType.FullName.Split('.', '/', '`', '+').Where(part => part.Length != 0).All(ReactorNameHeuristics.IsGeneratedName)) return;
        var resources = context.Module.Resources.OfType<EmbeddedResource>().Where(resource =>
            checker.Body.Instructions.Any(i => i.OpCode.Code == Code.Ldstr && Equals(i.Operand, resource.Name.String))).ToArray();
        if (resources.Length != 1) return;
        var origin = RecoveredResourceOrigin.Capture(resources[0]);
        if (!Valid(checker, origin, evidence)) return;
        context.TryGetFact<IReadOnlyList<IntegrityResourceOwnership>>("integrity.resourceOwners", out var earlier);
        if (earlier?.Any(item => item.Checker == checker) == true) return;
        context.SetFact<IReadOnlyList<IntegrityResourceOwnership>>("integrity.resourceOwners", [.. earlier ?? [], new(checker, origin)]);
        context.AddEvidence(new Evidence("integrity-resource-ownership",
            $"Independent cold-start verification attributed {origin.Name} (SHA-256 {origin.Sha256}) before verdict specialization. Resource cleanup still requires physical removal of the checker.", checker.FullName));
    }

    internal static void Capture(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled) return;
        context.TryGetFact<IReadOnlyList<IntegrityResourceOwnership>>("integrity.resourceOwners", out var earlier);
        var ownership = earlier?.ToList() ?? [];
        var resources = context.Module.Resources.OfType<EmbeddedResource>().ToArray();
        var candidates = context.Module.GetTypes().Where(type => !type.IsGlobalModuleType &&
                type.FullName.Split('.', '/', '`', '+').Where(part => part.Length != 0).All(ReactorNameHeuristics.IsGeneratedName))
            .SelectMany(type => type.Methods).Where(method => method.Rid != 0 && !ownership.Any(item => item.Checker == method) && method.HasBody && method.IsStatic && !method.IsConstructor &&
                !method.HasGenericParameters && !method.DeclaringType.HasGenericParameters && method.MethodSig.Params.Count == 0 &&
                method.ReturnType.ElementType == ElementType.Void && !MemberVisibility.IsExternallyVisible(method) &&
                CallsVerification(method, 2, []))
            .Select(method => (Method: method, Resources: resources.Where(resource => method.Body.Instructions.Any(instruction =>
                instruction.OpCode.Code == Code.Ldstr && Equals(instruction.Operand, resource.Name.String))).ToArray()))
            .Where(candidate => candidate.Resources.Length == 1).Take(5).ToArray();
        if (candidates.Length > 4) return;
        foreach (var candidate in candidates)
        {
            var origin = RecoveredResourceOrigin.Capture(candidate.Resources[0]);
            if (!Read(candidate.Method, out var first, out var firstSteps) || !Read(candidate.Method, out var second, out var secondSteps) ||
                firstSteps != secondSteps || !first!.Agrees(second!) || !Valid(candidate.Method, origin, first)) continue;
            ownership.Add(new(candidate.Method, origin));
            context.AddEvidence(new Evidence("integrity-resource-ownership",
                $"Two independent checker interpretations read the module and {origin.Name} (SHA-256 {origin.Sha256}) and verified its signature. " +
                "Resource cleanup still requires physical removal of the checker.", candidate.Method.FullName));
        }
        context.SetFact<IReadOnlyList<IntegrityResourceOwnership>>("integrity.resourceOwners", ownership);

        bool Read(MethodDef method, out LoaderInterpretationEvidence? evidence, out int steps)
        {
            evidence = null; steps = 0;
            if (!BootstrapMachine.TrySeed(context, 1_000_000, out var machine, out _) || machine is null) return false;
            // An optional ownership probe must not add unrelated failures to the run's ledger.
            var world = BootstrapMachine.Environment(context);
            machine.State.RegisterRunEnvironment(new RunEnvironment(world.Host, world.Declarations, new BlockerLedger(), world.Strict));
            var result = machine.Execute(method); steps = result.Steps;
            if (!result.Succeeded) return false;
            evidence = machine.State.LoaderEvidence;
            return true;
        }
    }

    internal static bool Valid(MethodDef checker, RecoveredResourceOrigin resource, LoaderInterpretationEvidence evidence)
    {
        var effects = evidence.EffectsOf(checker.MDToken.Raw);
        if (evidence.ObservationsTruncated || !effects.AllInvocationsCompleted || effects.WroteMappedImage ||
            effects.WroteScratchRegion || effects.Registrations.Count != 0) return false;
        var observations = evidence.Observations.Where(observation => observation.CallStack.Contains(checker.MDToken.Raw)).ToArray();
        if (observations.Any(observation => observation.Kind is LoaderObservationKind.DeclaredCall or LoaderObservationKind.SteppedCall or LoaderObservationKind.Termination)) return false;
        var checks = observations.Where(observation => observation.Kind == LoaderObservationKind.SignatureVerification).ToArray();
        if (checks.Length == 0 || checks.Any(check => check.Verdict != true) ||
            !observations.Any(observation => observation.Kind == LoaderObservationKind.ModuleFileRead &&
                (observation.Detail.StartsWith("FileStream over ", StringComparison.Ordinal) || observation.Detail.StartsWith("File.ReadAllBytes of ", StringComparison.Ordinal)))) return false;
        var reads = observations.Where(observation => observation.Kind == LoaderObservationKind.ManagedResourceRead)
            .Select(observation => System.Text.Json.JsonSerializer.Deserialize<ManagedResourceRead>(observation.Detail)).ToArray();
        return reads.Length != 0 && reads.All(read => read is not null && read.Name == resource.Name && read.Sha256 == resource.Sha256);
    }

    internal static IEnumerable<RecoveredResourceOrigin> RemovedOrigins(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete ||
            !context.TryGetFact<IReadOnlyList<IntegrityResourceOwnership>>("integrity.resourceOwners", out var ownership) || ownership is null) yield break;
        var surviving = context.Module.GetTypes().SelectMany(type => type.Methods).ToHashSet();
        foreach (var item in ownership) if (!surviving.Contains(item.Checker)) yield return item.Resource;
    }

    private static bool CallsVerification(MethodDef method, int depth, HashSet<MethodDef> seen)
    {
        if (!method.HasBody || !seen.Add(method)) return false;
        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.OpCode.Code is not (Code.Call or Code.Callvirt) || instruction.Operand is not IMethod call) continue;
            if (call.DeclaringType is TypeRef type && type.FullName == "System.Security.Cryptography.RSACryptoServiceProvider" &&
                call.Name == "VerifyHash" && type.DefinitionAssembly?.Name.String is "mscorlib" or "System.Security.Cryptography" or "System.Security.Cryptography.Csp") return true;
            if (depth > 0 && call.ResolveMethodDef() is { } helper && helper.DeclaringType == method.DeclaringType && CallsVerification(helper, depth - 1, seen)) return true;
        }
        return false;
    }
}
