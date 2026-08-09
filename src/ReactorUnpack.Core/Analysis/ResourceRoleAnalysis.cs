using dnlib.DotNet;

namespace ReactorUnpack.Core.Analysis;

public enum ResourceRole
{
    Unknown,
    ProxyMap,
    StringTable,
    ManagedPayload,
    MethodPatchStream,
    VirtualMachineData,
    IntegrityData
}

public sealed record ResourceRoleFact(
    string Resource,
    ResourceRole Role,
    double Confidence,
    IReadOnlyList<string> Consumers,
    IReadOnlyList<string> Evidence);

public static class ResourceRoleAnalyzer
{
    public static IReadOnlyList<ResourceRoleFact> Analyze(
        ModuleDefMD module,
        ReactorStructureFacts structure)
    {
        var methods = module.GetTypes().SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .ToArray();
        var results = new List<ResourceRoleFact>();
        foreach (var resource in module.Resources.OfType<EmbeddedResource>())
        {
            var consumers = methods.Where(method =>
                method.Body.Instructions.Any(instruction =>
                    instruction.Operand is string value &&
                    value == resource.Name)).ToArray();
            var calls = consumers
                .SelectMany(method => method.Body.Instructions)
                .Select(instruction => instruction.Operand as IMethod)
                .Where(method => method is not null)
                .Cast<IMethod>()
                .ToArray();
            var evidence = new List<string>();
            var role = ResourceRole.Unknown;
            var confidence = 0.25;
            if (calls.Any(call => call.Name.String.StartsWith("ResolveMethod", StringComparison.Ordinal)))
            {
                role = ResourceRole.ProxyMap;
                confidence = 0.9;
                evidence.Add("consumer resolves method tokens");
            }
            else if (calls.Any(call =>
                         call.DeclaringType?.FullName == "System.Reflection.Assembly" &&
                         call.Name == "Load"))
            {
                role = ResourceRole.ManagedPayload;
                confidence = 0.9;
                evidence.Add("consumer reaches Assembly.Load");
            }
            else if (consumers.Any(ReactorStructureDetector.IsStringResolver))
            {
                role = ResourceRole.StringTable;
                confidence = 0.9;
                evidence.Add("consumer has string(int32) resolver signature");
            }
            else if (structure.MethodStubCount >= 10 &&
                     Entropy.Calculate(resource.CreateReader().ToArray()) >= 7.75)
            {
                role = ResourceRole.MethodPatchStream;
                confidence = resource.CreateReader().Length > 1024 ? 0.65 : 0.4;
                evidence.Add("high-entropy resource in method-stub generation");
            }
            else if (resource.CreateReader().Length == 256 && structure.IsReactor6)
            {
                role = ResourceRole.IntegrityData;
                confidence = 0.65;
                evidence.Add("256-byte runtime integrity blob");
            }

            results.Add(new ResourceRoleFact(
                resource.Name,
                role,
                confidence,
                consumers.Select(method => $"{method.MDToken} {method.FullName}").ToArray(),
                evidence));
        }

        return results;
    }
}

public sealed class ResourceRolePass : DeobfuscationPass
{
    public override string Name => "resource-roles";
    public override IReadOnlyCollection<string> Dependencies => ["resource-analysis"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var structure) ||
            structure is null)
            return (PassStatus.Failed, 0, ["Structural facts are unavailable."]);
        var facts = ResourceRoleAnalyzer.Analyze(context.Module, structure);
        context.SetFact("resource.roles", facts);
        foreach (var fact in facts.Where(fact => fact.Role != ResourceRole.Unknown))
        {
            context.AddEvidence(new Evidence(
                "resource-role",
                $"{fact.Resource}: {fact.Role}",
                string.Join("; ", fact.Consumers),
                fact.Confidence));
        }

        return (PassStatus.Success, 0,
            [$"Classified {facts.Count(fact => fact.Role != ResourceRole.Unknown)} of {facts.Count} resources."]);
    }
}
