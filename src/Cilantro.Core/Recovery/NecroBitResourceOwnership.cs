using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Ownership of directly named data by a recovered, generated decrypt-table writer.</summary>
internal sealed record NecroBitResourceOwnership(MethodDef Writer, FieldDef Table, RecoveredResourceOrigin Resource)
{
    internal static IReadOnlyList<NecroBitResourceOwnership> Capture(ArtifactContext context, InterpretedRewrite rewrite)
    {
        if (rewrite.Evidence.ObservationsTruncated || rewrite.NecroBitBodies.Count == 0 || rewrite.NecroBitTables.Count != 1)
            return [];
        var table = rewrite.NecroBitTables[0];
        if (!table.Keys.SequenceEqual(rewrite.NecroBitBodies.Select(body => body.Key).Order())) return [];
        var field = context.Module.GetTypes().SelectMany(type => type.Fields).SingleOrDefault(field => field.FullName == table.Field);
        if (field is not { IsStatic: true } || !field.DeclaringType.FullName.Split('.', '/', '`', '+')
                .Where(part => part.Length != 0).All(ReactorNameHeuristics.IsGeneratedName)) return [];
        var resources = context.Module.Resources.OfType<EmbeddedResource>().ToArray();
        var result = new List<NecroBitResourceOwnership>();
        foreach (var method in field.DeclaringType.Methods.Where(method => method.HasBody && !method.IsConstructor))
        {
            // A resource read by another helper under a common bootstrap is not owned here.
            // Require the actual table assignment and one direct resource name in this body.
            if (!method.Body.Instructions.Any(instruction => instruction.OpCode.Code == Code.Stsfld &&
                    instruction.Operand is IField target && target.ResolveFieldDef() == field) ||
                !rewrite.Evidence.EffectsOf(method.MDToken.Raw).StaticFieldsWritten.Contains(field.FullName)) continue;
            var names = method.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Ldstr)
                .Select(instruction => instruction.Operand).OfType<string>().ToHashSet(StringComparer.Ordinal);
            var directlyNamed = resources.Where(resource => names.Contains(resource.Name.String)).ToArray();
            if (directlyNamed.Length != 1) continue;
            var origin = RecoveredResourceOrigin.Capture(directlyNamed[0]);
            if (!rewrite.Evidence.Observations.Any(observation => observation.Kind == LoaderObservationKind.ManagedResourceRead &&
                    observation.CallStack.Contains(method.MDToken.Raw) &&
                    System.Text.Json.JsonSerializer.Deserialize<ManagedResourceRead>(observation.Detail) is { } read &&
                    read.Name == origin.Name && read.Sha256 == origin.Sha256)) continue;
            result.Add(new(method, field, origin));
        }
        return result;
    }

    internal static IEnumerable<RecoveredResourceOrigin> RemovedOrigins(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete ||
            !context.TryGetFact<IReadOnlyList<NecroBitResourceOwnership>>("method-protection.necroBitResources", out var ownership) || ownership is null)
            yield break;
        var types = context.Module.GetTypes().ToArray();
        var methods = types.SelectMany(type => type.Methods).ToHashSet();
        var fields = types.SelectMany(type => type.Fields).ToHashSet();
        foreach (var item in ownership)
            if (!methods.Contains(item.Writer) && !fields.Contains(item.Table)) yield return item.Resource;
    }
}
