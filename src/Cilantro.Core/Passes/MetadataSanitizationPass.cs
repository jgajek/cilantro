using dnlib.DotNet;

namespace Cilantro.Core;

public sealed class MetadataSanitizationPass : DeobfuscationPass
{
    public override string Name => "metadata-sanitization";
    public override IReadOnlyCollection<string> Dependencies => ["string-recovery"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var poisoned = 0;
        foreach (var assemblyReference in context.Module.GetAssemblyRefs())
        {
            if (assemblyReference.Version is not null &&
                assemblyReference.Version.Major == ushort.MaxValue &&
                assemblyReference.Name == "mscorlib")
            {
                poisoned++;
                context.AddEvidence(new Evidence(
                    "metadata",
                    IsReferenced(context.Module, assemblyReference)
                        ? "Poisoned mscorlib AssemblyRef remains referenced and was preserved."
                        : "Unreferenced poisoned mscorlib AssemblyRef will be omitted by metadata rebuild.",
                    assemblyReference.FullName,
                    1.0));
            }
        }

        return (PassStatus.Success, 0, [$"Identified {poisoned} poisoned assembly references."]);
    }

    private static bool IsReferenced(ModuleDef module, AssemblyRef target) =>
        module.GetTypes().Any(type =>
            References(type.BaseType, target) ||
            type.Interfaces.Any(item => References(item.Interface, target)) ||
            type.Fields.Any(field => References(field.FieldType, target)) ||
            type.Methods.Any(method =>
                References(method.ReturnType, target) ||
                method.Parameters.Any(parameter => References(parameter.Type, target)) ||
                method.HasBody && method.Body.Instructions.Any(instruction =>
                    instruction.Operand is ITypeDefOrRef typeRef && References(typeRef, target))));

    private static bool References(IType? type, AssemblyRef target)
    {
        var scope = type?.Scope;
        return scope is AssemblyRef reference && ReferenceEquals(reference, target);
    }
}
