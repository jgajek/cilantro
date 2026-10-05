using dnlib.DotNet;
using Cilantro.Core.Verification;

namespace Cilantro.Core;

public sealed class MetadataSanitizationPass : DeobfuscationPass
{
    public override string Name => "metadata-sanitization";
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery"];

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

        var removed = 0;
        foreach (var owner in CustomAttributeValidation.Owners(context.Module))
        {
            foreach (var attribute in owner.CustomAttributes.ToArray())
            {
                // An absent constructor cannot name an attribute. Do not guess a replacement
                // from its blob or remove valid attributes whose external types are unavailable.
                if (attribute.Constructor is not null)
                    continue;
                owner.CustomAttributes.Remove(attribute);
                context.AddChange(new ChangeRecord(Name, "remove-invalid-custom-attribute",
                    owner.MDToken.ToString(),
                    $"Removed a custom attribute with no valid constructor reference (blob offset {attribute.BlobOffset})."));
                removed++;
            }
        }
        return (PassStatus.Success, removed,
            [$"Identified {poisoned} poisoned assembly references.",
             $"Removed {removed} custom attributes with invalid constructor references."]);
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
