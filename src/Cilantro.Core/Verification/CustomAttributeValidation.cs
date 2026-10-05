using dnlib.DotNet;

namespace Cilantro.Core.Verification;

internal static class CustomAttributeValidation
{
    // Metadata owners include parameters, generic constraints and references, not just types
    // and methods. Resolve the owner rather than the attribute row so removals are respected.
    internal static IEnumerable<IHasCustomAttribute> Owners(ModuleDef module)
    {
        var seen = new HashSet<IHasCustomAttribute>(ReferenceEqualityComparer.Instance);
        foreach (var owner in DeclaredOwners(module))
            if (seen.Add(owner))
                yield return owner;
        if (module is not ModuleDefMD metadata)
            yield break;
        var tables = metadata.Metadata.TablesStream;
        for (uint rid = 1; rid <= tables.CustomAttributeTable.Rows; rid++)
        {
            if (tables.TryReadCustomAttributeRow(rid, out var row) &&
                metadata.ResolveHasCustomAttribute(row.Parent) is { } owner && seen.Add(owner))
                yield return owner;
        }
    }

    private static IEnumerable<IHasCustomAttribute> DeclaredOwners(ModuleDef module)
    {
        yield return module;
        if (module.Assembly is { } assembly)
            yield return assembly;
        foreach (var type in module.GetTypes())
        {
            yield return type;
            foreach (var field in type.Fields) yield return field;
            foreach (var property in type.Properties) yield return property;
            foreach (var item in type.Events) yield return item;
            foreach (var item in type.Interfaces) yield return item;
            foreach (var parameter in type.GenericParameters)
            {
                yield return parameter;
                foreach (var constraint in parameter.GenericParamConstraints) yield return constraint;
            }
            foreach (var method in type.Methods)
            {
                yield return method;
                foreach (var parameter in method.ParamDefs) yield return parameter;
                foreach (var parameter in method.GenericParameters)
                {
                    yield return parameter;
                    foreach (var constraint in parameter.GenericParamConstraints) yield return constraint;
                }
            }
        }
    }
}
