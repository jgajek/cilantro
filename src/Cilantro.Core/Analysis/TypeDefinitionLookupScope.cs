using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

/// <summary>Caches type searches for an interval in which declarations do not change.</summary>
internal readonly struct TypeDefinitionLookupScope : IDisposable
{
    private readonly ModuleDef? module;
    private readonly bool wasEnabled;

    public TypeDefinitionLookupScope(ModuleDef? module)
    {
        this.module = module;
        wasEnabled = module?.EnableTypeDefFindCache ?? false;
        if (module is not null && !wasEnabled)
            module.EnableTypeDefFindCache = true;
    }

    public void Dispose()
    {
        // Disabling also clears dnlib's index, so subsequent renames/additions are visible.
        if (module is not null && !wasEnabled)
            module.EnableTypeDefFindCache = false;
    }
}
