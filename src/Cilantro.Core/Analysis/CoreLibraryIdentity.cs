using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

internal static class CoreLibraryIdentity
{
    internal static bool Matches(ModuleDef module, ITypeDefOrRef type, string name) =>
        type is TypeRef && type.FullName == name &&
        (type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName ||
         module.CorLibTypes.AssemblyRef.Name == "mscorlib" &&
         module.CorLibTypes.AssemblyRef.PublicKeyOrToken?.Token?.ToString() == "b77a5c561934e089" &&
         type.DefinitionAssembly is { Name.String: "mscorlib" } legacy &&
         legacy.PublicKeyOrToken?.Token?.ToString() == "b77a5c561934e089" &&
         (legacy.Version == new Version(2, 0, 0, 0) || legacy.Version == new Version(4, 0, 0, 0)) &&
         UTF8String.IsNullOrEmpty(legacy.Culture));
}
