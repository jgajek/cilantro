using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

/// <summary>Reviewed core-library and facade bindings used by dependency runtimes.</summary>
internal static class DependencyFrameworkScope
{
    internal static bool Matches(ITypeDefOrRef type, ModuleDef module)
    {
        if (type is not TypeRef || type.DefinitionAssembly is not { } scope) return false;
        var core = module.CorLibTypes.AssemblyRef;
        if (scope.FullName == core.FullName) return true;
        // Babel 12 emits these forwarded types through Runtime.Extensions on
        // CoreCLR. Keep the facade, version, token and forwarded type explicit;
        // a matching namespace or a reference to an arbitrary System.* library
        // cannot authorize executing its members in the closed interpreter.
        return core.Name == "System.Runtime" && core.Version is { Major: 8 or 10, Minor: 0, Build: 0, Revision: 0 } &&
            core.Culture.String is "" or "neutral" && core.PublicKeyOrToken?.Token?.ToString() == "b03f5f7f11d50a3a" &&
            scope.Version == core.Version &&
            scope.Culture.String is "" or "neutral" && scope.PublicKeyOrToken?.Token?.ToString() == "b03f5f7f11d50a3a" &&
            (scope.Name == "System.Runtime.Extensions" && type.FullName is "System.Collections.Hashtable" or "System.IO.BinaryReader" or "System.IO.MemoryStream" or "System.Math" ||
             scope.Name == "System.Security.Cryptography.Algorithms" && type.FullName is "System.Security.Cryptography.Aes" or "System.Security.Cryptography.DES" or
                 "System.Security.Cryptography.TripleDES" or "System.Security.Cryptography.Rijndael" or "System.Security.Cryptography.RC2" ||
             scope.Name == "System.Security.Cryptography.Primitives" && type.FullName is "System.Security.Cryptography.SymmetricAlgorithm" or "System.Security.Cryptography.CryptoStream");
    }
}
