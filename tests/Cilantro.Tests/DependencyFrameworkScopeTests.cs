using Cilantro.Core.Analysis;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class DependencyFrameworkScopeTests
{
    [Theory]
    [InlineData(8, "System.Collections", "Hashtable")]
    [InlineData(8, "System.IO", "BinaryReader")]
    [InlineData(8, "System.IO", "MemoryStream")]
    [InlineData(10, "System", "Math")]
    [InlineData(10, "System.Collections", "Hashtable")]
    public void ReviewedFacadesBindOnlyKnownForwardedTypes(int version, string ns, string name)
    {
        using var module = Module(version);
        var facade = new AssemblyRefUser(new AssemblyNameInfo($"System.Runtime.Extensions, Version={version}.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"));
        Assert.True(DependencyFrameworkScope.Matches(new TypeRefUser(module, ns, name, facade), module));
    }

    [Theory]
    [InlineData("System.Runtime.Extensions", 8, "neutral", "null", "System.IO", "BinaryReader")]
    [InlineData("System.Runtime.Extensions", 10, "neutral", "b03f5f7f11d50a3a", "System.IO", "BinaryReader")]
    [InlineData("System.Runtime.Extensions", 8, "fr", "b03f5f7f11d50a3a", "System.IO", "BinaryReader")]
    [InlineData("Foreign", 8, "neutral", "b03f5f7f11d50a3a", "System.IO", "BinaryReader")]
    [InlineData("System.Runtime.Extensions", 8, "neutral", "b03f5f7f11d50a3a", "System", "Environment")]
    [InlineData("System.Runtime.Extensions", 8, "neutral", "b03f5f7f11d50a3a", "System.IO", "File")]
    [InlineData("System.Runtime.Extensions", 8, "neutral", "b03f5f7f11d50a3a", "System.Security.Cryptography", "Aes")]
    [InlineData("System.Security.Cryptography.Algorithms", 8, "neutral", "null", "System.Security.Cryptography", "Aes")]
    [InlineData("System.Security.Cryptography.Primitives", 8, "neutral", "b03f5f7f11d50a3a", "System.IO", "BinaryReader")]
    public void ForeignAndUnreviewedBindingsCannotEnterClosedConstruction(string assembly, int version, string culture,
        string token, string ns, string name)
    {
        using var module = Module(8);
        var scope = new AssemblyRefUser(new AssemblyNameInfo($"{assembly}, Version={version}.0.0.0, Culture={culture}, PublicKeyToken={token}"));
        Assert.False(DependencyFrameworkScope.Matches(new TypeRefUser(module, ns, name, scope), module));
    }

    [Theory]
    [InlineData(9)]
    [InlineData(11)]
    public void AnUnreviewedCoreVersionDoesNotAuthorizeItsFacade(int version)
    {
        using var module = Module(version);
        var scope = new AssemblyRefUser(new AssemblyNameInfo($"System.Runtime.Extensions, Version={version}.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"));
        Assert.False(DependencyFrameworkScope.Matches(new TypeRefUser(module, "System.IO", "BinaryReader", scope), module));
    }

    private static ModuleDefUser Module(int version) => new("Scope.dll", Guid.NewGuid(),
        new AssemblyRefUser(new AssemblyNameInfo($"System.Runtime, Version={version}.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")));

    [Theory]
    [InlineData(8, "Algorithms", "Aes")]
    [InlineData(10, "Algorithms", "Aes")]
    [InlineData(8, "Primitives", "SymmetricAlgorithm")]
    [InlineData(10, "Primitives", "SymmetricAlgorithm")]
    [InlineData(8, "Primitives", "CryptoStream")]
    [InlineData(10, "Primitives", "CryptoStream")]
    public void ReviewedCryptoFacadesRetainExactVersionAndTypeBindings(int version, string facade, string type)
    {
        using var module = Module(version);
        var scope = new AssemblyRefUser(new AssemblyNameInfo($"System.Security.Cryptography.{facade}, Version={version}.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"));
        Assert.True(DependencyFrameworkScope.Matches(new TypeRefUser(module, "System.Security.Cryptography", type, scope), module));
    }
}
