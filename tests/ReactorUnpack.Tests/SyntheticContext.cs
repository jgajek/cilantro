using dnlib.DotNet;
using ReactorUnpack.Core;

namespace ReactorUnpack.Tests;

/// <summary>
/// Serializes a synthetic module to a temporary file and loads it into an <see cref="ArtifactContext"/>
/// so members carry real metadata tokens, which the transform passes key on.
/// </summary>
internal static class SyntheticContext
{
    public static ArtifactContext Build(Action<ModuleDefUser> populate)
    {
        var module = new ModuleDefUser("synthetic.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("synthetic", new Version(1, 0));
        assembly.Modules.Add(module);
        populate(module);

        var path = Path.Combine(
            Path.GetTempPath(), $"ReactorUnpack.Synthetic.{Guid.NewGuid():N}.dll");
        module.Write(path);
        try
        {
            return ArtifactContext.Load(path);
        }
        finally
        {
            File.Delete(path);
        }
    }

    public static TypeDefUser AddType(ModuleDefUser module, string name)
    {
        var type = new TypeDefUser("Synthetic", name, module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.NotPublic | TypeAttributes.Class
        };
        module.Types.Add(type);
        return type;
    }
}
