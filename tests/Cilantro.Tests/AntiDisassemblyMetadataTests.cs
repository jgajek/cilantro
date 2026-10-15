using Cilantro.Core;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class AntiDisassemblyMetadataTests
{
    [Theory]
    [InlineData(true, false, 2)]
    [InlineData(false, false, 0)]
    [InlineData(true, true, 0)]
    public void RemovesOnlyTheFrameworkMarkerWhenCleanupIsEnabled(bool enabled, bool foreign, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            IResolutionScope scope = foreign ? new AssemblyRefUser("ApplicationAttributes", new Version(1, 0)) : module.CorLibTypes.AssemblyRef;
            var type = new TypeRefUser(module, "System.Runtime.CompilerServices", "SuppressIldasmAttribute", scope);
            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), type);
            module.Assembly.CustomAttributes.Add(new CustomAttribute(ctor));
            module.CustomAttributes.Add(new CustomAttribute(ctor));
            var other = new TypeRefUser(module, "System.Runtime.CompilerServices", "CompilerGeneratedAttribute", module.CorLibTypes.AssemblyRef);
            module.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), other)));
        });
        var bodies = context.Module.GetTypes().SelectMany(t => t.Methods).ToDictionary(m => m, MethodBodySnapshot.Capture);
        context.SetFact("options.removeRuntime", enabled);
        Assert.Equal(expected, new AntiDisassemblyMetadataPass().Run(context).Changes);
        Assert.Equal(3 - expected, context.Module.CustomAttributes.Count + context.Module.Assembly.CustomAttributes.Count);
        Assert.Contains(context.Module.CustomAttributes, a => a.AttributeType.Name == "CompilerGeneratedAttribute");
        Assert.True(bodies.All(p => p.Value.StructurallyEquals(p.Key)));
        Assert.Equal(0, new AntiDisassemblyMetadataPass().Run(context).Changes);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed);
        using var bytes = new MemoryStream();
        context.Module.Write(bytes);
        using var reloaded = ModuleDefMD.Load(bytes.ToArray());
        Assert.True(AssemblyVerifier.Verify(reloaded).Passed);
        Assert.Equal(3 - expected, reloaded.CustomAttributes.Count + reloaded.Assembly.CustomAttributes.Count);
    }
}
