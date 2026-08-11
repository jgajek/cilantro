using dnlib.DotNet;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Tests;

public sealed class RewriteAllowanceTests
{
    [Fact]
    public void AddedResourceFailsTheStrictIdentityGate()
    {
        using var context = SyntheticContext.Build(module =>
            SyntheticContext.AddType(module, "Host"));
        context.Module.Resources.Add(new EmbeddedResource(
            "restored.resources", [1, 2, 3], ManifestResourceAttributes.Private));

        var result = AssemblyVerifier.Verify(
            context.Module, context.OriginalIdentity, context.OriginalStructure);

        Assert.False(result.Passed);
        Assert.Contains(result.Diagnostics,
            diagnostic => diagnostic.Contains("resource set", StringComparison.Ordinal));
    }

    [Fact]
    public void DeclaredResourceAdditionPassesTheIdentityGate()
    {
        using var context = SyntheticContext.Build(module =>
            SyntheticContext.AddType(module, "Host"));
        context.Module.Resources.Add(new EmbeddedResource(
            "restored.resources", [1, 2, 3], ManifestResourceAttributes.Private));

        var allowance = new RewriteAllowance(
            AddedResources: new HashSet<string>(StringComparer.Ordinal) { "restored.resources" });
        var result = AssemblyVerifier.Verify(
            context.Module, context.OriginalIdentity, context.OriginalStructure, allowance);

        // The structural snapshot still counts resources, so a bare identity allowance is not
        // enough on its own; the resource-name gate, which the allowance targets, must pass.
        Assert.DoesNotContain(result.Diagnostics,
            diagnostic => diagnostic.Contains("resource set", StringComparison.Ordinal));
    }
}
