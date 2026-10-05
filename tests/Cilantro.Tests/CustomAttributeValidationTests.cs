using Cilantro.Core;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

namespace Cilantro.Tests;

public sealed class CustomAttributeValidationTests
{
    [Fact]
    public void InvalidConstructorsAreRejectedThenRemovedWithoutResolvingExternalAttributes()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Host");
            type.Fields.Add(new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32)));
        });
        var field = context.Module.GetTypes().Single(type => type.Name == "Host").Fields.Single();
        var missingAssembly = new AssemblyRefUser("Unavailable.Attributes", new Version(1, 0));
        var external = new TypeRefUser(context.Module, "External", "MarkerAttribute", missingAssembly);
        var constructor = new MemberRefUser(context.Module, ".ctor",
            MethodSig.CreateInstance(context.Module.CorLibTypes.Void), external);
        var valid = new CustomAttribute(constructor);
        field.CustomAttributes.Add(valid);
        field.CustomAttributes.Add(new CustomAttribute((ICustomAttributeType)null!));
        context.Module.Assembly.CustomAttributes.Add(new CustomAttribute((ICustomAttributeType)null!));

        var before = AssemblyVerifier.Verify(context.Module);
        Assert.False(before.Passed);
        Assert.Equal(2, before.Diagnostics.Count(message => message.Contains("invalid constructor")));

        var result = new MetadataSanitizationPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(2, context.Changes.Count(change => change.Kind == "remove-invalid-custom-attribute"));
        Assert.Same(valid, Assert.Single(field.CustomAttributes));
        Assert.True(AssemblyVerifier.Verify(context.Module).Passed);
        new MetadataSanitizationPass().Run(context);
        Assert.Equal(2, context.Changes.Count);
    }

    [Fact]
    public void SerializedBrokenAttributeCannotPassReloadVerificationAndCanBeSanitized()
    {
        using var context = SyntheticContext.Build(module =>
            SyntheticContext.AddType(module, "Host").Fields.Add(
                new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32))));
        var field = context.Module.GetTypes().Single(type => type.Name == "Host").Fields.Single();
        field.CustomAttributes.Add(new CustomAttribute((ICustomAttributeType)null!));
        var path = Path.Combine(Path.GetTempPath(), $"Cilantro.BadAttribute.{Guid.NewGuid():N}.dll");
        try
        {
            // Deliberately produce damaged metadata like a previously rewritten input.
            context.Module.Write(path, new ModuleWriterOptions(context.Module) { Logger = DummyLogger.NoThrowInstance });
            var before = AssemblyVerifier.VerifyFile(path);
            Assert.False(before.Passed);
            Assert.Contains(before.Diagnostics, message => message.Contains("invalid constructor"));
            using var damaged = ArtifactContext.Load(path);
            Assert.Equal(PassStatus.Success, new MetadataSanitizationPass().Run(damaged).Status);
            Assert.Single(damaged.Changes);
            damaged.Module.Write(path);
            Assert.True(AssemblyVerifier.VerifyFile(path).Passed);
            using var reloaded = ModuleDefMD.Load(File.ReadAllBytes(path));
            Assert.Empty(reloaded.GetTypes().Single(type => type.Name == "Host").Fields.Single().CustomAttributes);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
