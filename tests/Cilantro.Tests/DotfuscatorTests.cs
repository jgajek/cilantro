using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Pipeline;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorTests
{
    [Theory]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, true)]
    [InlineData(true, true, true, true)]
    public void AttributionRequiresAnAppliedLocalAttribute(bool applied, bool derivesAttribute, bool expected, bool modern = false)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = new TypeDefUser("", "DotfuscatorAttribute", derivesAttribute
                ? new TypeRefUser(module, "System", "Attribute", module.CorLibTypes.AssemblyRef)
                : module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
            type.Methods.Add(ctor);
            if (modern) { ctor.MethodSig.Params.Add(module.CorLibTypes.Int32); ctor.MethodSig.Params.Add(module.CorLibTypes.Boolean); }
            ctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (applied)
            {
                var attribute = new CustomAttribute(ctor);
                attribute.ConstructorArguments.Add(new(module.CorLibTypes.String, "0123456789:7.1.4"));
                if (modern) { attribute.ConstructorArguments.Add(new(module.CorLibTypes.Int32, 1)); attribute.ConstructorArguments.Add(new(module.CorLibTypes.Boolean, true)); }
                module.Assembly.CustomAttributes.Add(attribute);
            }
        });
        var result = new DotfuscatorDetectionPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        var facts = DotfuscatorStructureDetector.Analyze(context.Module);
        Assert.Equal(expected, facts.IsDotfuscator);
        new ProtectorIdentityPass().Run(context);
        Assert.True(context.TryGetFact<ProtectorIdentity>(ProtectorIdentityPass.Fact, out var identity));
        Assert.Equal(expected ? "dotfuscator" : "none", identity!.Token);
        Assert.Empty(identity.Capabilities);
        if (expected) Assert.Equal("0123456789:7.1.4", identity.Generation);
    }

    [Fact]
    public void DotfuscatorPassesAreOrderedAndClassifiedForMutationGating()
    {
        var passes = CilantroPipeline.CreateDefaultPasses();
        _ = new CilantroPipeline(); // Validates every declared dependency.
        var names = passes.Select(pass => pass.Name).ToList();
        Assert.True(names.IndexOf("dotfuscator-detection") < names.IndexOf("protector-identity"));
        Assert.True(names.IndexOf("dotfuscator-literal-strings") < names.IndexOf("payload-extraction"));
        var planned = PipelinePlanner.Plan(passes);
        var decoder = Assert.Single(planned, pass => pass.Pass.Name == "dotfuscator-literal-strings");
        Assert.True(decoder.MutatesModule);
        Assert.Equal(PipelinePhase.IlTransform, decoder.Phase);
        var native = Assert.Single(planned, pass => pass.Pass.Name == "dotfuscator-native-strings");
        Assert.True(native.MutatesModule);
        Assert.True(native.Pass.GatesEmission);
        Assert.Equal(PipelinePhase.IlTransform, native.Phase);
        Assert.True(names.IndexOf("dotfuscator-native-strings") < names.IndexOf("payload-extraction"));
        var resources = Assert.Single(planned, pass => pass.Pass.Name == "dotfuscator-resources");
        Assert.True(resources.MutatesModule);
        Assert.Equal(PipelinePhase.IlTransform, resources.Phase);
        Assert.True(names.IndexOf("dotfuscator-native-strings") < names.IndexOf("dotfuscator-resources"));
        Assert.True(names.IndexOf("dotfuscator-resources") < names.IndexOf("resource-entry-extraction"));
        var checks = Assert.Single(planned, pass => pass.Pass.Name == "dotfuscator-checks");
        Assert.True(checks.MutatesModule);
        Assert.True(checks.Pass.GatesEmission);
        Assert.Equal(PipelinePhase.IlTransform, checks.Phase);
        Assert.True(names.IndexOf("method-body-recovery") < names.IndexOf("dotfuscator-checks"));
        Assert.True(names.IndexOf("dotfuscator-checks") < names.IndexOf("dotfuscator-control-flow"));
    }
}
