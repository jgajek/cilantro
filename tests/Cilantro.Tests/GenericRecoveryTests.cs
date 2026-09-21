using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;

namespace Cilantro.Tests;

public sealed class GenericRecoveryTests
{
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    public void UnknownProtectorRequiresExplicitOptInAndHonorsFailOnPartial(bool generic, bool failOnPartial, bool emitted)
    {
        WithSample((input, directory) =>
        {
            var result = new CilantroPipeline().Run(input, new PipelineOptions(
                GenericRecovery: generic, FailOnPartial: failOnPartial,
                ReportDirectory: directory, OutputPath: Path.Combine(directory, "cleaned.dll")));
            Assert.Equal(emitted, result.Success);
            Assert.Equal(emitted, result.OutputPath is not null);
            Assert.Equal("none", result.Report.Protector);
            Assert.True(result.Report.VerificationPassed);
            if (emitted)
            {
                using var module = ModuleDefMD.Load(result.OutputPath!);
                var method = module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Value");
                Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.FlowControl == FlowControl.Cond_Branch);
                Assert.DoesNotContain(method.Body.Instructions, i => i.IsLdcI4() && i.GetLdcI4Value() == 7);
                Assert.Contains(result.Report.Evidence, e => e.Category == "recovery-mode");
            }
        });
    }

    [Theory]
    [InlineData(PassStatus.Partial, true, false)]
    [InlineData(PassStatus.Unsupported, true, false)]
    [InlineData(PassStatus.Failed, false, false)]
    [InlineData(PassStatus.Partial, false, true)]
    public void GenericModePreservesOtherEmissionGates(PassStatus status, bool gates, bool emitted)
    {
        WithSample((input, directory) =>
        {
            var passes = CilantroPipeline.CreateDefaultPasses().Append(new ResultPass(status, gates));
            var result = new CilantroPipeline(passes).Run(input, new PipelineOptions(
                GenericRecovery: true, ReportDirectory: directory, OutputPath: Path.Combine(directory, "cleaned.dll")));
            Assert.Equal(emitted, result.Success);
            Assert.Equal(emitted, result.OutputPath is not null);
        });
    }

    [Fact]
    public void GenericModeDoesNotEmitStructurallyInvalidCode()
    {
        WithSample((input, directory) =>
        {
            var result = new CilantroPipeline([new InvalidBranchPass()]).Run(input, new PipelineOptions(
                GenericRecovery: true, ReportDirectory: directory, OutputPath: Path.Combine(directory, "cleaned.dll")));
            Assert.False(result.Success);
            Assert.False(result.Report.VerificationPassed);
            Assert.Null(result.OutputPath);
        });
    }

    private static void WithSample(Action<string, string> action)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.Generic").FullName;
        try
        {
            using var module = new ModuleDefUser("generic.dll") { Kind = ModuleKind.Dll };
            var assembly = new AssemblyDefUser("generic", new Version(1, 0));
            assembly.Modules.Add(module);
            var type = SyntheticContext.AddType(module, "Host");
            var method = new MethodDefUser("Value", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static)
            { Body = new CilBody() };
            type.Methods.Add(method);
            var end = Instruction.Create(OpCodes.Ldc_I4_1);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Brfalse, end));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_7));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            method.Body.Instructions.Add(end);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            var input = Path.Combine(directory, "generic.dll");
            module.Write(input);
            action(input, directory);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private sealed class ResultPass(PassStatus status, bool gates) : DeobfuscationPass
    {
        public override string Name => "test-gate";
        public override bool GatesEmission => gates;
        protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context) => (status, 0, []);
    }

    private sealed class InvalidBranchPass : DeobfuscationPass
    {
        public override string Name => "test-invalid";
        protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
        {
            var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Value");
            method.Body.Instructions[1].Operand = Instruction.Create(OpCodes.Ret);
            return (PassStatus.Success, 1, []);
        }
    }
}
