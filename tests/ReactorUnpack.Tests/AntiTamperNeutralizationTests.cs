using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

public sealed class AntiTamperNeutralizationTests
{
    [Fact]
    public void RemovesProvenIntegrityCheckOnJitHookSample()
    {
        var result = RunAnalyze("Reason.PAC.dll");
        var pass = Assert.Single(
            result.Report.Passes,
            item => item.Pass == "antitamper-neutralization");

        Assert.Equal(PassStatus.Success, pass.Status);
        Assert.Equal(1, pass.Changes);
        Assert.Contains(result.Report.Evidence,
            evidence => evidence.Category == "antitamper-neutralized");
    }

    [Fact]
    public void LeavesAlreadyCleanOracleUntouched()
    {
        var result = RunAnalyze("Reason.PAC.oracle.dll");
        var pass = Assert.Single(
            result.Report.Passes,
            item => item.Pass == "antitamper-neutralization");

        Assert.Equal(PassStatus.Success, pass.Status);
        Assert.Equal(0, pass.Changes);
        Assert.DoesNotContain(result.Report.Evidence,
            evidence => evidence.Category == "antitamper-neutralized");
    }

    [Fact]
    public void EscapeCheckReportsFieldsReadOutsideTheRemovedSubtree()
    {
        using var module = BuildFieldModule(readerInsideSubtree: false);
        var type = module.Types.Single(item => item.Name == "Runtime");
        var writer = type.Methods.Single(method => method.Name == "Writer");
        var field = type.Fields.Single(item => item.Name == "Flag");
        var subtree = new HashSet<uint> { writer.MDToken.Raw };

        var escaping = AntiTamperNeutralizationPass.FindEscapingFieldReaders(
            module, subtree, [field.FullName]);

        Assert.Equal([field.FullName], escaping);
    }

    [Fact]
    public void EscapeCheckIgnoresFieldsReadOnlyInsideTheRemovedSubtree()
    {
        using var module = BuildFieldModule(readerInsideSubtree: true);
        var type = module.Types.Single(item => item.Name == "Runtime");
        var writer = type.Methods.Single(method => method.Name == "Writer");
        var reader = type.Methods.Single(method => method.Name == "Reader");
        var field = type.Fields.Single(item => item.Name == "Flag");
        var subtree = new HashSet<uint> { writer.MDToken.Raw, reader.MDToken.Raw };

        var escaping = AntiTamperNeutralizationPass.FindEscapingFieldReaders(
            module, subtree, [field.FullName]);

        Assert.Empty(escaping);
    }

    [Fact]
    public void CallSubtreeFollowsTransitiveCallEdges()
    {
        using var module = BuildFieldModule(readerInsideSubtree: true);
        var type = module.Types.Single(item => item.Name == "Runtime");
        var entry = type.Methods.Single(method => method.Name == "Entry");
        var writer = type.Methods.Single(method => method.Name == "Writer");
        var reader = type.Methods.Single(method => method.Name == "Reader");

        var subtree = AntiTamperNeutralizationPass.ComputeCallSubtree(entry);

        Assert.Contains(entry.MDToken.Raw, subtree);
        Assert.Contains(writer.MDToken.Raw, subtree);
        Assert.Contains(reader.MDToken.Raw, subtree);
    }

    private static PipelineResult RunAnalyze(string filename)
    {
        var sample = Path.Combine(FindRepositoryRoot(), "samples", filename);
        var directory = Path.Combine(
            Path.GetTempPath(), $"ReactorUnpack.AntiTamper.{Guid.NewGuid():N}");
        try
        {
            return new ReactorPipeline().Run(sample, new PipelineOptions(
                AnalyzeOnly: true, ReportDirectory: directory));
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, true);
        }
    }

    /// <summary>
    /// Builds a module, serializes it, and reloads it so members carry real metadata tokens, which
    /// the escape and subtree helpers key on.
    /// </summary>
    private static ModuleDefMD BuildFieldModule(bool readerInsideSubtree)
    {
        var module = new ModuleDefUser("antitamper.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("antitamper", new Version(1, 0));
        assembly.Modules.Add(module);
        var type = new TypeDefUser("Tests", "Runtime", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);

        var field = new FieldDefUser(
            "Flag",
            new FieldSig(module.CorLibTypes.Int32),
            FieldAttributes.Static | FieldAttributes.Public);
        type.Fields.Add(field);

        var writer = NewStaticVoid("Writer");
        writer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        writer.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, field));
        writer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(writer);

        var reader = NewStaticVoid("Reader");
        reader.Body.Instructions.Add(Instruction.Create(OpCodes.Ldsfld, field));
        reader.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
        reader.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(reader);

        var entry = NewStaticVoid("Entry");
        entry.Body.Instructions.Add(Instruction.Create(OpCodes.Call, writer));
        if (readerInsideSubtree)
            entry.Body.Instructions.Add(Instruction.Create(OpCodes.Call, reader));
        entry.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(entry);

        using var stream = new MemoryStream();
        module.Write(stream);
        return ModuleDefMD.Load(stream.ToArray());

        MethodDefUser NewStaticVoid(string name) => new(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "ReactorUnpack.slnx")))
                return current.FullName;
            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Repository root not found.");
    }
}
