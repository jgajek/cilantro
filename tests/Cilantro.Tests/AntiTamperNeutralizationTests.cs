using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

public sealed class AntiTamperNeutralizationTests
{
    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
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

    [SampleFact]
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

    /// <summary>
    /// Reactor puts the gate at the head of every type initializer, so a frame with one caller is
    /// the exception. Confining the edit to the global initializer left the rest of them running the
    /// check the removal was for, which is what withheld the cleaned copy on such a sample.
    /// </summary>
    [Fact]
    public void EveryCallerOfTheGateIsCollected()
    {
        using var module = BuildGateModule(GateReference.TwoDirectCalls);
        var gate = Gate(module);

        var found = AntiTamperNeutralizationPass.TryFindCalls(
            module, gate, out var calls, out var diagnostic);

        Assert.True(found);
        Assert.Equal(2, calls.Length);
        Assert.Equal(2, calls.Select(item => item.Method).Distinct().Count());
        Assert.Empty(diagnostic);
    }

    /// <summary>
    /// The two ways the search comes back empty send a reader in opposite directions, so they are
    /// held apart here: this one means the gate is already unreachable.
    /// </summary>
    [Fact]
    public void AGateNothingCallsIsDeclinedAsUnreached()
    {
        using var module = BuildGateModule(GateReference.None);
        var gate = Gate(module);

        var found = AntiTamperNeutralizationPass.TryFindCalls(
            module, gate, out var calls, out var diagnostic);

        Assert.False(found);
        Assert.Empty(calls);
        Assert.Contains("no reachable call", diagnostic);
    }

    /// <summary>
    /// And this one means there is a route to the gate whose end the pass cannot see, where nopping
    /// the calls it can account for would report a gate removed that is still reachable.
    /// </summary>
    [Fact]
    public void AGateNamedWithoutBeingCalledIsDeclined()
    {
        using var module = BuildGateModule(GateReference.FunctionPointer);
        var gate = Gate(module);

        var found = AntiTamperNeutralizationPass.TryFindCalls(
            module, gate, out var calls, out var diagnostic);

        Assert.False(found);
        Assert.Empty(calls);
        Assert.Contains("other than by a direct call", diagnostic);
    }

    private enum GateReference
    {
        None,
        TwoDirectCalls,
        FunctionPointer
    }

    private static MethodDef Gate(ModuleDefMD module) => module.Types
        .Single(type => type.Name == "Runtime")
        .Methods.Single(method => method.Name == "Gate");

    private static ModuleDefMD BuildGateModule(GateReference reference)
    {
        var module = new ModuleDefUser("gate.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("gate", new Version(1, 0));
        assembly.Modules.Add(module);
        var type = new TypeDefUser("Tests", "Runtime", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);

        var gate = NewStaticVoid("Gate");
        gate.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(gate);

        switch (reference)
        {
            case GateReference.TwoDirectCalls:
                foreach (var name in (string[])["First", "Second"])
                {
                    var caller = NewStaticVoid(name);
                    caller.Body.Instructions.Add(Instruction.Create(OpCodes.Call, gate));
                    caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                    type.Methods.Add(caller);
                }
                break;
            case GateReference.FunctionPointer:
                var taker = NewStaticVoid("Taker");
                taker.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, gate));
                taker.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
                taker.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                type.Methods.Add(taker);
                break;
            default:
                break;
        }

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

    private static PipelineResult RunAnalyze(string filename)
    {
        var sample = Checkout.Sample(filename);
        var directory = Path.Combine(
            Path.GetTempPath(), $"Cilantro.AntiTamper.{Guid.NewGuid():N}");
        try
        {
            return new CilantroPipeline().Run(sample, new PipelineOptions(
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

}
