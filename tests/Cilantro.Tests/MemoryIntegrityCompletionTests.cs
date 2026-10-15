using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class MemoryIntegrityCompletionTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("changed-source", false)]
    [InlineData("changed-body", false)]
    [InlineData("reader-retained", false)]
    [InlineData("no-evidence", false)]
    public void VerifiedMemoryPathRetiresOnlyItsExactUnusedSignatureInput(string scenario, bool removed)
    {
        using var context = Fixture();
        var gate = Gate(context);
        Facts(context, gate);
        var resource = (EmbeddedResource)context.Module.Resources.Single();
        var at = gate.Body.Instructions.IndexOf(gate.Body.Instructions.Single(i => i.Operand is IMethod m && m.Name == "VerifyHash")) - 4;
        gate.Body.Instructions.Insert(at, OpCodes.Ldstr.ToInstruction("signature"));
        gate.Body.Instructions.Insert(at + 1, OpCodes.Pop.ToInstruction());
        var origin = RecoveredResourceOrigin.Capture(resource);
        // The later successful memory-load bootstrap has no signature-resource read.
        context.SetFact("bootstrap.evidence", new LoaderInterpretationEvidence([], new Dictionary<uint, LoaderMethodEffects>()));
        if (scenario != "no-evidence") context.SetFact("bootstrap.moduleFileRefusalEvidence", new LoaderInterpretationEvidence([
            new(LoaderObservationKind.ManagedResourceRead, System.Text.Json.JsonSerializer.Serialize(
                new ManagedResourceRead(origin.Name, origin.Sha256, 3)), null, [gate.MDToken.Raw])
        ], new Dictionary<uint, LoaderMethodEffects>()));
        var completed = new MemoryIntegrityCompletionPass().Run(context);
        Assert.True(completed.Changes == 1, string.Join("; ", completed.Diagnostics));
        if (scenario == "changed-source")
        {
            context.Module.Resources.Remove(resource);
            context.Module.Resources.Add(new EmbeddedResource("signature", new byte[] { 4 }, ManifestResourceAttributes.Private));
        }
        if (scenario == "changed-body") gate.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
        if (scenario == "reader-retained")
        {
            var read = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read");
            read.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("signature"));
            read.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        new ProtectorResourceCleanupPass().Run(context);
        Assert.Equal(removed, !context.Module.Resources.Any(r => r.Name == "signature"));
        Assert.Equal(7, Read(context));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RemovesOnlyTheRecordedFileCheckAndKeepsSharedInitialization(bool handler)
    {
        using var context = Fixture();
        var gate = Gate(context);
        if (handler)
        {
            var il = gate.Body.Instructions;
            var signature = il.Single(i => i.Operand is IMethod m && m.Name == "VerifyHash");
            var start = il[il.IndexOf(signature) - 4];
            var end = il[^1];
            var catcher = OpCodes.Pop.ToInstruction();
            il.Insert(il.Count - 1, OpCodes.Leave.ToInstruction(end));
            il.Insert(il.Count - 1, catcher);
            il.Insert(il.Count - 1, OpCodes.Leave.ToInstruction(end));
            gate.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            { TryStart = start, TryEnd = catcher, HandlerStart = catcher, HandlerEnd = end,
                CatchType = context.Module.CorLibTypes.GetTypeRef("System", "Exception") });
        }
        Facts(context, gate);
        var before = Read(context);
        var result = new MemoryIntegrityCompletionPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.True(context.TryGetFact<uint>("antitamper.memoryLoadEntryPoint", out var completed));
        Assert.Equal(gate.MDToken.Raw, completed);
        Assert.Equal(before, Read(context));
        Assert.Equal(7, Read(context));
        Assert.DoesNotContain(gate.Body.Instructions, i => i.Operand is IMethod m && m.Name == "VerifyHash");
        Assert.Contains(gate.Body.Instructions, i => i.OpCode.Code == Code.Stsfld);
        Assert.Empty(gate.Body.ExceptionHandlers);
        Assert.Equal(0, new MemoryIntegrityCompletionPass().Run(context).Changes);
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("no-refusal")]
    [InlineData("other-frame")]
    [InlineData("passing-file")]
    [InlineData("not-reactor")]
    [InlineData("external-assembly")]
    [InlineData("extra-location-use")]
    [InlineData("unknown-startup")]
    public void RefusesUnattributedOrUnprovenSpecialization(string scenario)
    {
        using var context = Fixture();
        var gate = Gate(context);
        Facts(context, gate);
        switch (scenario)
        {
            case "disabled": context.SetFact("options.removeRuntime", false); break;
            case "no-refusal": context.SetFact("bootstrap.moduleFileRefused", false); break;
            case "other-frame": context.SetFact("bootstrap.moduleFileRefusal", new LoaderObservation(LoaderObservationKind.SignatureVerification, "RSA", false, [0x06009999])); break;
            case "passing-file": context.SetFact("bootstrap.moduleFileRefusal", new LoaderObservation(LoaderObservationKind.SignatureVerification, "RSA", true, [gate.MDToken.Raw])); break;
            case "not-reactor": context.SetFact("reactor.structure", new ReactorStructureFacts(0, 0, 0, 0, 0, 0, 0, false, false, ReactorCapability.None, 0, "test")); break;
            case "external-assembly": gate.Body.Instructions.Single(i => i.OpCode.Code == Code.Ldtoken).Operand = context.Module.CorLibTypes.Object.TypeDefOrRef; break;
            case "extra-location-use":
                // Passing the location onward must not authorize dropping arbitrary
                // work: leave a second signature call reachable even for empty location.
                var signature = gate.Body.Instructions.Single(i => i.Operand is IMethod m && m.Name == "VerifyHash");
                var finish = gate.Body.Instructions[^1];
                var index = gate.Body.Instructions.IndexOf(finish);
                foreach (var i in new[] { OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(),
                    OpCodes.Ldnull.ToInstruction(), OpCodes.Callvirt.ToInstruction((IMethod)signature.Operand), OpCodes.Pop.ToInstruction() })
                    gate.Body.Instructions.Insert(index++, i);
                break;
            case "unknown-startup":
                context.Module.GlobalType.FindStaticConstructor()!.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(new MemberRefUser(context.Module,
                    "Missing", MethodSig.CreateStatic(context.Module.CorLibTypes.Void), context.Module.CorLibTypes.Object.TypeDefOrRef))); break;
        }
        var before = MethodBodySnapshot.Capture(gate);
        Assert.Equal(0, new MemoryIntegrityCompletionPass().Run(context).Changes);
        Assert.True(before.StructurallyEquals(gate));
    }

    [Fact]
    public void BranchEnteringReceiverEvaluationRefusesSelection()
    {
        using var context = Fixture();
        var gate = Gate(context);
        var location = MemoryIntegrityCompletionPass.SelectLocation(gate);
        Assert.NotNull(location);
        var nop = OpCodes.Nop.ToInstruction();
        gate.Body.Instructions.Insert(gate.Body.Instructions.IndexOf(location!), nop);
        gate.Body.Instructions.Insert(0, OpCodes.Br.ToInstruction(nop));
        Assert.Null(MemoryIntegrityCompletionPass.SelectLocation(gate));
    }

    private static MethodDef Gate(ArtifactContext c) => c.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Check");
    private static void Facts(ArtifactContext c, MethodDef gate)
    {
        c.SetFact("options.removeRuntime", true);
        c.SetFact("bootstrap.moduleFileRefused", true);
        c.SetFact("bootstrap.moduleFileRefusal", new LoaderObservation(LoaderObservationKind.SignatureVerification, "RSA", false, [gate.MDToken.Raw]));
        c.SetFact("reactor.structure", new ReactorStructureFacts(0, 0, 0, 0, 0, 0, 0, false, false, ReactorCapability.Virtualization, 1, "test"));
    }

    private static int Read(ArtifactContext c)
    {
        Assert.True(BootstrapMachine.TrySeed(c, 10000, out var machine, out var why), why);
        Assert.True(machine!.Execute(c.Module.GlobalType.FindStaticConstructor()!).Succeeded);
        var reader = c.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read");
        return machine.Execute(reader).Value.AsInt32();
    }

    private static ArtifactContext Fixture() => SyntheticContext.Build(module =>
    {
        module.Resources.Add(new EmbeddedResource("signature", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Private));
        var type = SyntheticContext.AddType(module, "Integrity");
        var state = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static); type.Fields.Add(state);
        var gate = new MethodDefUser("Check", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static) { Body = new CilBody { InitLocals = true } }; type.Methods.Add(gate);
        var reader = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Static) { Body = new CilBody() }; type.Methods.Add(reader);
        reader.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(state)); reader.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var location = new Local(module.CorLibTypes.String); gate.Body.Variables.Add(location);
        var end = OpCodes.Ret.ToInstruction();
        var systemType = module.CorLibTypes.GetTypeRef("System", "Type");
        var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
        var rsa = module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "RSACryptoServiceProvider");
        var instructions = new[] {
            OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Stsfld.ToInstruction(state), OpCodes.Ldtoken.ToInstruction(type),
            OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(systemType.ToTypeSig(),
                new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), systemType)),
            OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Assembly", MethodSig.CreateInstance(assembly.ToTypeSig()), systemType)),
            OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Location", MethodSig.CreateInstance(module.CorLibTypes.String), assembly)),
            OpCodes.Stloc.ToInstruction(location), OpCodes.Ldloc.ToInstruction(location), OpCodes.Brfalse.ToInstruction(end),
            OpCodes.Ldloc.ToInstruction(location), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Length",
                MethodSig.CreateInstance(module.CorLibTypes.Int32), module.CorLibTypes.String.TypeDefOrRef)), OpCodes.Brfalse.ToInstruction(end),
            OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(),
            OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "VerifyHash", MethodSig.CreateInstance(module.CorLibTypes.Boolean,
                new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.String, new SZArraySig(module.CorLibTypes.Byte)), rsa)),
            OpCodes.Pop.ToInstruction(), OpCodes.Ldstr.ToInstruction(" is tampered."), OpCodes.Pop.ToInstruction(), end };
        foreach(var i in instructions) gate.Body.Instructions.Add(i);
        var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
        module.GlobalType.Methods.Add(cctor); cctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(gate)); cctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
    });
}
