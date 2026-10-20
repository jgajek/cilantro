using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Removes reviewed Babel debugging and original-image integrity initializers.</summary>
public sealed class BabelCheckPass : DeobfuscationPass
{
    public override string Name => "babel-checks";
    public override IReadOnlyCollection<string> Dependencies => ["babel-detection", "method-body-recovery"];
    public override bool GatesEmission => true;
    internal const string NeutralizedFact = "babel.checks.neutralized";

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<BabelStructureFacts>("babel.structure", out var babel) || babel?.IsBabel != true)
            return (PassStatus.Success, 0, ["No Babel checks detected."]);
        using var original = ModuleDefMD.Load(context.OriginalBytes);
        var checks = BabelCheckShape.Find(original).ToArray();
        if (checks.Length == 0) return (PassStatus.Success, 0, ["No Babel check initializers found."]);
        foreach (var check in checks)
        {
            if (!BabelCheckShape.Supported(check))
                return (PassStatus.Unsupported, 0, [$"Unreviewed Babel {check.Kind} graph {check.Graph.Fingerprint}; emission withheld."]);
            if (check.Kind == "integrity" && !OriginalImageAccepted(context, original, check.Method, out var why))
                return (PassStatus.Unsupported, 0, [$"Babel original-image integrity proof did not complete: {why}"]);
        }
        var changed = 0;
        var tokens = new HashSet<uint>();
        using var batch = new BodyMutationBatch();
        foreach (var check in checks)
        {
            if (context.Module.ResolveToken(check.Method.MDToken) is not MethodDef root)
                return (PassStatus.Unsupported, 0, ["Babel check initializer is unavailable."]);
            foreach (var caller in context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
                foreach (var call in caller.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Call &&
                             instruction.Operand is IMethod called && called.ResolveMethodDef() == root).ToArray())
                {
                    batch.Capture(caller);
                    call.OpCode = OpCodes.Nop;
                    call.Operand = null;
                    changed++;
                }
            batch.Capture(root);
            root.Body = new CilBody();
            root.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            tokens.Add(root.MDToken.Raw);
            batch.RecordChange(context, new(Name, "neutralize-babel-check", root.FullName,
                $"Selected the clean {check.Kind} path of reviewed graph {check.Graph.Fingerprint}; no background thread or native checker was executed."));
        }
        if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed)
            return (PassStatus.Unsupported, 0, ["Babel check removal did not pass structural verification; original checks retained."]);
        batch.Commit();
        foreach (var check in checks)
            RecoveryOrphans.DeclareOwningTypes(context, check.Graph.Types.SelectMany(type => type.Methods).Select(method =>
                context.Module.ResolveToken(method.MDToken)).OfType<MethodDef>());
        context.SetFact(NeutralizedFact, tokens);
        return (PassStatus.Success, changed, [$"Neutralized {changed} calls to {checks.Length} reviewed Babel check initializers; integrity bindings verified against the original mapped image."]);
    }

    private static bool OriginalImageAccepted(ArtifactContext context, ModuleDef original, MethodDef root, out string why)
    {
        // The reviewed loop visits the original PE words; its work scales with
        // image size. Keep a hard ceiling for damaged or nonterminating inputs.
        var steps = (int)Math.Clamp((long)context.OriginalBytes.Length * 64, 4_000_000, 64_000_000);
        var machine = new StaticMachine(BootstrapMachine.Limits(steps), modelTypeInitialization: true);
        machine.State.RegisterModuleMetadata(original);
        machine.State.RegisterAssemblyIdentity(original.Assembly?.Name ?? original.Name, original.Assembly?.PublicKeyToken?.Data ?? []);
        machine.State.RegisterPointerSize(context.OriginalImage.IsPe32Plus ? 8 : 4);
        machine.State.RegisterModuleFile(context.InputPath, context.OriginalBytes);
        if (!machine.State.TryRegisterImage(context.OriginalImage.CreateMappedImage(), context.OriginalImage.ImageBase, BootstrapMachine.MappedProtections(context.OriginalImage)))
        { why = "mapped-image budget exceeded"; return false; }
        var result = machine.Execute(root);
        var effects = machine.State.LoaderEvidence.EffectsOf(root.MDToken.Raw);
        why = result.Diagnostic ?? result.Status.ToString();
        return result.Succeeded && !effects.WroteStaticField && !effects.WroteMappedImage && !effects.WroteScratchRegion && effects.Registrations.Count == 0;
    }
}
