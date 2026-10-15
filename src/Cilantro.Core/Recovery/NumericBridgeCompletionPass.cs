using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Removes recovery-generated initialization calls once their work is gone.</summary>
public sealed class NumericBridgeCompletionPass : DeobfuscationPass
{
    public override string Name => "numeric-bridge-completion";
    public override IReadOnlyCollection<string> Dependencies => ["shared-initializer-runtime-cleanup"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<List<NumericTableRecoveryPass.InitializationBridge>>(
                NumericTableRecoveryPass.InitializationBridgesFact, out var bridges) || bridges is null)
            return (PassStatus.Success, 0, ["No recorded numeric initialization bridges."]);
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var present = methods.ToHashSet();
        var empty = bridges.Select(b => b.Method).Where(m => present.Contains(m) &&
            m.IsStatic && !m.IsConstructor && !m.HasGenericParameters &&
            m.MethodSig is { HasThis: false, GenParamCount: 0 } && m.MethodSig.Params.Count == 0 &&
            EmptyMethodBodies.DoesNothing(m) && SafeOwner(m.DeclaringType)).ToHashSet();
        using var edit = new BodyMutationBatch();
        var changed = 0;
        foreach (var method in methods.Where(m => m.HasBody))
        {
            var il = method.Body.Instructions;
            for (var index = 0; index < il.Count; index++)
            {
                var instruction = il[index];
                if (instruction.OpCode.Code != Code.Call || instruction.Operand is not MethodDef target ||
                    !empty.Contains(target) || index > 0 && il[index - 1].OpCode.OpCodeType == OpCodeType.Prefix)
                    continue;
                edit.Capture(method);
                instruction.OpCode = OpCodes.Nop;
                instruction.Operand = null;
                edit.RecordChange(context, new(Name, "remove-empty-numeric-bridge-call", method.FullName,
                    $"Removed a call to empty recovery-generated bridge {target.FullName}; no type initialization remains."));
                changed++;
            }
        }
        if (changed == 0) return (PassStatus.Success, 0, ["No empty numeric bridge calls remain."]);
        if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                CilantroPipeline.BuildRewriteAllowance(context)).Passed)
            return (PassStatus.Failed, 0, ["Numeric bridge removal failed verification and was rolled back."]);
        edit.Commit();
        RecoveryOrphans.DeclareOwningTypes(context, empty);
        return (PassStatus.Success, changed, [$"Removed {changed} empty numeric initialization call(s)."]);
    }

    private static bool SafeOwner(TypeDef owner)
    {
        for (var type = owner; type is not null; type = type.DeclaringType)
            if (type.HasGenericParameters) return false;
        return owner.FindStaticConstructor() is not { } initializer || EmptyTypeInitializers.DoesNothing(initializer);
    }
}

public sealed class NumericBridgeRuntimeCleanupPass : RuntimeCleanupPass
{
    public override string Name => "numeric-bridge-runtime-cleanup";
    public override IReadOnlyCollection<string> Dependencies => ["numeric-bridge-completion"];
}
