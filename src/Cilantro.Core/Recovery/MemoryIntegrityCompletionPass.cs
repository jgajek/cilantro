using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Preserves a recovered payload's proven memory-load integrity path in its emitted CIL.</summary>
public sealed class MemoryIntegrityCompletionPass : DeobfuscationPass
{
    public override string Name => "memory-integrity-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["integrity-verdict"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<bool>("bootstrap.moduleFileRefused", out var memory) || !memory ||
            !context.TryGetFact<LoaderObservation>("bootstrap.moduleFileRefusal", out var refusal) || refusal is null ||
            refusal.Kind != LoaderObservationKind.SignatureVerification || refusal.Verdict != false ||
            !context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var reactor) || reactor?.IsReactor != true)
            return (PassStatus.Success, 0, ["No recorded Reactor file refusal requires memory-load integrity completion."]);

        var gates = context.Module.GetTypes().SelectMany(t => t.Methods)
            .Where(m => refusal.CallStack.Contains(m.MDToken.Raw) && SelectLocation(m) is not null).ToArray();
        if (gates.Length != 1)
            return (PassStatus.Partial, 0, ["File refusal does not identify a unique direct self-integrity routine."]);
        var gate = gates[0];
        var retiredInput = RetiredIntegrityResource.Candidate(context, gate);
        var budget = LoaderCallElisionPass.ColdInitializerStepBudget(context);
        bool Read(out LoaderInterpretationEvidence? evidence, out string reason) =>
            LoaderCallElisionPass.TryInterpretColdInitializer(context, gate,
                new StaticWorkBudget(budget), new StaticWorkBudget(budget), out evidence, out reason);
        if (!Read(out var before, out var diagnostic))
            return (PassStatus.Partial, 0, ["Memory-load startup proof did not complete: " + diagnostic]);

        using var transaction = new BodyMutationTransaction(gate);
        var site = SelectLocation(gate)!;
        var index = gate.Body.Instructions.IndexOf(site);
        // The receiver is proven to be this module's Assembly, so its non-null
        // get_Location has no side effects. Keep all receiver evaluation and state
        // initialization. Only the attributed check gets memory-load semantics.
        site.OpCode = OpCodes.Pop;
        site.Operand = null;
        gate.Body.Instructions.Insert(index + 1, OpCodes.Ldstr.ToInstruction(""));
        FoldEmptyLocation(gate, index + 2);
        ControlFlowCompletionPass.TryComplete(gate);
        RemoveUnenteredHandlers(gate);
        ControlFlowCompletionPass.TryComplete(gate);
        if (gate.Body.Instructions.Any(IsSignatureCall) ||
            gate.Body.Instructions.Any(i => i.Operand is string s && s == " is tampered."))
            return (PassStatus.Partial, 0, ["The file-check path did not become unreachable; the rewrite was rolled back."]);
        if (!Read(out var after, out diagnostic) || !before!.Agrees(after!))
            return (PassStatus.Partial, 0, ["Memory-load startup effects did not agree after cleanup; the rewrite was rolled back. " + diagnostic]);
        var verification = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity,
            context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context));
        if (!verification.Passed)
            return (PassStatus.Partial, 0, ["Memory-load integrity rewrite failed structural verification and was rolled back."]);
        transaction.Commit();
        RetiredIntegrityResource.Remember(context, gate, retiredInput);
        context.SetFact("antitamper.memoryLoadEntryPoint", gate.MDToken.Raw);
        context.AddChange(new(Name, "remove-memory-payload-file-check", gate.FullName,
            "Removed the recorded rejected-file integrity path by specializing only this check to the payload's memory-load location; " +
            "retained initialization and shared state. Two independent cold startups before and after agree on loader effects."));
        return (PassStatus.Success, 1, ["Removed one attributed file-integrity check; preserved the recovered payload's memory-load startup effects."]);
    }

    internal static Instruction? SelectLocation(MethodDef gate)
    {
        if (!gate.HasBody || !gate.IsStatic || gate.HasGenericParameters || gate.DeclaringType.HasGenericParameters ||
            gate.MethodSig.Params.Count != 0 || gate.ReturnType.ElementType != ElementType.Void ||
            MemberVisibility.IsExternallyVisible(gate) || ReadingMarker.Marks(gate)) return null;
        var il = gate.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Count(IsSignatureCall) != 1 || !il.Any(i => i.OpCode.Code == Code.Ldstr && i.Operand is string s && s == " is tampered.")) return null;
        var locations = il.Select((i, n) => (i, n)).Where(p => IsCall(p.i,
            "System.String System.Reflection.Assembly::get_Location()")).ToArray();
        if (locations.Length != 1 || locations[0].n < 3) return null;
        var at = locations[0].n;
        if (il[at - 3].OpCode.Code != Code.Ldtoken || il[at - 3].Operand is not ITypeDefOrRef type ||
            type.ResolveTypeDef()?.Module != gate.Module ||
            !IsCall(il[at - 2], "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)") ||
            !IsCall(il[at - 1], "System.Reflection.Assembly System.Type::get_Assembly()")) return null;
        var first = gate.Body.Instructions.IndexOf(il[at - 3]) + 1;
        var last = gate.Body.Instructions.IndexOf(il[at]);
        var inner = gate.Body.Instructions.Skip(first).Take(last - first + 1).ToHashSet();
        if (gate.Body.Instructions.Any(i => i.Operand is Instruction target && inner.Contains(target) ||
            i.Operand is IList<Instruction> targets && targets.Any(inner.Contains)) ||
            gate.Body.ExceptionHandlers.Any(e => inner.Contains(e.TryStart) || inner.Contains(e.HandlerStart) ||
                e.FilterStart is { } filter && inner.Contains(filter) ||
                e.TryEnd is { } end && inner.Contains(end) || e.HandlerEnd is { } handlerEnd && inner.Contains(handlerEnd))) return null;
        return locations[0].i;
    }

    private static void FoldEmptyLocation(MethodDef gate, int start)
    {
        var il = gate.Body.Instructions;
        while (start < il.Count && il[start].OpCode.Code == Code.Nop) start++;
        if (start == il.Count || !il[start].IsStloc() || il[start].GetLocal(gate.Body.Variables) is not { } local) return;
        var accesses = il.Where(i => i.GetLocal(gate.Body.Variables) == local).ToArray();
        var reads = accesses.Where(i => i.IsLdloc()).ToArray();
        if (accesses.Any(i => i != il[start] && !i.IsLdloc())) return;
        var entries = il.SelectMany(i => i.Operand is Instruction t ? [t] : i.Operand as IList<Instruction> ?? []).ToHashSet();
        foreach (var eh in gate.Body.ExceptionHandlers)
            foreach (var edge in new[] { eh.TryStart, eh.TryEnd, eh.HandlerStart, eh.HandlerEnd, eh.FilterStart })
                if (edge is not null) entries.Add(edge);
        foreach (var read in reads)
        {
            var next = il.IndexOf(read) + 1;
            while (next < il.Count && il[next].OpCode.Code == Code.Nop && !entries.Contains(il[next])) next++;
            if (next == il.Count || entries.Contains(il[next])) continue;
            if (!ControlFlowCompletionPass.StoredBeforeEveryRead(gate, il[start], [read])) continue;
            if (IsCall(il[next], "System.Int32 System.String::get_Length()"))
            {
                read.OpCode = OpCodes.Ldc_I4_0; read.Operand = null;
                il[next].OpCode = OpCodes.Nop; il[next].Operand = null;
            }
            else if (il[next].OpCode.Code is Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S)
            { read.OpCode = OpCodes.Ldc_I4_1; read.Operand = null; }
        }
    }

    private static void RemoveUnenteredHandlers(MethodDef gate)
    {
        // Ordinary CFG cleanup deliberately roots every handler. Here the proven
        // early return can bypass the entire file-check region. Remove its clauses
        // only when *none* of their protected/filter/handler instructions can be
        // entered from the method entry without an exception. Otherwise keep all.
        var handlers = gate.Body.ExceptionHandlers.ToArray();
        if (handlers.Length == 0) return;
        HashSet<Instruction> reachable;
        gate.Body.ExceptionHandlers.Clear();
        try { reachable = CfgDeadCodePass.ComputeReachable(gate); }
        finally { foreach (var handler in handlers) gate.Body.ExceptionHandlers.Add(handler); }
        var il = gate.Body.Instructions;
        bool Enters(Instruction? start, Instruction? end)
        {
            if (start is null) return false;
            var first = il.IndexOf(start);
            var last = end is null ? il.Count : il.IndexOf(end);
            return first < 0 || last < first || il.Skip(first).Take(last - first).Any(reachable.Contains);
        }
        if (handlers.Any(e => Enters(e.TryStart, e.TryEnd) || Enters(e.HandlerStart, e.HandlerEnd) ||
            e.FilterStart is not null && Enters(e.FilterStart, e.HandlerStart))) return;
        gate.Body.ExceptionHandlers.Clear();
    }

    private static bool IsCall(Instruction i, string signature) => i.OpCode.Code is Code.Call or Code.Callvirt &&
        i.Operand is IMethod m && m.FullName == signature && m.DeclaringType is TypeRef &&
        m.DeclaringType.DefinitionAssembly?.Name.String is "mscorlib" or "System.Runtime" or "System.Reflection" or "System.Security.Cryptography.Csp" or "System.Security.Cryptography";

    private static bool IsSignatureCall(Instruction i) => IsCall(i,
        "System.Boolean System.Security.Cryptography.RSACryptoServiceProvider::VerifyHash(System.Byte[],System.String,System.Byte[])");
}
