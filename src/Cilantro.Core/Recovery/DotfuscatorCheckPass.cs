using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Selects the clean verdict of reviewed Dotfuscator debugging, integrity and Android root checks.</summary>
public sealed class DotfuscatorCheckPass : DeobfuscationPass
{
    public override string Name => "dotfuscator-checks";
    public override IReadOnlyCollection<string> Dependencies => ["dotfuscator-detection", "method-body-recovery"];
    public override bool GatesEmission => true;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<DotfuscatorStructureFacts>("dotfuscator.structure", out var facts) || facts?.IsDotfuscator != true)
            return (PassStatus.Success, 0, ["No Dotfuscator check runtime detected."]);
        using var original = ModuleDefMD.Load(context.OriginalBytes);
        var runtimes = DotfuscatorCheckShape.Find(original).ToArray();
        if (runtimes.Length == 0) return (PassStatus.Success, 0, ["No generated debugging, integrity or Android root checker found."]);
        var unknown = new List<string>();
        var normalized = new Dictionary<uint, string>();
        foreach (var runtime in runtimes.Where(runtime => !DotfuscatorCheckShape.Supported(runtime)))
        {
            // Each family receives a fresh private copy. Later token-bound
            // recovery continues to use the original bytes and metadata.
            using var proof = ModuleDefMD.Load(context.OriginalBytes);
            var candidate = DotfuscatorCheckShape.Find(proof).SingleOrDefault(item => item.Method.MDToken == runtime.Method.MDToken);
            if (candidate is not null && DotfuscatorCheckNormalization.TryNormalize(candidate, requireShortLocalMarker: true, out var fingerprint) &&
                DotfuscatorCheckNormalization.Reviewed(fingerprint)) normalized.Add(runtime.Method.MDToken.Raw, fingerprint);
            else unknown.Add(runtime.Kind + ": " + runtime.Fingerprint);
        }
        if (unknown.Count != 0)
            return (PassStatus.Unsupported, 0, ["Unreviewed Dotfuscator checks preserved; emission withheld because retained checks could reject a rewritten assembly.",
                .. unknown]);
        var methods = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToArray();
        var changed = new HashSet<MethodDef>();
        var sites = 0;
        var responses = 0;
        var retiredResponses = new List<RetiredDotfuscatorResponseRuntime.Site>();
        using var batch = new BodyMutationBatch();
        foreach (var runtime in runtimes)
        {
            if (context.Module.ResolveToken(runtime.Method.MDToken) is not MethodDef detector)
                return (PassStatus.Unsupported, 0, ["Generated check method is unavailable."]);
            foreach (var caller in methods)
            {
                var calls = caller.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Call &&
                    instruction.Operand is IMethod called && called.ResolveMethodDef() == detector).ToArray();
                foreach (var call in calls)
                {
                    batch.Capture(caller);
                    var index = caller.Body.Instructions.IndexOf(call);
                    var verdict = call;
                    // Retire only the closed generated metadata/address sequence.
                    // Other argument evaluation retains all application effects.
                    var retiredArguments = runtime.Kind is "tamper-file" or "tamper-memory" && RetireTamperArguments(caller, call, detector, runtime.Kind);
                    if (detector.MethodSig.Params.Count > 0 && !retiredArguments)
                    {
                        call.OpCode = OpCodes.Pop;
                        call.Operand = null;
                        for (var argument = 1; argument < detector.MethodSig.Params.Count; argument++)
                            caller.Body.Instructions.Insert(++index, OpCodes.Pop.ToInstruction());
                        verdict = OpCodes.Ldc_I4.ToInstruction(unchecked((int)runtime.CleanVerdict));
                        caller.Body.Instructions.Insert(++index, verdict);
                    }
                    else { call.OpCode = OpCodes.Ldc_I4; call.Operand = unchecked((int)runtime.CleanVerdict); }
                    var verdictUses = FoldVerdictUses(caller, verdict, unchecked((int)runtime.CleanVerdict));
                    responses += FoldResponses(caller, verdictUses, retiredResponses);
                    RetireProbability(caller);
                    changed.Add(caller);
                    sites++;
                }
            }
            // Handles taken elsewhere must receive the same verdict. The original
            // runtime's type initialization is a reviewed part of the checker family.
            batch.Capture(detector);
            detector.Body = new CilBody();
            detector.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(unchecked((int)runtime.CleanVerdict)));
            detector.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            changed.Add(detector);
        }
        foreach (var method in changed)
        {
            method.Body.SimplifyBranches();
            if (!EvaluationStackAnalyzer.Analyze(method).Valid)
                return (PassStatus.Unsupported, 0, ["Check recovery did not pass evaluation-stack verification; changes rolled back."]);
        }
        batch.Commit();
        RetiredDotfuscatorResponseRuntime.Remember(context, retiredResponses);
        foreach (var runtime in runtimes.Where(runtime => runtime.Kind == "root"))
        {
            RetiredDotfuscatorRootRuntime.Remember(context, runtime);
            var types = runtime.Types.Select(type => context.Module.ResolveToken(type.MDToken)).OfType<TypeDef>().ToArray();
            // Whole-family review attributes the injected helpers. Ordinary
            // visibility, reachability and surviving-reference checks still
            // decide which declarations may disappear.
            RecoveryOrphans.DeclareTypes(context, types);
            RecoveryOrphans.Declare(context, types.SelectMany(type => type.Methods));
        }
        context.SetFact("dotfuscator.checks.neutralizedSites", sites);
        context.SetFact("dotfuscator.checks.normalizedGraphs", normalized);
        foreach (var runtime in runtimes)
            context.AddEvidence(new("dotfuscator-check", $"Selected the clean {runtime.Kind} verdict of reviewed graph {normalized.GetValueOrDefault(runtime.Method.MDToken.Raw, runtime.Fingerprint)}" +
                (normalized.ContainsKey(runtime.Method.MDToken.Raw) ? " after bounded control-flow normalization" : "") +
                "; native/file probing was not executed by analysis.", runtime.Method.MDToken.ToString()));
        context.AddChange(new(Name, "neutralize-dotfuscator-checks", "module", $"Neutralized {sites} calls and simplified {responses} response dispatchers; application notifications retained."));
        return (PassStatus.Success, sites, [$"Neutralized {runtimes.Length} reviewed checker methods at {sites} call sites; simplified {responses} response dispatchers and retained application notification effects.",
            $"Matched {normalized.Count} checker families to reviewed complete graphs after bounded control-flow normalization."]);
    }

    private static HashSet<Instruction> FoldVerdictUses(MethodDef caller, Instruction verdict, int value)
    {
        var proven = new HashSet<Instruction>();
        var graph = ControlFlowGraph.Build(caller);
        var block = graph.BlockOf(verdict);
        var il = caller.Body.Instructions;
        var index = il.IndexOf(verdict);
        if (index + 1 >= il.Count || !il[index + 1].IsStloc()) return proven;
        var store = il[index + 1];
        if (graph.BlockOf(store) != block) return proven;
        var local = store.GetLocal(caller.Body.Variables);
        if (local is null || il.Any(instruction => instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S &&
                instruction.GetLocal(caller.Body.Variables) == local)) return proven;
        // Propagate only a must-known definition. Exception edges carry unknown
        // state because an exception can leave a block before its final store.
        var outgoing = graph.Blocks.ToDictionary(item => item, _ => false);
        var lastStores = graph.Blocks.ToDictionary(item => item, item => item.Instructions.LastOrDefault(instruction =>
            instruction.IsStloc() && instruction.GetLocal(caller.Body.Variables) == local));
        bool Incoming(BasicBlock item) => item != graph.Entry && item.Predecessors.Count > 0 &&
            item.Predecessors.All(edge => edge.Kind != ControlFlowEdgeKind.Exception && outgoing[edge.Source]);
        if (graph.Blocks.Count <= 4096)
        {
            for (var iteration = 0; iteration <= graph.Blocks.Count; iteration++)
            {
                var changed = false;
                foreach (var item in graph.Blocks)
                {
                    var known = lastStores[item] is { } last ? last == store : Incoming(item);
                    if (outgoing[item] == known) continue;
                    outgoing[item] = known;
                    changed = true;
                }
                if (!changed) break;
            }
        }
        foreach (var item in graph.Blocks)
        {
            var known = Incoming(item);
            foreach (var instruction in item.Instructions)
            {
                if (instruction.IsStloc() && instruction.GetLocal(caller.Body.Variables) == local) { known = instruction == store; continue; }
                if (!known || !instruction.IsLdloc() || instruction.GetLocal(caller.Body.Variables) != local) continue;
                instruction.OpCode = OpCodes.Ldc_I4;
                instruction.Operand = value;
                proven.Add(instruction);
            }
            var meaningful = item.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
            for (var at = 0; at + 6 < meaningful.Length; at++)
            {
                var slice = meaningful.AsSpan(at, 7);
                if (!slice[0].IsLdcI4() || !slice[1].IsLdcI4() || slice[2].OpCode.Code != Code.Xor ||
                    !slice[3].IsLdcI4() || slice[4].OpCode.Code != Code.And || !slice[5].IsLdcI4() ||
                    slice[5].GetLdcI4Value() != 0 || slice[6].OpCode.Code != Code.Cgt_Un) continue;
                var answer = ((slice[0].GetLdcI4Value() ^ slice[1].GetLdcI4Value()) & slice[3].GetLdcI4Value()) != 0;
                if (at + 8 < meaningful.Length && meaningful[at + 7].IsLdcI4() && meaningful[at + 7].GetLdcI4Value() == 0 && meaningful[at + 8].OpCode.Code == Code.Ceq)
                {
                    answer = !answer;
                    meaningful[at + 7].OpCode = OpCodes.Nop; meaningful[at + 7].Operand = null;
                    meaningful[at + 8].OpCode = OpCodes.Nop; meaningful[at + 8].Operand = null;
                }
                slice[0].OpCode = OpCodes.Ldc_I4;
                slice[0].Operand = answer ? 1 : 0;
                for (var erased = 1; erased < slice.Length; erased++) { slice[erased].OpCode = OpCodes.Nop; slice[erased].Operand = null; }
            }
        }
        return proven;
    }

    private static bool RetireTamperArguments(MethodDef caller, Instruction call, MethodDef detector, string kind)
    {
        var il = caller.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        var at = Array.IndexOf(il, call);
        var memory = kind == "tamper-memory";
        var length = memory ? 16 : 15;
        if (at < length - 1) return false;
        var slice = il.AsSpan(at - length + 1, length);
        var graph = ControlFlowGraph.Build(caller);
        if (graph.BlockOf(slice[0]) != graph.BlockOf(call) || slice[0].OpCode.Code != Code.Call ||
            slice[0].Operand is not IMethod getterReference || getterReference.ResolveMethodDef() is not { IsStatic: true, HasBody: true } getter ||
            getter.DeclaringType != caller.DeclaringType || !LiteralArray(getter) || !slice[1].IsStloc() ||
            slice[2].OpCode.Code != Code.Ldtoken || slice[2].Operand is not ITypeDefOrRef owner || owner.ResolveTypeDef() != caller.DeclaringType ||
            !FrameworkCall(slice[3], "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)", caller.Module) ||
            !FrameworkCall(slice[4], "System.Reflection.Assembly System.Reflection.Assembly::GetAssembly(System.Type)", caller.Module)) return false;
        if (memory && (slice[5].OpCode.Code != Code.Call || slice[5].Operand is not IMethod address ||
            address.ResolveMethodDef() is not { } method || method.DeclaringType != detector.DeclaringType ||
            method.Name != "FindMyAddress" || method.MethodSig.Params.Count != 1 || method.MethodSig.Params[0].FullName != "System.Reflection.Assembly" ||
            method.ReturnType.FullName != "System.IntPtr")) return false;
        var local = slice[1].GetLocal(caller.Body.Variables);
        if (local is null || caller.Body.Instructions.Count(instruction => (instruction.IsLdloc() || instruction.IsStloc() ||
            instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S) && instruction.GetLocal(caller.Body.Variables) == local) != 4) return false;
        for (var argument = 0; argument < 3; argument++)
        {
            var index = (memory ? 6 : 5) + argument * 3;
            if (!slice[index].IsLdloc() || slice[index].GetLocal(caller.Body.Variables) != local ||
                !slice[index + 1].IsLdcI4() || slice[index + 1].GetLdcI4Value() != argument || slice[index + 2].OpCode.Code != Code.Ldelem_Ref) return false;
        }
        for (var erased = 0; erased < length - 1; erased++) { slice[erased].OpCode = OpCodes.Nop; slice[erased].Operand = null; }
        return true;
    }

    private static bool LiteralArray(MethodDef getter)
    {
        if (getter.HasGenericParameters || getter.MethodSig.Params.Count != 0 || getter.ReturnType.FullName != "System.String[]" ||
            getter.Body.Variables.Count != 1 || getter.Body.ExceptionHandlers.Count != 0) return false;
        var il = getter.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        if (il.Length != 17 || !il[0].IsLdcI4() || il[0].GetLdcI4Value() != 3 || il[1].OpCode.Code != Code.Newarr ||
            il[1].Operand is not ITypeDefOrRef { FullName: "System.String" } || !il[2].IsStloc() || !il[15].IsLdloc() || il[16].OpCode.Code != Code.Ret) return false;
        var local = il[2].GetLocal(getter.Body.Variables);
        if (il[15].GetLocal(getter.Body.Variables) != local) return false;
        for (var item = 0; item < 3; item++)
        {
            var at = 3 + item * 4;
            if (!il[at].IsLdloc() || il[at].GetLocal(getter.Body.Variables) != local || !il[at + 1].IsLdcI4() ||
                il[at + 1].GetLdcI4Value() != item || il[at + 2].OpCode.Code != Code.Ldstr ||
                il[at + 2].Operand is not string { Length: <= 1048576 } || il[at + 3].OpCode.Code != Code.Stelem_Ref) return false;
        }
        return true;
    }

    private static bool FrameworkCall(Instruction instruction, string signature, ModuleDef module) => instruction.OpCode.Code == Code.Call &&
        instruction.Operand is IMethod called && called.FullName == signature && called.DeclaringType is TypeRef &&
        called.DeclaringType.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;

    private static int FoldResponses(MethodDef caller, HashSet<Instruction> verdictUses, List<RetiredDotfuscatorResponseRuntime.Site> retired)
    {
        var graph = ControlFlowGraph.Build(caller);
        var il = caller.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        var count = 0;
        for (var at = 0; at + 18 < il.Length; at++)
        {
            var slice = il.AsSpan(at, 19);
            if (!slice[0].IsLdcI4() || slice[0].GetLdcI4Value() != 2 || slice[1].OpCode.Code != Code.Newarr ||
                slice[1].Operand is not TypeRef { FullName: "System.Action" } action || action.DefinitionAssembly?.FullName != caller.Module.CorLibTypes.AssemblyRef.FullName || !slice[2].IsStloc() ||
                !slice[3].IsLdloc() || !slice[9].IsLdloc() || !slice[15].IsLdloc() ||
                !slice[4].IsLdcI4() || slice[4].GetLdcI4Value() != 0 || !slice[10].IsLdcI4() || slice[10].GetLdcI4Value() != 1 ||
                slice[5].OpCode.Code != Code.Ldnull || slice[11].OpCode.Code != Code.Ldnull ||
                slice[6].OpCode.Code != Code.Ldftn || slice[12].OpCode.Code != Code.Ldftn ||
                !ActionConstructor(slice[7], caller.Module) || !ActionConstructor(slice[13], caller.Module) ||
                slice[8].OpCode.Code != Code.Stelem_Ref || slice[14].OpCode.Code != Code.Stelem_Ref ||
                !slice[16].IsLdcI4() || slice[16].GetLdcI4Value() is not (0 or 1) || slice[17].OpCode.Code != Code.Ldelem_Ref ||
                slice[18].OpCode.Code != Code.Callvirt || slice[18].Operand is not IMethod { FullName: "System.Void System.Action::Invoke()" } invoke ||
                invoke.DeclaringType?.DefinitionAssembly?.FullName != caller.Module.CorLibTypes.AssemblyRef.FullName ||
                graph.BlockOf(slice[0]) != graph.BlockOf(slice[18])) continue;
            var local = slice[2].GetLocal(caller.Body.Variables);
            if (local is null || slice[3].GetLocal(caller.Body.Variables) != local || slice[9].GetLocal(caller.Body.Variables) != local ||
                slice[15].GetLocal(caller.Body.Variables) != local || caller.Body.Instructions.Count(instruction =>
                    (instruction.IsLdloc() || instruction.IsStloc() || instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S) &&
                    instruction.GetLocal(caller.Body.Variables) == local) != 4) continue;
            var selected = slice[slice[16].GetLdcI4Value() == 0 ? 6 : 12].Operand as IMethod;
            if (selected?.ResolveMethodDef() is not { IsStatic: true, HasBody: true } thunk || thunk.DeclaringType != caller.DeclaringType ||
                thunk.HasGenericParameters || thunk.MethodSig.Params.Count != 0 || thunk.ReturnType.ElementType != ElementType.Void) continue;
            // Only a selector derived from this reviewed check can attribute a
            // response. Other literal-index Action arrays may still be folded,
            // but confer no permission to retire their methods or public types.
            if (verdictUses.Contains(slice[16]) &&
                slice[slice[16].GetLdcI4Value() == 0 ? 12 : 6].Operand is IMethod failed && failed.ResolveMethodDef() is { } failure)
                retired.Add(new(caller, failure, thunk));
            slice[0].OpCode = OpCodes.Call;
            slice[0].Operand = thunk;
            for (var erased = 1; erased < slice.Length; erased++) { slice[erased].OpCode = OpCodes.Nop; slice[erased].Operand = null; }
            count++;
        }
        return count;
    }

    private static bool ActionConstructor(Instruction instruction, ModuleDef module) => instruction.OpCode.Code == Code.Newobj &&
        instruction.Operand is IMethod { FullName: "System.Void System.Action::.ctor(System.Object,System.IntPtr)" } called &&
        called.DeclaringType is TypeRef && called.DeclaringType.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;

    private static void RetireProbability(MethodDef caller)
    {
        var il = caller.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        var graph = ControlFlowGraph.Build(caller);
        for (var at = 0; at + 20 < il.Length; at++)
        {
            var slice = il.AsSpan(at, 21);
            if (!slice[0].IsLdcI4() || slice[0].GetLdcI4Value() != 8 || slice[1].OpCode.Code != Code.Newarr ||
                slice[1].Operand is not ITypeDefOrRef { FullName: "System.Byte" } || !slice[2].IsStloc() || !slice[4].IsStloc() ||
                !NamedFrameworkCall(slice[3], Code.Call, "System.Security.Cryptography.RandomNumberGenerator System.Security.Cryptography.RandomNumberGenerator::Create()", caller.Module) ||
                !slice[5].IsLdloc() || !slice[6].IsLdloc() ||
                !NamedFrameworkCall(slice[7], Code.Callvirt, "System.Void System.Security.Cryptography.RandomNumberGenerator::GetBytes(System.Byte[])", caller.Module) ||
                !slice[8].IsLdloc() || !NamedFrameworkCall(slice[9], Code.Callvirt, "System.Void System.Security.Cryptography.RandomNumberGenerator::Dispose()", caller.Module) ||
                slice[10].OpCode.Code != Code.Ldc_R8 || slice[10].Operand is not double probability || !double.IsFinite(probability) || probability is < 0 or > 1 ||
                !slice[11].IsLdloc() || !slice[12].IsLdcI4() || slice[12].GetLdcI4Value() != 0 ||
                !NamedFrameworkCall(slice[13], Code.Call, "System.UInt64 System.BitConverter::ToUInt64(System.Byte[],System.Int32)", caller.Module) ||
                slice[14].OpCode.Code != Code.Conv_R_Un || slice[15].OpCode.Code != Code.Conv_R8 || slice[16].OpCode.Code != Code.Ldc_R8 ||
                slice[16].Operand is not double denominator || denominator != 18446744073709551616d || slice[17].OpCode.Code != Code.Div || slice[18].OpCode.Code != Code.Clt ||
                slice[19].OpCode.Code is not (Code.Brtrue or Code.Brtrue_S) || slice[19].Operand is not Instruction target ||
                slice[20].OpCode.Code != Code.Call || slice[20].Operand is not IMethod reference || reference.ResolveMethodDef() is not { } thunk ||
                thunk.DeclaringType != caller.DeclaringType || !EmptyResponse(thunk) ||
                graph.BlockOf(slice[0]) != graph.BlockOf(slice[19]) || !graph.HaveIdenticalExceptionRegions(slice[0], slice[20])) continue;
            var skipped = graph.BlockOf(slice[20]);
            if (skipped.Predecessors.Count != 1 || skipped.Predecessors[0].Source != graph.BlockOf(slice[19]) ||
                skipped.Predecessors[0].Kind != ControlFlowEdgeKind.FallThrough) continue;
            var callIndex = caller.Body.Instructions.IndexOf(slice[20]);
            var targetIndex = caller.Body.Instructions.IndexOf(target);
            if (targetIndex <= callIndex || caller.Body.Instructions.Skip(callIndex + 1).Take(targetIndex - callIndex - 1).Any(instruction => instruction.OpCode.Code != Code.Nop)) continue;
            var buffer = slice[2].GetLocal(caller.Body.Variables);
            var random = slice[4].GetLocal(caller.Body.Variables);
            if (buffer is null || random is null || buffer == random || slice[5].GetLocal(caller.Body.Variables) != random ||
                slice[8].GetLocal(caller.Body.Variables) != random || slice[6].GetLocal(caller.Body.Variables) != buffer ||
                slice[11].GetLocal(caller.Body.Variables) != buffer || Uses(buffer) != 3 || Uses(random) != 3) continue;
            foreach (var instruction in slice) { instruction.OpCode = OpCodes.Nop; instruction.Operand = null; }
        }
        int Uses(Local local) => caller.Body.Instructions.Count(instruction =>
            (instruction.IsLdloc() || instruction.IsStloc() || instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S) && instruction.GetLocal(caller.Body.Variables) == local);
    }

    private static bool EmptyResponse(MethodDef method) => method.IsStatic && method.IsPrivate && !method.HasGenericParameters &&
        method.MethodSig.Params.Count == 0 && method.ReturnType.ElementType == ElementType.Void && method.ImplAttributes == MethodImplAttributes.IL &&
        !method.HasDeclSecurities && !method.HasCustomAttributes && method.HasBody && method.Body.ExceptionHandlers.Count == 0 &&
        method.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).Select(instruction => instruction.OpCode.Code).SequenceEqual([Code.Ret]);

    private static bool NamedFrameworkCall(Instruction instruction, Code opcode, string signature, ModuleDef module)
    {
        if (instruction.OpCode.Code != opcode || instruction.Operand is not IMethod called || called.FullName != signature ||
            called.DeclaringType is not TypeRef || called.DeclaringType.DefinitionAssembly is not AssemblyRef assembly) return false;
        var token = assembly.PublicKeyOrToken?.Token?.Data;
        // The reviewed CoreCLR injector writes this facade as an unsigned,
        // zero-version reference; the Framework injector uses its signed identity.
        if (assembly.Name == "System.Security.Cryptography.Algorithms" && assembly.Version == new Version(0, 0, 0, 0) &&
            (token is null || token.Length == 0) && module.CorLibTypes.AssemblyRef.Name == "System.Runtime" &&
            module.CorLibTypes.AssemblyRef.PublicKeyOrToken?.Token?.ToString() == "b03f5f7f11d50a3a") return true;
        return assembly.Name.String is "mscorlib" or "System.Runtime" or "System.Private.CoreLib" or "System.Security.Cryptography" or "System.Security.Cryptography.Algorithms" &&
            token is not null && Convert.ToHexStringLower(token) is "b77a5c561934e089" or "b03f5f7f11d50a3a" or "7cec85d7bea7798e";
    }
}
