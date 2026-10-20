using System.Security.Cryptography;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Recovers reviewed v2 native-key sites without loading a native library.</summary>
public sealed class DotfuscatorV2StringPass : DeobfuscationPass
{
    public override string Name => "dotfuscator-native-strings";
    public override IReadOnlyCollection<string> Dependencies => ["dotfuscator-detection", "dotfuscator-literal-strings"];
    // Unresolved keys depend on original caller names/signatures. Later transforms
    // may change those, so an incomplete recovery must withhold the rewritten file.
    public override bool GatesEmission => true;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<DotfuscatorStructureFacts>("dotfuscator.structure", out var facts) ||
            facts?.IsDotfuscator != true || !facts.HasNativeStringRuntime)
            return (PassStatus.Success, 0, ["No Dotfuscator v2 native-key runtime detected."]);
        using var original = ModuleDefMD.Load(context.OriginalBytes);
        var runtimes = DotfuscatorV2Shape.Find(original).ToArray();
        var diagnostics = new List<string>();
        var count = 0;
        var unresolved = 0;
        var changedCallers = new HashSet<MethodDef>();
        var retired = new List<DotfuscatorV2Shape.Runtime>();
        using var batch = new BodyMutationBatch();
        foreach (var runtime in runtimes)
        {
            var decoder = context.Module.ResolveToken(runtime.Decoder.MDToken) as MethodDef;
            if (decoder is null) { unresolved++; continue; }
            var callers = context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody &&
                m.Body.Instructions.Any(i => i.OpCode.Code == Code.Call && i.Operand is IMethod called && called.ResolveMethodDef() == decoder)).ToArray();
            if (callers.Length == 0) continue;
            if (!DotfuscatorV2Shape.Supported(runtime))
            {
                unresolved++;
                diagnostics.Add($"Unsupported Dotfuscator v2 decoder/bridge graph {runtime.Fingerprint}; calls preserved.");
                continue;
            }
            if (!Companions(context, runtime, out var detail))
            {
                unresolved++;
                diagnostics.Add(detail);
                continue;
            }
            context.AddEvidence(new("dotfuscator-v2-inputs", detail, Confidence: 1));
            retired.Add(runtime);
            foreach (var caller in callers)
            {
                var source = original.ResolveToken(caller.MDToken) as MethodDef;
                var signature = source is null ? null : DotfuscatorV2Codec.Signature(source);
                if (signature is null || signature.Length > 16384 || original.Assembly.Name.String.Length > 1024) { unresolved++; continue; }
                var key = DotfuscatorV2Codec.Key(original.Assembly.Name.String, signature);
                var graph = ControlFlowGraph.Build(caller);
                var il = caller.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                for (var at = 0; at < il.Length; at++)
                {
                    var call = il[at];
                    if (call.OpCode.Code != Code.Call || call.Operand is not IMethod called || called.ResolveMethodDef() != decoder) continue;
                    if (at < 4 || il[at - 4].OpCode.Code != Code.Ldstr || !il[at - 3].IsLdcI4() ||
                        il[at - 2].OpCode.Code != Code.Call || il[at - 2].Operand is not IMethod current ||
                        current.FullName != "System.Reflection.MethodBase System.Reflection.MethodBase::GetCurrentMethod()" ||
                        current.DeclaringType is not TypeRef || current.DeclaringType.DefinitionAssembly?.FullName !=
                            runtime.Parts.MethodSig.Params[0].ToTypeDefOrRef()?.DefinitionAssembly?.FullName ||
                        il[at - 1].OpCode.Code != Code.Call || il[at - 1].Operand is not IMethod parts ||
                        parts.ResolveMethodDef()?.MDToken != runtime.Parts.MDToken ||
                        graph.BlockOf(il[at - 4]) != graph.BlockOf(call) ||
                        !DotfuscatorV2Codec.TryDecode((string)il[at - 4].Operand, il[at - 3].GetLdcI4Value(), key, out var text))
                    { unresolved++; continue; }
                    batch.Capture(caller);
                    for (var erased = at - 4; erased < at; erased++) { il[erased].OpCode = OpCodes.Nop; il[erased].Operand = null; }
                    call.OpCode = OpCodes.Ldstr;
                    call.Operand = text;
                    var insert = caller.Body.Instructions.IndexOf(call);
                    // Preserve application type initialization. The reviewed native
                    // bridge's initialization/checks are intentionally retired here.
                    foreach (var owner in new[] { decoder.DeclaringType, parts.ResolveMethodDef()!.DeclaringType }.Distinct())
                        if (owner.FindStaticConstructor() is not null)
                        {
                            var helpers = new TypeRefUser(context.Module, "System.Runtime.CompilerServices", "RuntimeHelpers", context.Module.CorLibTypes.AssemblyRef);
                            var handle = new TypeRefUser(context.Module, "System", "RuntimeTypeHandle", context.Module.CorLibTypes.AssemblyRef);
                            var initialize = new MemberRefUser(context.Module, "RunClassConstructor", MethodSig.CreateStatic(context.Module.CorLibTypes.Void, new ValueTypeSig(handle)), helpers);
                            caller.Body.Instructions.Insert(insert++, OpCodes.Ldtoken.ToInstruction(owner));
                            caller.Body.Instructions.Insert(insert++, OpCodes.Call.ToInstruction(initialize));
                        }
                    // Encoding.GetString returns a fresh nonempty string. Keep that
                    // observable allocation rather than returning an interned literal.
                    var toChars = new MemberRefUser(context.Module, "ToCharArray", MethodSig.CreateInstance(new SZArraySig(context.Module.CorLibTypes.Char)), context.Module.CorLibTypes.String.TypeDefOrRef);
                    var constructor = new MemberRefUser(context.Module, ".ctor", MethodSig.CreateInstance(context.Module.CorLibTypes.Void, new SZArraySig(context.Module.CorLibTypes.Char)), context.Module.CorLibTypes.String.TypeDefOrRef);
                    caller.Body.Instructions.Insert(++insert, OpCodes.Callvirt.ToInstruction(toChars));
                    caller.Body.Instructions.Insert(++insert, OpCodes.Newobj.ToInstruction(constructor));
                    batch.RecordChange(context, new(Name, "decode-native-key-string", caller.FullName,
                        $"Recovered v2 string using original caller signature '{signature}', signed environment and reviewed native codec; clean runtime-check verdict selected."));
                    count++;
                    changedCallers.Add(caller);
                }
            }
        }
        if (runtimes.Length == 0) { unresolved++; diagnostics.Add("No supported Dotfuscator v2 decoder/bridge graph could be established."); }
        foreach (var caller in changedCallers)
        {
            caller.Body.SimplifyBranches();
            caller.Body.OptimizeBranches();
        }
        if (!AssemblyVerifier.Verify(context.Module).Passed)
            return (PassStatus.Partial, 0, ["Dotfuscator v2 rewrites failed verification and were rolled back; emission withheld."]);
        batch.Commit();
        if (unresolved == 0)
            foreach (var runtime in retired)
            {
                // Keep the bridge intact for its whole-type proof. Public bridge
                // entry points are not ordinary dead private application helpers.
                RecoveryOrphans.Declare(context, runtime.Methods.Where(method => method.DeclaringType != runtime.NativeType)
                    .Select(method => context.Module.ResolveToken(method.MDToken)).OfType<MethodDef>());
                RetiredDotfuscatorNativeRuntime.Remember(context, runtime);
            }
        context.TryGetFact<int>("strings.constantSites", out var earlier);
        context.SetFact("strings.constantSites", earlier + count);
        diagnostics.Insert(0, $"Recovered {count} native-key v2 string site(s); {unresolved} unresolved runtime/site group(s). No sample code or supplied native library was executed.");
        if (unresolved > 0) diagnostics.Add("Dotfuscator v2 native-key recovery is incomplete; emission withheld to preserve caller name/signature bindings.");
        return (unresolved == 0 ? PassStatus.Success : count == 0 ? PassStatus.Unsupported : PassStatus.Partial, count, diagnostics);
    }

    private static bool Companions(ArtifactContext context, DotfuscatorV2Shape.Runtime runtime, out string detail)
    {
        var directory = Path.GetDirectoryName(context.InputPath)!;
        var environment = Path.Combine(directory, runtime.EnvironmentFile);
        detail = "Dotfuscator v2 requires its signed environment file and reviewed native companion beside the input.";
        try
        {
            if (!File.Exists(environment) || new FileInfo(environment).Length != 20480) return false;
            if (!DotfuscatorV2Companions.TryValidateNative(directory, context.Module, out var nativeDetail)) { detail = nativeDetail; return false; }
            var bytes = File.ReadAllBytes(environment);
            if (!DotfuscatorV2Codec.ValidateEnvironment(bytes, runtime.Seed, out detail)) return false;
            detail = $"Validated signed {runtime.EnvironmentFile}, SHA-256 {Convert.ToHexStringLower(SHA256.HashData(bytes))}; {nativeDetail}; decoder graph {runtime.Fingerprint}.";
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        { detail = $"Dotfuscator v2 companion validation failed: {exception.Message}"; return false; }
    }
}
