using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Whole-type retirement of the reviewed exception emitted for a rejected check response.</summary>
internal sealed record RetiredDotfuscatorResponseRuntime(TypeDef Exception, MethodDef Failure, MethodDef Empty,
    string Shape, string TypeShape, string Message, string Display)
{
    internal sealed record Site(MethodDef Caller, MethodDef Failure, MethodDef Empty);
    private const string Fact = "dotfuscator.checks.retiredResponses";
    private const string VerifiedFact = "dotfuscator.checks.verifiedResponseRetirement";
    private const string MethodsFact = "dotfuscator.checks.removableResponses";

    internal static IReadOnlyCollection<MethodDef> Methods(ArtifactContext context) =>
        context.TryGetFact<HashSet<MethodDef>>(MethodsFact, out var methods) && methods is not null ? methods : [];

    internal static void Remember(ArtifactContext context, List<Site> sites)
    {
        if (sites.Count == 0) return;
        using var original = ModuleDefMD.Load(context.OriginalBytes);
        var proofs = new List<RetiredDotfuscatorResponseRuntime>();
        foreach (var site in sites.Distinct())
        {
            if (original.ResolveToken(site.Failure.MDToken) is not MethodDef failure ||
                original.ResolveToken(site.Empty.MDToken) is not MethodDef empty ||
                original.ResolveToken(site.Caller.MDToken) is not MethodDef caller ||
                failure.DeclaringType != caller.DeclaringType || empty.DeclaringType != caller.DeclaringType ||
                !ReadResponse(failure, empty, out var type) ||
                !ReadException(type!, out var shape, out var typeShape, out var message, out var display) || !Reviewed(shape) ||
                context.Module.ResolveToken(type!.MDToken) is not TypeDef current) continue;
            proofs.Add(new(current, site.Failure, site.Empty, shape, typeShape, message, display));
            RecoveryOrphans.Declare(context, [site.Failure, site.Empty]);
        }
        context.SetFact<IReadOnlyList<RetiredDotfuscatorResponseRuntime>>(Fact, proofs);
    }

    internal static IEnumerable<TypeDef> Unused(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<RetiredDotfuscatorResponseRuntime>>(Fact, out var proofs) || proofs is null || proofs.Count == 0) return [];
        var result = new HashSet<TypeDef>();
        var methods = new HashSet<MethodDef>();
        context.SetFact(MethodsFact, methods);
        var present = context.Module.GetTypes().ToHashSet();
        context.TryGetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", out var removed);
        if (!context.TryGetFact<HashSet<(uint, uint)>>(VerifiedFact, out var verified) || verified is null)
            context.SetFact(VerifiedFact, verified = []);
        var forms = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions).Where(instruction => instruction.OpCode.OperandType == OperandType.ShortInlineBrTarget)
            .Select(instruction => (Instruction: instruction, instruction.OpCode)).ToArray();
        try
        {
            BranchForms.Reach(context.Module);
            using var bytes = new MemoryStream(); context.Module.Write(bytes);
            using var copy = ModuleDefMD.Load(bytes.ToArray());
            foreach (var proof in proofs)
            {
                if (!present.Contains(proof.Exception)) continue;
                var type = copy.GetTypes().SingleOrDefault(type => type.FullName == proof.Exception.FullName);
                var failure = CopyMethod(copy, proof.Failure);
                var empty = CopyMethod(copy, proof.Empty);
                var key = (proof.Failure.MDToken.Raw, proof.Empty.MDToken.Raw);
                // Subsequent cleanup stages can revisit a type after ordinary
                // method cleanup retired its verified private response methods.
                // Only recorded cleanup removals may stand in for those bodies.
                var failureValid = failure is not null ? ReadFailure(failure, out var connected) && connected == type :
                    verified.Contains(key) && removed?.Contains(key.Item1) == true;
                var emptyValid = empty is not null ? ReadEmpty(empty) : verified.Contains(key) && removed?.Contains(key.Item2) == true;
                var typeShape = ""; var message = ""; var display = "";
                var typeRead = type is not null && ReadExceptionCore(type, false, out _, out typeShape, out message, out display);
                var typeValid = typeRead && message == proof.Message && display == proof.Display &&
                    (typeShape == proof.TypeShape || verified.Contains(key) && MatchesRecordedProjection(context, proof, removed, typeShape));
                if (!failureValid || !emptyValid || !typeValid)
                {
                    context.AddEvidence(new("dotfuscator-response-retained", $"Response/type retirement withheld: rejected response valid={failureValid}, clean response valid={emptyValid}, complete exception valid={typeValid}; type read={typeRead}, current shape={typeShape}, expected shape={proof.TypeShape}, literal data intact={message == proof.Message && display == proof.Display}."));
                    continue;
                }
                if (context.Module.GetTypes().Where(type => type != proof.Exception).SelectMany(type => type.Methods).Where(method => method.HasBody)
                    .SelectMany(method => method.Body.Instructions).Any(instruction => instruction.Operand is string text &&
                        (text == proof.Exception.FullName || text == proof.Exception.ReflectionFullName ||
                            text.StartsWith(proof.Exception.ReflectionFullName + ",", StringComparison.Ordinal)))) continue;
                result.Add(proof.Exception);
                verified.Add(key);
                var names = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
                    .SelectMany(method => method.Body.Instructions).Select(instruction => instruction.Operand).OfType<string>().ToHashSet(StringComparer.Ordinal);
                foreach (var method in new[] { proof.Failure, proof.Empty })
                    if (method.DeclaringType is not null && !names.Contains(method.Name.String) && !names.Contains(method.FullName)) methods.Add(method);
            }
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or InvalidOperationException or dnlib.DotNet.Writer.ModuleWriterException)
        { methods.Clear(); return []; }
        finally { foreach (var form in forms) form.Instruction.OpCode = form.OpCode; }
        return result;
    }

    private static MethodDef? CopyMethod(ModuleDef copy, MethodDef method) => method.DeclaringType is { } owner ? copy.GetTypes()
        .SingleOrDefault(type => type.FullName == owner.FullName)?.Methods.SingleOrDefault(candidate => candidate.FullName == method.FullName) : null;

    private static bool MatchesRecordedProjection(ArtifactContext context, RetiredDotfuscatorResponseRuntime proof,
        IReadOnlySet<uint>? removed, string currentShape)
    {
        if (removed is null) return false;
        using var original = ModuleDefMD.Load(context.OriginalBytes);
        var type = original.GetTypes().SingleOrDefault(type => type.FullName == proof.Exception.FullName);
        if (type is null || !ReadException(type, out var sourceShape, out var sourceTypeShape, out _, out _) ||
            sourceShape != proof.Shape || sourceTypeShape != proof.TypeShape)
        { context.AddEvidence(new("dotfuscator-response-projection", "Original exception proof did not revalidate.")); return false; }
        var present = proof.Exception.Methods.Select(method => method.MDToken.Raw).ToHashSet();
        var missing = type.Methods.Where(method => !present.Contains(method.MDToken.Raw)).ToArray();
        if (missing.Length == 0 || missing.Any(method => !removed.Contains(method.MDToken.Raw)))
        { context.AddEvidence(new("dotfuscator-response-projection", $"Projection missing rows: {string.Join(',', missing.Select(method => method.MDToken.Raw))}; recorded: {string.Join(',', removed)}; surviving: {string.Join(',', present)}.")); return false; }
        // Other recovery passes can retire the string decoder on this same type
        // before a newly dead response releases the exception. Project the exact
        // original declaration only through recorded method removals. Remaining
        // bodies, metadata, fields, signatures and literal data still match whole.
        foreach (var method in missing) type.Methods.Remove(method);
        var read = ReadExceptionCore(type, false, out _, out var projected, out _, out _);
        context.AddEvidence(new("dotfuscator-response-projection", $"Projected exception read={read}, shape={projected}; current={currentShape}."));
        return read && projected == currentShape;
    }

    private static bool ReadResponse(MethodDef failure, MethodDef empty, out TypeDef? exception)
    {
        exception = null;
        return ReadEmpty(empty) && ReadFailure(failure, out exception);
    }

    private static bool ReadEmpty(MethodDef empty) => ResponseMethod(empty) &&
        GeneratedRuntimeBodyNormalization.TryNormalizeStackSafe(empty, true, out _) &&
        empty.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).Select(instruction => instruction.OpCode.Code).SequenceEqual([Code.Ret]);

    private static bool ReadFailure(MethodDef failure, out TypeDef? exception)
    {
        exception = null;
        if (!ResponseMethod(failure) || !GeneratedRuntimeBodyNormalization.TryNormalizeStackSafe(failure, true, out _)) return false;
        var rejected = failure.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        if (rejected.Length != 5 ||
            rejected[0].OpCode.Code != Code.Newobj || rejected[0].Operand is not IMethod constructor ||
            constructor.ResolveMethodDef() is not { IsInstanceConstructor: true } target || target.Module != failure.Module ||
            target.MethodSig.Params.Count != 0 || rejected[1].OpCode.Code != Code.Dup ||
            rejected[2].OpCode.Code != Code.Callvirt || rejected[2].Operand is not IMethod hash ||
            hash.FullName != "System.Int32 System.Object::GetHashCode()" || hash.DeclaringType is not TypeRef ||
            hash.DeclaringType.DefinitionAssembly?.FullName != failure.Module.CorLibTypes.AssemblyRef.FullName ||
            rejected[3].OpCode.Code != Code.Pop || rejected[4].OpCode.Code != Code.Throw) return false;
        exception = target.DeclaringType;
        return true;
    }

    private static bool ResponseMethod(MethodDef method) => method.Attributes == (MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig) &&
        method.ImplAttributes == MethodImplAttributes.IL && method.SemanticsAttributes == MethodSemanticsAttributes.None &&
        !method.HasCustomAttributes && !method.HasGenericParameters && !method.HasDeclSecurities && !method.HasOverrides &&
        !method.HasImplMap && method.MethodSig.GenParamCount == 0 && !method.MethodSig.HasThis && method.MethodSig.Params.Count == 0 &&
        method.ReturnType.ElementType == ElementType.Void && method.ParamDefs.Count == 0 && method.HasBody && method.Body.ExceptionHandlers.Count == 0;

    // Called exclusively on private module copies. Preserve marker fields: they
    // may still have application consumers, which the final reference gate checks.
    private static bool ReadException(TypeDef type, out string shape, out string typeShape, out string message, out string display)
        => ReadExceptionCore(type, true, out shape, out typeShape, out message, out display);

    private static bool ReadExceptionCore(TypeDef type, bool ownership, out string shape, out string typeShape, out string message, out string display)
    {
        shape = typeShape = message = display = "";
        if (type.Methods.Count is < 3 or > 12 || type.BaseType is not TypeRef { FullName: "System.Exception" } ||
            type.BaseType.DefinitionAssembly?.FullName != type.Module.CorLibTypes.AssemblyRef.FullName) return false;
        foreach (var method in type.Methods)
            if (!GeneratedRuntimeBodyNormalization.TryNormalizeStackSafe(method, true, out _)) return false;
        var constructors = type.Methods.Where(method => method.IsInstanceConstructor).ToArray();
        var displays = type.Methods.Where(method => method.Name == "ToString").ToArray();
        if (constructors.Length != 1 || displays.Length != 1) return false;
        var messages = constructors[0].Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Ldstr).ToArray();
        var formatted = displays[0].Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Ldstr).ToArray();
        if (messages.Length != 1 || formatted.Length != 1 || messages[0].Operand is not string { Length: > 0 and <= 8192 } text ||
            formatted[0].Operand is not string { Length: <= 16384 } full || !full.EndsWith(": " + text, StringComparison.Ordinal)) return false;
        var name = full[..^(text.Length + 2)];
        if (!name.StartsWith("System.", StringComparison.Ordinal) || !name.EndsWith("Exception", StringComparison.Ordinal)) return false;
        message = text; display = full;
        messages[0].Operand = "$exception-message"; formatted[0].Operand = "$exception-display";
        try
        {
            if (ownership)
            {
                var graph = DotfuscatorRootCheckShape.Read(constructors[0], true);
                if (graph.Types.Count is < 1 or > 2 || graph.Types[0] != type) return false;
                shape = graph.Fingerprint;
            }
            // Original ownership includes the entire native bridge when the
            // decoder lives here. Later retirement checks this complete type,
            // including exact call signatures/scopes, independently of changes
            // to a different declaration's bodies. Native bridge retirement has
            // its own independent whole-type proof.
            typeShape = DotfuscatorRootCheckShape.ReadType(constructors[0]).Fingerprint;
            return (!ownership || shape.Length == 64) && typeShape.Length == 64;
        }
        finally { messages[0].Operand = text; formatted[0].Operand = full; }
    }

    private static bool Reviewed(string shape) => shape is
        "eafb4c5dfa49acb27e87b626e354cec1b02c6fe02fa0ca90ddef741712fcd4ed" or
        "989ae9c3ee23068c84ea11f232b6348c7021e08f9f9523c19f793a0b0aed6c48" or
        "58475d94bf42c3bb5b623d194dd514c0bda705efb5cf0d6d6cdeb026be538a94" or
        "5756dbd6262bdc71877cb35f3883ca902cff33d4c3a3aaf604d68d7b0f6ca3aa" or
        "8817ec5d76f9a046340ef7c685b984d60376f467bf9f5cdeb361939dba7d9c5d" or
        "703ce65015e362775f6483cf6675f1b3fc040614cadfc47f254e86a04dc44970" or
        "9bb12fef0f48b87edf0f4a325e2ade15008cae279bf91abc9b14755df5af651d" or
        "71734b9704e589d7e9ea9f292fd0d95a0bc447684da087a79af4b3f78e09c1d9" or
        "f7205475005ba8dfaff95e894bb2a4c33568d82da148101ff6af4c8e4a2cfa18" or
        "381464c15e1c6206bab2a125bdbdfa0adb8123c34f0cf9da1f8e2f856b950c71" or
        "91e4fde80b1b73ae92ef5bf62b54eb6e1dd76c2927d083ce60d6dda587c33f92" or
        "def4eff272ed1d82393047f10f8ac23dc45f3fd86e586e5492338bf58d59aecb" or
        "bba97d167aba925a5b6485dca4db62095453ebafb673f5a2bb5658618afbebb4" or
        "83943f134a0f433a62d4184eff4938d6bdd1f04aa8d2b7bd28ab769a1448e092";
}
