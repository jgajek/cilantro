using System.Security.Cryptography;
using System.Text;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Retires the complete reviewed resource family after direct framework rebinding.</summary>
internal sealed record RetiredDotfuscatorResourceRuntime(IReadOnlyList<TypeDef> Family, string Fingerprint, string Metadata)
{
    private const string Fact = "dotfuscator.resources.retiredRuntime";
    private const string FamilyFact = "dotfuscator.resources.reviewedFamily";

    internal static bool CanRebind(ArtifactContext context, DotfuscatorResourceShape.Runtime runtime)
    {
        // Validate original and current graphs independently before trusting any
        // replacement. Seed/key text is a data parameter, not a code wildcard.
        using var source = ModuleDefMD.Load(context.OriginalBytes);
        using var current = Copy(context.Module);
        var valid = source.ResolveToken(runtime.Manager.MDToken) is TypeDef original &&
            current.ResolveToken(runtime.Manager.MDToken) is TypeDef manager &&
            Describe(original, true, out var graph, out var metadata, out _) && Reviewed(graph, metadata) &&
            Describe(manager, true, out var now, out var currentMetadata, out _) && graph == now && metadata == currentMetadata;
        if (valid)
        {
            var root = (TypeDef)context.Module.ResolveToken(runtime.Manager.MDToken);
            context.SetFact<IReadOnlyList<TypeDef>>(FamilyFact, GeneratedRuntimeShape.Read(root.Methods[0]).Types.ToArray());
        }
        return valid;
    }

    internal static int RebindAndRemember(ArtifactContext context, TypeDef manager)
    {
        if (!context.TryGetFact<IReadOnlyList<TypeDef>>(FamilyFact, out var reviewed) || reviewed is null) return 0;
        var family = reviewed.ToHashSet();
        var survivors = context.Module.GetTypes().Where(type => !family.Contains(type)).ToArray();
        if (survivors.SelectMany(type => type.Methods).Where(method => method.HasBody).SelectMany(method => method.Body.Instructions)
            .Any(instruction => instruction.Operand is string text && family.Any(type => text == type.FullName ||
                text == type.ReflectionFullName || text.StartsWith(type.ReflectionFullName + ",", StringComparison.Ordinal)))) return 0;
        var changes = new List<(MethodDef Owner, Instruction Instruction, object Before)>();
        foreach (var method in survivors.SelectMany(type => type.Methods).Where(method => method.HasBody))
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is not IMethod called || called.DeclaringType.ResolveTypeDef() != manager) continue;
                var target = called.ResolveMethodDef();
                var inheritedRelease = called.Name == "ReleaseAllResources" && called.MethodSig.HasThis && called.MethodSig.GenParamCount == 0 && called.MethodSig.Params.Count == 0 &&
                    called.MethodSig.RetType.ElementType == ElementType.Void && instruction.OpCode.Code == Code.Callvirt;
                if (!inheritedRelease && (target is null || target.DeclaringType != manager || !target.IsPublic ||
                    !(target.IsInstanceConstructor && instruction.OpCode.Code == Code.Newobj ||
                        target.IsVirtual && instruction.OpCode.Code is Code.Call or Code.Callvirt))) continue;
                changes.Add((method, instruction, called));
                instruction.Operand = new MemberRefUser(context.Module, called.Name, called.MethodSig, manager.BaseType);
            }
        if (RuntimeCleanupPass.CollectReferencedCandidates(context.Module, survivors, family).Count != 0 ||
            changes.Select(change => change.Owner).Distinct().Any(method => !EvaluationStackAnalyzer.Analyze(method).Valid))
        {
            foreach (var change in changes) change.Instruction.Operand = change.Before;
            return 0;
        }
        // The current snapshot contains the exact forwarding bodies emitted by
        // resource recovery. Later cleanup accepts only that complete family.
        using var copy = Copy(context.Module);
        var copiedFamily = reviewed.Select(type => copy.GetTypes().Single(candidate => candidate.FullName == type.FullName)).ToArray();
        if (!Describe(copiedFamily[0], false, out var fingerprint, out var metadata, out _, copiedFamily))
        {
            foreach (var change in changes) change.Instruction.Operand = change.Before;
            return 0;
        }
        context.SetFact(Fact, new RetiredDotfuscatorResourceRuntime(reviewed, fingerprint, metadata));
        if (changes.Count != 0) context.AddChange(new("dotfuscator-resources", "rebind-resource-manager", manager.FullName,
            $"Rebound {changes.Count} reviewed constructor/virtual calls directly to System.Resources.ResourceManager."));
        return changes.Count;
    }

    internal static IEnumerable<TypeDef> Unused(ArtifactContext context)
    {
        if (!context.TryGetFact<RetiredDotfuscatorResourceRuntime>(Fact, out var proof) || proof is null ||
            proof.Family.Any(type => !context.Module.GetTypes().Contains(type))) return [];
        using var copy = Copy(context.Module);
        var copiedFamily = proof.Family.Select(type => copy.GetTypes().Single(candidate => candidate.FullName == type.FullName)).ToArray();
        if (!Describe(copiedFamily[0], false, out var fingerprint, out var metadata, out var family, copiedFamily) ||
            fingerprint != proof.Fingerprint || metadata != proof.Metadata)
        {
            context.AddEvidence(new("dotfuscator-resource-runtime-retained", "Resource runtime changed after direct framework rebinding; whole-family retirement withheld."));
            return [];
        }
        var names = family.Select(type => type.FullName).ToHashSet(StringComparer.Ordinal);
        var candidates = context.Module.GetTypes().Where(type => names.Contains(type.FullName)).ToArray();
        if (context.Module.GetTypes().Where(type => !names.Contains(type.FullName)).SelectMany(type => type.Methods)
            .Where(method => method.HasBody).SelectMany(method => method.Body.Instructions)
            .Any(instruction => instruction.Operand is string text && candidates.Any(type => text == type.FullName ||
                text == type.ReflectionFullName || text.StartsWith(type.ReflectionFullName + ",", StringComparison.Ordinal)))) return [];
        return candidates;
    }

    // Normalize only an independent metadata copy, never the output bodies.
    private static ModuleDefMD Copy(ModuleDef module)
    {
        // Earlier control-flow passes may expand unrelated application bodies.
        // The proof must be serializable without retaining temporary branch-form
        // changes in those bodies, including when the writer refuses the input.
        var forms = module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions).Where(instruction => instruction.OpCode.OperandType == OperandType.ShortInlineBrTarget)
            .Select(instruction => (Instruction: instruction, instruction.OpCode)).ToArray();
        try
        {
            BranchForms.Reach(module);
            using var bytes = new MemoryStream(); module.Write(bytes);
            return ModuleDefMD.Load(bytes.ToArray());
        }
        finally
        {
            foreach (var form in forms) form.Instruction.OpCode = form.OpCode;
        }
    }

    // Normalize only an independent metadata copy, never the output bodies.
    private static bool Describe(TypeDef manager, bool maskParameters, out string fingerprint, out string metadata, out IReadOnlyList<TypeDef> types,
        IReadOnlyList<TypeDef>? completeFamily = null)
    {
        fingerprint = metadata = "";
        types = [];
        try
        {
            var graph = GeneratedRuntimeShape.Read(manager.Methods[0]);
            types = completeFamily ?? graph.Types;
            if (types.Count != 2 || types.Any(type => type.HasGenericParameters || type.HasNestedTypes || type.HasProperties ||
                    type.HasEvents || type.HasDeclSecurities || type.Fields.Any(field => field.HasConstant) ||
                    type.Methods.Any(method => method.HasGenericParameters || method.ParamDefs.Any(parameter => parameter.HasConstant)))) return false;
            string[] parameters = maskParameters ? manager.Methods.First(method => method.IsInstanceConstructor).Body.Instructions
                .Where(instruction => instruction.Operand is string).Select(instruction => (string)instruction.Operand).ToArray() : [];
            if (maskParameters && parameters.Length != 2) return false;
            metadata = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", types.Select(GeneratedRuntimeMetadata.Describe)))));
            foreach (var method in types.SelectMany(type => type.Methods))
            {
                if (maskParameters)
                    foreach (var instruction in method.Body.Instructions)
                        if (instruction.Operand is string text)
                        {
                            if (text == parameters[0]) instruction.Operand = "$seed";
                            else if (text == parameters[1]) instruction.Operand = "$keys";
                        }
                if (!GeneratedRuntimeBodyNormalization.TryNormalize(method, true, out _)) return false;
            }
            fingerprint = maskParameters ? GeneratedRuntimeShape.ReadCanonical(manager.Methods[0]).Fingerprint :
                Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n",
                    types.Select(type => GeneratedRuntimeShape.ReadCanonical(type.Methods[0]).Fingerprint)))));
            return true;
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or InvalidOperationException or dnlib.DotNet.Writer.ModuleWriterException)
        { return false; }
    }

    private static bool Reviewed(string fingerprint, string metadata) => (fingerprint, metadata) is
        ("b22a23a7edfb02b9fc4300c1e3a6ca38a171f253d0707cb44d368a3e80a3f92b", "5a627a113c3a85a4f57c7f23332e3ed0ceea9886cd94e8f9920dc5f57d7ab6fb") or
        ("f5307c35a3edb52d1b568f91b03c4dae5aaabb7bac2f8867ce4320f19f7d79b7", "b1ba0459e749df8fcb421f486d3021c5cc930432f0e35296a863e3eb118b91bf") or
        ("d18a63617489a4c9718ebfabd3efd9c936de511c86e0144256d8c6ba662db8e9", "893b6c5ae1fb0211b804763a3328725463b4aa92e1ec03d014ecaa48ba978b2d");
}
