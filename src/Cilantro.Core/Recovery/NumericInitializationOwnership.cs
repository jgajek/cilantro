using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Proves private numeric construction has no inputs beyond fixed resources and closed shared tables.</summary>
internal static class NumericInitializationOwnership
{
    internal static bool TryProve(ArtifactContext context, MethodDef initializer, out TypeDef? shared, out string reason,
        out IReadOnlyList<RecoveredResourceOrigin> resources)
    {
        shared = null;
        resources = [];
        if (context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions).Any(i => i.Operand is IMethod c &&
                c.DeclaringType.FullName == "System.Security.Cryptography.CryptoConfig"))
        { reason = "application crypto-provider configuration is not closed"; return false; }
        var owner = initializer.DeclaringType;
        var pending = new Stack<MethodDef>(); pending.Push(initializer);
        var seen = new HashSet<MethodDef>();
        var sharedOwners = new Dictionary<TypeDef, ClosedInitializerValues.Result>();
        var bindingTargets = owner.Fields.Select(f => (Field: f, Target: ReadonlyDelegateBinding.Target(f)))
            .Where(p => p.Target is not null).ToDictionary(p => p.Field, p => p.Target!);
        var readFailure = "";
        if (!Read(out var first, out var firstSteps, out var firstFrames) ||
            !Read(out var second, out var secondSteps, out var secondFrames))
        { reason = "independent cold construction did not complete: " + readFailure; return false; }
        if (!firstFrames.SetEquals(secondFrames) || firstSteps != secondSteps || !first!.Agrees(second!) || first.ObservationsTruncated)
        { reason = "independent cold construction disagreed"; return false; }
        while (pending.TryPop(out var method))
        {
            // Only executed bodies can introduce inputs into this fixed construction.
            // All their static inputs are checked below; unmodeled external operations
            // refuse during execution. Thus a dead crypto/format arm is not a license
            // to execute its factory, nor an input to the path that bypasses it.
            if (!firstFrames.Contains(method)) continue;
            if (!seen.Add(method)) continue;
            reason = $"unreadable or open construction method {method.FullName}";
            if (seen.Count > 128 || !method.HasBody || method.HasGenericParameters || method.DeclaringType.HasGenericParameters ||
                method.IsPinvokeImpl || method.Body.Variables.Count != 0 && !method.Body.InitLocals) return false;
            foreach (var instruction in method.Body.Instructions)
            {
                reason = $"unclosed construction at {method.FullName} IL_{instruction.Offset:X4} ({instruction.OpCode})";
                if (instruction.OpCode.Code is Code.Calli or Code.Ldsflda or Code.Ldtoken or Code.Ldvirtftn or
                    Code.Localloc or Code.Cpblk or Code.Initblk or Code.Jmp) return false;
                if (instruction.OpCode.Code == Code.Ldftn)
                {
                    if (instruction.Operand is not IMethod function || function.ResolveMethodDef() is not { } target ||
                        !bindingTargets.ContainsValue(target) || method != initializer) return false;
                    pending.Push(target);
                    continue;
                }
                if (instruction.OpCode.Code is Code.Ldsfld or Code.Stsfld or Code.Ldfld or Code.Stfld or Code.Ldflda &&
                    instruction.Operand is IField fieldReference)
                {
                    var field = fieldReference.ResolveFieldDef();
                    if (field is null || field.Module != context.Module) return false;
                    if (field.IsStatic && field.DeclaringType != owner)
                    {
                        if (instruction.OpCode.Code != Code.Ldsfld || !Shared(field.DeclaringType) ||
                            !sharedOwners[field.DeclaringType].Fields.Contains(field)) return false;
                    }
                    if (field.IsStatic && field.DeclaringType == owner && instruction.OpCode.Code is not (Code.Ldsfld or Code.Stsfld)) return false;
                }
                if (instruction.OpCode.Code is not (Code.Call or Code.Callvirt or Code.Newobj)) continue;
                if (instruction.Operand is not IMethod called || called is MethodSpec) return false;
                if (called.ResolveMethodDef() is { } callee && callee.Module == context.Module)
                {
                    if (callee.IsRuntime)
                    {
                        if (instruction.OpCode.Code == Code.Newobj && callee.IsInstanceConstructor &&
                            bindingTargets.Keys.Any(f => f.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() == callee.DeclaringType)) continue;
                        var receiver = ReadonlyDelegateBinding.Receiver(method, instruction);
                        if (receiver is null || !bindingTargets.TryGetValue(receiver, out var target)) return false;
                        pending.Push(target);
                        continue;
                    }
                    if (!callee.HasBody) return false;
                    if (instruction.OpCode.Code == Code.Callvirt && callee.IsVirtual ||
                        instruction.OpCode.Code == Code.Newobj && firstFrames.Contains(callee) &&
                        !HasClosedLifetime(callee.DeclaringType)) return false;
                    pending.Push(callee);
                    if (callee.DeclaringType != owner && callee.DeclaringType.FindStaticConstructor() is { } cctor)
                    {
                        if (!Shared(callee.DeclaringType)) pending.Push(cctor);
                    }
                }
                // External operations are checked at execution time below. Closed
                // inputs fix the path; an unsupported operation on that path refuses
                // the proof rather than being guessed or stepped over.
            }
        }
        reason = "multiple shared initialization orders are not established";
        if (sharedOwners.Count > 1) return false;
        var allowedFields = owner.Fields.Where(f => f.IsStatic).Concat(sharedOwners.Values.SelectMany(p => p.Fields))
            .Select(f => f.FullName).ToHashSet(StringComparer.Ordinal);
        reason = "cold construction effects or inputs are not closed";
        var effects = first.EffectsOf(initializer.MDToken.Raw);
        if (!effects.AllInvocationsCompleted || effects.WroteMappedImage || effects.WroteScratchRegion || effects.Registrations.Count != 0 ||
            effects.StaticFieldsWritten.Any(f => !allowedFields.Contains(f))) return false;
        if (sharedOwners.Keys.Any(t => t.FindStaticConstructor() is not { } init ||
            !first.EffectsOf(init.MDToken.Raw).AllInvocationsCompleted)) return false;
        var origins = new HashSet<RecoveredResourceOrigin>();
        foreach (var observation in first.Observations)
        {
            if (observation.Kind == LoaderObservationKind.StrongNameProbe) continue;
            if (observation.Kind != LoaderObservationKind.ManagedResourceRead) return false;
            var read = JsonSerializer.Deserialize<ManagedResourceRead>(observation.Detail);
            if (read is null || context.Module.Resources.Count(r => r.Name.String == read.Name) != 1 ||
                context.Module.Resources.OfType<EmbeddedResource>().Count(r => new RecoveredResourceOrigin(read.Name, read.Sha256).Matches(r)) != 1)
                return false;
            origins.Add(new RecoveredResourceOrigin(read.Name, read.Sha256));
        }
        shared = sharedOwners.Keys.SingleOrDefault();
        resources = origins.ToArray();
        reason = "closed private construction and shared initialization";
        return true;

        bool Shared(TypeDef type)
        {
            if (sharedOwners.ContainsKey(type)) return true;
            var proof = ClosedInitializerValues.Check(type);
            if (!proof.Passed) return false;
            sharedOwners.Add(type, proof); return true;
        }

        bool Read(out LoaderInterpretationEvidence? evidence, out int steps, out HashSet<MethodDef> entered)
        {
            evidence = null; steps = 0;
            var frames = new HashSet<MethodDef>(); entered = frames;
            var machine = new StaticMachine(BootstrapMachine.Limits(2_000_000),
                new ConstructionIntrinsics(context.Module), modelTypeInitialization: true);
            machine.FrameEntered = (method, _) => frames.Add(method);
            // No supplied declarations, neutralized-method shortcuts, trusted external
            // bodies, file image or ambient host state participate in this proof.
            machine.State.RegisterRunEnvironment(new RunEnvironment(new HostEnvironment(HostProfile.Empty)));
            machine.State.RegisterModuleMetadata(context.Module);
            machine.State.RegisterAssemblyIdentity(context.Module.Assembly?.Name ?? context.Module.Name,
                context.Module.Assembly?.PublicKeyToken?.Data ?? []);
            machine.State.RegisterPointerSize(context.OriginalImage.IsPe32Plus ? 8 : 4);
            foreach (var resource in context.Module.Resources.OfType<EmbeddedResource>())
                machine.State.RegisterResource(resource.Name, resource.CreateReader().ToArray());
            var result = machine.Execute(initializer); steps = result.Steps;
            if (!result.Succeeded || machine.State.CapturedAssemblyLoads.Count != 0)
            { readFailure = result.Diagnostic ?? result.Status.ToString(); return false; }
            evidence = machine.State.LoaderEvidence; return true;
        }
    }

    private static bool HasClosedLifetime(TypeDef type)
    {
        var seen = new HashSet<TypeDef>();
        var module = type.Module;
        while (seen.Add(type))
        {
            if (type.Methods.Any(m => m.Name == "Finalize" || m.HasOverrides)) return false;
            if (type.BaseType is TypeRef parent && parent.FullName == "System.Object" &&
                parent.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName) return true;
            if (type.BaseType?.ResolveTypeDef() is not { } next || next.Module != module) return false;
            type = next;
        }
        return false;
    }

    private sealed class ConstructionIntrinsics(ModuleDef module) : IStaticIntrinsicRegistry
    {
        private readonly StaticIntrinsicRegistry defaults = StaticIntrinsicRegistry.CreateDefault();
        public bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic)
        {
            if (FrameworkCall(module, method) && defaults.TryResolve(method, out intrinsic)) return true;
            intrinsic = Refused.Instance; return true;
        }
    }

    private sealed class Refused : IStaticIntrinsic
    {
        internal static readonly Refused Instance = new();
        public bool Matches(IMethod method) => true;
        public IntrinsicResult Invoke(IntrinsicContext context, IMethod method, IReadOnlyList<StaticValue> arguments) =>
            IntrinsicResult.Unknown("Numeric initialization proof refuses " + method.FullName);
    }

    private static bool FrameworkCall(ModuleDef module, IMethod method)
    {
        if (method.DeclaringType is not TypeRef type || type.DefinitionAssembly?.FullName != module.CorLibTypes.AssemblyRef.FullName) return false;
        // Receivers can only originate in this private construction, fixed module
        // metadata, or separately proven immutable graphs. File/host/native APIs,
        // registration, code loading and arbitrary reflection are excluded.
        return method.FullName is
            "System.Reflection.Assembly System.Reflection.Assembly::GetExecutingAssembly()" or
            "System.Reflection.AssemblyName System.Reflection.Assembly::GetName()" or
            "System.Byte[] System.Reflection.AssemblyName::GetPublicKey()" or
            "System.Security.Cryptography.Aes System.Security.Cryptography.Aes::Create()" or
            "System.IO.Stream System.Reflection.Assembly::GetManifestResourceStream(System.String)" or
            "System.Void System.Object::.ctor()" or "System.Void System.InvalidOperationException::.ctor()" or
            "System.Void System.IDisposable::Dispose()" or
            "System.Int32 System.Math::Min(System.Int32,System.Int32)" or
            "System.Void System.Array::Copy(System.Array,System.Int32,System.Array,System.Int32,System.Int32)" or
            "System.Void System.Buffer::BlockCopy(System.Array,System.Int32,System.Array,System.Int32,System.Int32)" ||
            type.FullName == "System.String" && method.Name.String is "ToCharArray" or ".ctor" ||
            type.FullName == "System.IO.BinaryReader" && method.Name.String is ".ctor" or "ReadByte" or "ReadUInt16" or "ReadInt32" or
                "ReadUInt32" or "ReadInt64" or "ReadUInt64" or "ReadSingle" or "ReadDouble" or "Read" or "ReadBytes" or "ReadString" or "get_BaseStream" or "Dispose" ||
            type.FullName == "System.IO.MemoryStream" && method.Name.String is ".ctor" or "ToArray" ||
            type.FullName == "System.IO.Stream" && method.Name.String is "Read" or "ReadByte" or "Write" or "get_Length" or "get_Position" or "set_Position" ||
            type.FullName == "System.Security.Cryptography.SymmetricAlgorithm" && method.Name.String is "set_IV" or "set_Key" or "CreateDecryptor" ||
            type.FullName == "System.Security.Cryptography.CryptoStream" && method.Name == ".ctor";
    }
}
