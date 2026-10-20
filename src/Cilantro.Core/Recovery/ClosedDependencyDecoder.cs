using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Evaluates a fixed decoder input while checking observable effects and shared initialization.</summary>
internal static class ClosedDependencyDecoder
{
    internal sealed record Result(byte[] Bytes, IReadOnlyList<TypeDef> Initializers, IReadOnlySet<MethodDef> Methods, int Steps);
    private sealed record Trial(byte[] Bytes, LoaderInterpretationEvidence Evidence, HashSet<MethodDef> Methods, List<TypeDef> Initializers, int Steps);

    internal static bool TryRead(ArtifactContext context, MethodDef decoder, byte[] input, out Result? result, out string reason)
    {
        result = null;
        reason = "The decoder or crypto-provider configuration is not closed.";
        if (!decoder.IsStatic || !decoder.HasBody || decoder.HasGenericParameters || decoder.DeclaringType.HasGenericParameters ||
            decoder.MethodSig.Params.Count != 1 || input.Length > 16 * 1024 * 1024 ||
            context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).SelectMany(m => m.Body.Instructions)
                .Any(i => i.Operand is IMethod called && called.DeclaringType.FullName == "System.Security.Cryptography.CryptoConfig")) return false;
        var failure = "";
        if (!Read(out var first)) { reason = failure; return false; }
        var shared = new Dictionary<TypeDef, ClosedInitializerValues.Result>();
        var unwritten = UnwrittenFields.Prove(context.Module);
        foreach (var method in first!.Methods)
        {
            reason = "Unsupported decoder body " + method.FullName;
            if (!method.HasBody || method.IsPinvokeImpl || method.HasGenericParameters || method.DeclaringType.HasGenericParameters ||
                method.Body.Variables.Count != 0 && !method.Body.InitLocals || first.Methods.Count > 256) return false;
            foreach (var instruction in method.Body.Instructions)
            {
                reason = $"Open decoder input or effect at {method.FullName} IL_{instruction.Offset:X4} ({instruction.OpCode}).";
                if (instruction.OpCode.Code is Code.Calli or Code.Ldsflda or Code.Ldftn or Code.Ldvirtftn or Code.Localloc or Code.Cpblk or Code.Initblk or Code.Jmp) return false;
                if (instruction.OpCode.Code == Code.Ldtoken)
                {
                    var following = method.Body.Instructions.Skip(method.Body.Instructions.IndexOf(instruction) + 1).FirstOrDefault(i => i.OpCode.Code != Code.Nop);
                    if (instruction.Operand is not ITypeDefOrRef type || type.ResolveTypeDef() is not { } owner || owner.Module != context.Module ||
                        following?.OpCode.Code != Code.Call || following.Operand is not IMethod call ||
                        call.FullName != "System.Void System.Runtime.CompilerServices.RuntimeHelpers::RunClassConstructor(System.RuntimeTypeHandle)" ||
                        !Framework(call, context.Module) || !Shared(owner)) return false;
                }
                if (instruction.OpCode.Code is Code.Ldsfld or Code.Stsfld or Code.Ldfld or Code.Stfld or Code.Ldflda && instruction.Operand is IField reference)
                {
                    var field = reference.ResolveFieldDef();
                    if (field is null || field.Module != context.Module) return false;
                    if (field.IsStatic)
                    {
                        if (instruction.OpCode.Code == Code.Ldsfld && unwritten.Holds(field)) continue;
                        if (!Shared(field.DeclaringType) || !shared[field.DeclaringType].Fields.Contains(field) ||
                            instruction.OpCode.Code == Code.Stsfld && method != field.DeclaringType.FindStaticConstructor()) return false;
                    }
                }
                if (instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj && instruction.Operand is IMethod called)
                {
                    if (called is MethodSpec) return false;
                    if (called.ResolveMethodDef() is { } target && target.Module == context.Module && first.Methods.Contains(target))
                    {
                        if (instruction.OpCode.Code == Code.Callvirt && target.IsVirtual ||
                            instruction.OpCode.Code == Code.Newobj && !ClosedLifetime(target.DeclaringType)) return false;
                    }
                }
            }
        }
        var initializers = new List<TypeDef>();
        foreach (var type in first.Initializers)
        {
            var initializer = type.FindStaticConstructor()!;
            if (EmptyInitializer(initializer)) continue;
            reason = "Shared initialization is not closed for " + type.FullName;
            if (!Shared(type) || MayReenter(initializer, decoder)) return false;
            initializers.Add(type);
        }
        reason = "Decoder effects are not limited to preserved initialization.";
        var effects = first.Evidence.EffectsOf(decoder.MDToken.Raw);
        var writes = shared.Values.SelectMany(p => p.Fields).Select(f => f.FullName).ToHashSet(StringComparer.Ordinal);
        if (first.Evidence.Effects.ContainsKey(decoder.MDToken.Raw) && !effects.AllInvocationsCompleted ||
            effects.WroteMappedImage || effects.WroteScratchRegion || effects.Registrations.Count != 0 ||
            effects.StaticFieldsWritten.Any(f => !writes.Contains(f)) || first.Evidence.ObservationsTruncated ||
            first.Evidence.Observations.Any(o => o.Kind != LoaderObservationKind.StrongNameProbe)) return false;
        if (!Read(out var second)) { reason = failure; return false; }
        if (!first.Bytes.AsSpan().SequenceEqual(second!.Bytes) || first.Steps != second.Steps ||
            !first.Methods.SetEquals(second.Methods) || !first.Initializers.SequenceEqual(second.Initializers) || !first.Evidence.Agrees(second.Evidence))
        { reason = "Independent strict decoder executions disagreed."; return false; }
        result = new(first.Bytes, initializers, first.Methods, first.Steps);
        reason = "Fixed-input decoding leaves its input bytes unchanged; only closed shared initialization must be preserved.";
        return true;

        bool Shared(TypeDef type)
        {
            if (shared.ContainsKey(type)) return true;
            var proof = ClosedInitializerValues.Check(type);
            if (!proof.Passed) return false;
            shared.Add(type, proof); return true;
        }

        bool Read(out Trial? trial)
        {
            trial = null;
            var machine = new StaticMachine(BootstrapMachine.Limits(256_000_000), new DecoderIntrinsics(context.Module), modelTypeInitialization: true);
            var methods = new HashSet<MethodDef>();
            var initialized = new List<TypeDef>();
            machine.FrameEntered = (method, _) =>
            {
                methods.Add(method);
                if (method.IsStaticConstructor && !initialized.Contains(method.DeclaringType)) initialized.Add(method.DeclaringType);
            };
            machine.State.RegisterRunEnvironment(new RunEnvironment(new HostEnvironment(HostProfile.Empty)));
            machine.State.RegisterModuleMetadata(context.Module);
            machine.State.RegisterAssemblyIdentity(context.Module.Assembly?.Name ?? context.Module.Name, context.Module.Assembly?.PublicKeyToken?.Data ?? []);
            machine.State.RegisterPointerSize(context.OriginalImage.IsPe32Plus ? 8 : 4);
            machine.State.RegisterResource("Cilantro.DecoderInput", input);
            if (!machine.State.TryOpenResource("Cilantro.DecoderInput", out var stream) ||
                !machine.State.Heap.TryGetModelValue<StaticValue>(stream, "Buffer", out var inputBuffer))
            { failure = "Could not construct the fixed decoder input."; return false; }
            // Match new MemoryStream(byte[]): its backing array is writable and
            // remains aliased by the caller, even though the stream is fresh.
            machine.State.Heap.TrySetModelValue(stream, "Writable", true);
            var execution = machine.Execute(decoder, [stream]);
            if (!execution.Succeeded || machine.State.RanOutOfBudget || machine.State.CapturedAssemblyLoads.Count != 0)
            { failure = execution.Diagnostic ?? execution.Status.ToString(); return false; }
            var after = new byte[input.Length];
            if (!machine.State.Heap.TryReadBytes(inputBuffer, 0, after) || !input.AsSpan().SequenceEqual(after))
            { failure = "The decoder changes its caller-owned input bytes."; return false; }
            if (!machine.State.Heap.TryGetObjectType(execution.Value, out var type) || type != "System.IO.MemoryStream" ||
                !machine.State.Heap.TryGetModelValue<StaticValue>(execution.Value, "Buffer", out var buffer) ||
                !machine.State.Heap.TryGetModelValue<int>(execution.Value, "Length", out var length) || length is < 0 or > 16 * 1024 * 1024 ||
                !machine.State.Heap.TryGetModelValue<int>(execution.Value, "Origin", out var origin) ||
                !machine.State.Heap.TryGetModelValue<bool>(execution.Value, "Open", out var open) || !open)
            { failure = "The decoder does not return a readable modeled MemoryStream."; return false; }
            var output = new byte[length];
            if (!machine.State.Heap.TryReadBytes(buffer, origin, output))
            { failure = "The decoder result bytes are unavailable."; return false; }
            trial = new(output, machine.State.LoaderEvidence, methods, initialized, execution.Steps); return true;
        }
    }

    private static bool EmptyInitializer(MethodDef method)
    {
        if (!method.HasBody || method.Body.ExceptionHandlers.Count != 0) return false;
        var instructions = method.Body.Instructions;
        var seen = new HashSet<Instruction>();
        var index = 0;
        while (index >= 0 && index < instructions.Count && seen.Add(instructions[index]))
        {
            var instruction = instructions[index];
            if (instruction.OpCode.Code == Code.Ret) return true;
            if (instruction.OpCode.Code == Code.Nop) { index++; continue; }
            if (instruction.OpCode.Code is not (Code.Br or Code.Br_S) || instruction.Operand is not Instruction target) return false;
            index = instructions.IndexOf(target);
        }
        return false;
    }

    private static bool MayReenter(MethodDef initializer, MethodDef decoder)
    {
        var pending = new Stack<MethodDef>(); pending.Push(initializer);
        var seen = new HashSet<MethodDef>();
        while (pending.TryPop(out var method))
        {
            if (method == decoder) return true;
            if (!seen.Add(method)) continue;
            if (seen.Count > 256 || !method.HasBody) return true;
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is IMethod called && called.ResolveMethodDef() is { } target && target.Module == decoder.Module)
                { pending.Push(target); if (target.DeclaringType.FindStaticConstructor() is { } ctor) pending.Push(ctor); }
                if (instruction.Operand is IField field && field.ResolveFieldDef()?.DeclaringType.FindStaticConstructor() is { } owner) pending.Push(owner);
                if (instruction.OpCode.Code == Code.Ldtoken && instruction.Operand is ITypeDefOrRef type &&
                    type.ResolveTypeDef()?.FindStaticConstructor() is { } explicitInitializer) pending.Push(explicitInitializer);
            }
        }
        return false;
    }

    private static bool ClosedLifetime(TypeDef type)
    {
        var seen = new HashSet<TypeDef>();
        while (seen.Add(type))
        {
            if (type.Methods.Any(m => m.Name == "Finalize" || m.HasOverrides)) return false;
            if (type.BaseType is TypeRef parent && parent.FullName == "System.Object" && parent.DefinitionAssembly?.FullName == type.Module.CorLibTypes.AssemblyRef.FullName) return true;
            if (type.BaseType?.ResolveTypeDef() is not { } next || next.Module != type.Module) return false;
            type = next;
        }
        return false;
    }

    private sealed class DecoderIntrinsics(ModuleDef module) : IStaticIntrinsicRegistry
    {
        private readonly StaticIntrinsicRegistry defaults = StaticIntrinsicRegistry.CreateDefault();
        public bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic)
        {
            if (Framework(method, module) && defaults.TryResolve(method, out intrinsic)) return true;
            intrinsic = Refused.Instance; return true;
        }
    }
    private sealed class Refused : IStaticIntrinsic
    {
        internal static readonly Refused Instance = new();
        public bool Matches(IMethod method) => true;
        public IntrinsicResult Invoke(IntrinsicContext context, IMethod method, IReadOnlyList<StaticValue> arguments) =>
            IntrinsicResult.Unknown("Decoder effect proof refuses " + method.FullName);
    }

    private static bool Framework(IMethod method, ModuleDef module)
    {
        if (method.DeclaringType is not TypeRef type || !DependencyFrameworkScope.Matches(type, module)) return false;
        return method.FullName is
            "System.Void System.Object::.ctor()" or "System.Void System.InvalidOperationException::.ctor()" or
            "System.Void System.IDisposable::Dispose()" or
            "System.Reflection.Assembly System.Reflection.Assembly::GetExecutingAssembly()" or
            "System.Reflection.AssemblyName System.Reflection.Assembly::GetName()" or
            "System.Byte[] System.Reflection.AssemblyName::GetPublicKey()" or
            "System.Void System.Runtime.CompilerServices.RuntimeHelpers::RunClassConstructor(System.RuntimeTypeHandle)" or
            "System.Int32 System.Math::Min(System.Int32,System.Int32)" or
            "System.Void System.Array::Copy(System.Array,System.Int32,System.Array,System.Int32,System.Int32)" or
            "System.Void System.Buffer::BlockCopy(System.Array,System.Int32,System.Array,System.Int32,System.Int32)" ||
            type.FullName == "System.String" && method.Name.String is "ToCharArray" or ".ctor" ||
            type.FullName == "System.IO.BinaryReader" && method.Name.String is ".ctor" or "ReadByte" or "ReadUInt16" or "ReadInt32" or
                "ReadUInt32" or "ReadInt64" or "ReadUInt64" or "ReadSingle" or "ReadDouble" or "Read" or "ReadBytes" or "ReadString" or "get_BaseStream" or "Dispose" ||
            type.FullName is "System.IO.MemoryStream" or "System.IO.Stream" && method.Name.String is ".ctor" or "ToArray" or "Read" or "ReadByte" or
                "Write" or "WriteByte" or "Seek" or "get_Length" or "get_Position" or "set_Position" or "Dispose" or "Close" ||
            type.FullName == "System.Security.Cryptography.SymmetricAlgorithm" && method.Name.String is "set_IV" or "set_Key" or "CreateDecryptor" ||
            type.FullName is "System.Security.Cryptography.Aes" or "System.Security.Cryptography.DES" or "System.Security.Cryptography.TripleDES" or
                "System.Security.Cryptography.Rijndael" or "System.Security.Cryptography.RC2" && method.Name == "Create" && method.MethodSig.Params.Count == 0 ||
            type.FullName == "System.Security.Cryptography.CryptoStream" && method.Name.String is ".ctor" or "Read" or "Dispose" or "Close";
    }
}
