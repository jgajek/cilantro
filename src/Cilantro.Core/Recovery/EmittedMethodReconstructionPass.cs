using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Exposes a bounded, input-independent emitted stream decoder as marked analyst CIL.</summary>
public sealed class EmittedMethodReconstructionPass : DeobfuscationPass
{
    public override string Name => "emitted-method-reconstruction";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["control-flow-helper-completion"];
    internal const string Warning = "CILantro reconstructed this body from generated CIL for analysis. " +
        "Domain writes and reflected-call exception wrapping are retained. Generated assembly, type and method identities are not preserved; equivalence is not established.";

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.devirtualize", out var enabled) || !enabled || BootstrapMachine.Environment(context).Strict)
            return (PassStatus.Success, 0, ["Generated method reconstruction is disabled."]);
        var notes = new List<string>();
        var changes = 0;
        MethodDef? marker = null;
        foreach (var factory in context.Module.GetTypes().SelectMany(t => t.Methods).Where(Candidate).Take(32).ToArray())
        {
            var generated = Capture(context, factory, out var why);
            if (generated is null) { notes.Add($"{factory.MDToken}: {why}"); continue; }
            var original = factory.Body;
            using var transaction = new BodyMutationBatch([factory]);
            try
            {
                factory.Body = Lower(generated, factory);
                if (!AssemblyVerifier.Verify(context.Module).Passed)
                { notes.Add($"{factory.MDToken}: reconstructed CIL did not verify; original retained."); continue; }
                marker ??= AddMarker(context);
                factory.CustomAttributes.Add(new CustomAttribute(marker,
                    [new CAArgument(context.Module.CorLibTypes.String, new UTF8String(Warning))]));
                // Attribution does not delete a method still reached by the retained initializer.
                RecoveryOrphans.DeclareSubtree(context, original.Instructions
                    .Select(i => (i.Operand as IMethod)?.ResolveMethodDef()).OfType<MethodDef>()
                    .Where(m => m.Module == context.Module));
                transaction.RecordChange(context, new ChangeRecord(Name, "reconstruct-emitted-method",
                    factory.FullName, Warning));
                transaction.Commit();
                context.AddEvidence(new Evidence(Name, Warning, factory.FullName, 1.0));
                notes.Add($"{factory.MDToken}: reconstructed {generated.Body.Instructions.Count} emitted instructions. {Warning}");
                changes++;
            }
            catch (InvalidOperationException exception)
            { notes.Add($"{factory.MDToken}: reconstruction declined: {exception.Message}"); }
        }
        return (PassStatus.Success, changes, notes.Count == 0 ? ["No supported generated stream factory was found."] : notes);
    }

    private static bool Candidate(MethodDef method) => method.HasBody && !method.HasGenericParameters &&
        !method.DeclaringType.HasGenericParameters && method.MethodSig.Params.Count == 1 &&
        method.MethodSig.Params[0].FullName == "System.IO.Stream" && method.ReturnType.ElementType == ElementType.String &&
        method.Body.Instructions.Any(i => i.Operand is IMethod m && m.DeclaringType.FullName == "System.Reflection.Emit.TypeBuilder" && m.Name == "CreateType") &&
        method.Body.Instructions.Any(i => IsReflectionInvoke(i));

    private static bool IsReflectionInvoke(Instruction instruction) => instruction.Operand is IMethod method &&
        method.DeclaringType.FullName == "System.Type" && method.Name == "InvokeMember" && method.MethodSig?.Params.Count == 5;

    internal static MethodDef? Capture(ArtifactContext context, MethodDef factory, out string why)
    {
        if (factory.Body.ExceptionHandlers.Count != 0)
        { why = "factory exception handling cannot be discarded"; return null; }
        // No sample code is executed. The unknown stream must survive construction untouched.
        var inGenerated = false;
        var machine = new StaticMachine(new StaticMachineLimits(MaximumSteps: 1_000_000),
            new ConstructionIntrinsics(() => inGenerated));
        machine.State.RegisterModuleMetadata(context.Module);
        machine.State.RegisterRunEnvironment(new RunEnvironment(new HostEnvironment(HostProfile.Workstation)));
        var arguments = new List<StaticValue>();
        if (!factory.IsStatic)
        {
            machine.State.Heap.TryAllocateObject(factory.DeclaringType.FullName, out var receiver);
            arguments.Add(receiver);
        }
        arguments.Add(StaticValue.Unknown);
        MethodDef? captured = null;
        var invalid = false;
        var refusals = new HashSet<string>();
        Instruction? invocation = null;
        var visited = new HashSet<MethodDef>();
        machine.Stepped = (method, instruction) =>
        {
            if (inGenerated) return;
            visited.Add(method);
            if (instruction.Operand is IField { FieldSig: not null } field && field.DeclaringType.FullName != "System.Reflection.Emit.OpCodes")
            { invalid = true; refusals.Add($"construction accesses {field.FullName}"); }
            if (instruction.OpCode.Code is Code.Calli or Code.Starg or Code.Starg_S)
            { invalid = true; refusals.Add($"construction uses {instruction.OpCode}"); }
            if (method == factory) invocation = instruction;
        };
        machine.FrameEntered = (method, values) =>
        {
            if (!machine.State.IsAssembled(method.Module)) return;
            if (captured is not null) { invalid = true; refusals.Add("multiple generated frames"); return; }
            captured = method;
            inGenerated = true;
            var effects = machine.State.LoaderEvidence.EffectsOf(factory.MDToken.Raw);
            invalid |= effects.WroteStaticField || effects.WroteMappedImage || effects.WroteScratchRegion || effects.Registrations.Count != 0;
            invalid |= values.Count != 1 || values[0].Kind != StaticValueKind.Unknown;
            if (invalid) refusals.Add("construction effects or argument forwarding were not isolated");
        };
        var result = machine.Execute(factory, arguments);
        why = "could not establish an input-independent generated body: " + result.Status +
            (refusals.Count == 0 ? "" : "; " + string.Join("; ", refusals));
        if (invalid || captured is null || invocation is null || !IsReflectionInvoke(invocation) ||
            !captured.IsStatic || captured.MethodSig.Params.Count != 1 ||
            captured.MethodSig.Params[0].FullName != "System.IO.Stream" || captured.ReturnType.ElementType != ElementType.String ||
            captured.Body.ExceptionHandlers.Count != 0) return null;
        if (!HasUnmodifiedReturn(factory, invocation))
        { why = "the reflected invocation is not an unmodified tail return"; return null; }
        // Reject host/state-dependent construction even when the observed path happened to work.
        foreach (var method in visited)
        {
            // The factory's own initialization trigger survives the replacement, but a helper's
            // would disappear. Capture deliberately does not initialize types with unknown input.
            if (method.DeclaringType != factory.DeclaringType &&
                method.DeclaringType.FindStaticConstructor() is { } initializer &&
                (!initializer.HasBody || initializer.Body.Instructions.Any(i => i.OpCode.Code is not (Code.Nop or Code.Ret))))
            { why = "construction depends on another type initializer"; return null; }
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is IField { FieldSig: not null } field && field.DeclaringType.FullName != "System.Reflection.Emit.OpCodes")
                { why = "construction references mutable fields"; return null; }
                if (instruction.Operand is IMethod called && called.ResolveMethodDef()?.Module != context.Module &&
                    !ConstructionCall(called))
                { why = $"construction calls unsupported {called.FullName}"; return null; }
            }
        }
        why = "captured generated CIL; dynamic assembly identity remains outside the reconstruction";
        return captured;
    }

    // Follow only unconditional transport of the reflected result. Debug compilers
    // commonly spill that result and branch to a shared return. No computation,
    // side effect, conditional path, address escape or replacement value is allowed.
    internal static bool HasUnmodifiedReturn(MethodDef factory, Instruction invocation)
    {
        if (!factory.HasBody || factory.Body.ExceptionHandlers.Count != 0) return false;
        var il = factory.Body.Instructions;
        var index = il.IndexOf(invocation) + 1;
        if (index == 0) return false;
        var visited = new HashSet<Instruction>();
        Local? spill = null;
        var cast = false;
        var onStack = true;
        while (index < il.Count && visited.Count < 256)
        {
            var instruction = il[index++];
            if (!visited.Add(instruction)) return false;
            if (instruction.OpCode.Code == Code.Nop) continue;
            if (instruction.OpCode.Code is Code.Br or Code.Br_S)
            {
                if (instruction.Operand is not Instruction target || (index = il.IndexOf(target)) < 0) return false;
                continue;
            }
            if (!cast)
            {
                if (instruction.OpCode.Code != Code.Castclass || instruction.Operand is not ITypeDefOrRef type ||
                    !new SigComparer().Equals(type.ToTypeSig(), factory.Module.CorLibTypes.String)) return false;
                cast = true;
                continue;
            }
            if (instruction.OpCode.Code == Code.Ret) return onStack;
            if (instruction.IsStloc() && onStack && spill is null)
            {
                spill = instruction.GetLocal(factory.Body.Variables);
                if (spill is null || !new SigComparer().Equals(spill.Type, factory.Module.CorLibTypes.String)) return false;
                var uses = il.Where(i => i.GetLocal(factory.Body.Variables) == spill).ToArray();
                if (uses.Length != 2 || uses.Count(i => i.IsStloc()) != 1 || uses.Count(i => i.IsLdloc()) != 1) return false;
                onStack = false;
                continue;
            }
            if (instruction.IsLdloc() && !onStack && instruction.GetLocal(factory.Body.Variables) == spill)
            {
                onStack = true;
                continue;
            }
            return false;
        }
        return false;
    }
    private static bool ConstructionCall(IMethod method)
    {
        var owner = method.DeclaringType.FullName;
        if (owner.StartsWith("System.Reflection.Emit.", StringComparison.Ordinal)) return true;
        return (owner, method.Name.String) switch
        {
            ("System.Type", "GetTypeFromHandle" or "GetType" or "GetMethod" or "GetConstructor" or "InvokeMember") => true,
            ("System.Reflection.AssemblyName", ".ctor") => true,
            ("System.Reflection.MethodBase" or "System.Reflection.MethodInfo", "Invoke") => true,
            ("System.AppDomain", "get_CurrentDomain") => true,
            ("System.Object", ".ctor") => true,
            ("System.Convert", "FromBase64String") => true,
            ("System.Text.Encoding", "get_UTF8" or "GetString") => true,
            ("System.String", "Split") => true,
            ("System.Int32", "Parse") => true,
            _ => false
        };
    }

    // Reflection re-enters through the same registry, so a MethodInfo.Invoke cannot hide a
    // host-dependent framework call from the construction whitelist. Generated IL is retained,
    // not evaluated into constants, and can use the ordinary models after entry.
    private sealed class ConstructionIntrinsics(Func<bool> generated) : IStaticIntrinsicRegistry
    {
        private readonly StaticIntrinsicRegistry _inner = StaticIntrinsicRegistry.CreateDefault();
        public bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic)
        {
            intrinsic = null!;
            return (generated() || ConstructionCall(method)) && _inner.TryResolve(method, out intrinsic);
        }
    }

    internal static CilBody Lower(MethodDef generated, MethodDef factory)
    {
        var module = factory.Module;
        var importer = new Importer(module);
        var source = generated.Body;
        if (source.ExceptionHandlers.Count != 0) throw new InvalidOperationException("Generated exception regions are not supported.");
        if (generated.DeclaringType.FindStaticConstructor() is not null || generated.Module.GlobalType?.FindStaticConstructor() is not null)
            throw new InvalidOperationException("Generated type or module initialization cannot be discarded.");
        bool GeneratedType(ITypeDefOrRef? type) => type?.Scope == generated.Module || type?.ResolveTypeDef()?.Module == generated.Module;
        if (source.Variables.Any(local => GeneratedType(local.Type.ToTypeDefOrRef())) ||
            source.Instructions.Any(instruction => instruction.Operand switch
            {
                ITypeDefOrRef type => GeneratedType(type),
                IMemberRef member => GeneratedType(member.DeclaringType),
                _ => false
            }))
            throw new InvalidOperationException("The body references other generated declarations that cannot be imported independently.");
        var body = new CilBody { InitLocals = true };
        var locals = source.Variables.ToDictionary(v => v, v => new Local(importer.Import(v.Type)));
        foreach (var local in source.Variables) body.Variables.Add(locals[local]);
        var instructions = source.Instructions.ToDictionary(i => i, i => new Instruction(i.OpCode));
        foreach (var instruction in source.Instructions)
        {
            var copy = instructions[instruction];
            copy.Operand = instruction.Operand switch
            {
                Instruction target => instructions[target],
                IList<Instruction> targets => targets.Select(t => instructions[t]).ToArray(),
                Local local => locals[local],
                IMethod { MethodSig: not null } method => importer.Import(method),
                IField { FieldSig: not null } field => importer.Import(field),
                ITypeDefOrRef type => importer.Import(type),
                _ => instruction.Operand
            };
            if (instruction.IsLdarg() || (instruction.OpCode.Code is Code.Ldarga or Code.Ldarga_S) || instruction.IsStarg())
            {
                var index = instruction.Operand is Parameter parameter ? parameter.Index : instruction.GetParameterIndex();
                if (index != 0) throw new InvalidOperationException("Generated argument is outside the supported signature.");
                copy.OpCode = instruction.IsLdarg() ? OpCodes.Ldarg : (instruction.OpCode.Code is Code.Ldarga or Code.Ldarga_S) ? OpCodes.Ldarga : OpCodes.Starg;
                copy.Operand = factory.Parameters[factory.IsStatic ? 0 : 1];
            }
            body.Instructions.Add(copy);
        }
        var result = new Local(module.CorLibTypes.String);
        body.Variables.Add(result);
        var done = OpCodes.Ldloc.ToInstruction(result);
        foreach (var instruction in body.Instructions.ToArray().Where(i => i.OpCode.Code == Code.Ret))
        {
            instruction.OpCode = OpCodes.Stloc; instruction.Operand = result;
            body.Instructions.Insert(body.Instructions.IndexOf(instruction) + 1, OpCodes.Leave.ToInstruction(done));
        }
        var exception = module.CorLibTypes.GetTypeRef("System", "Exception");
        var wrapped = module.CorLibTypes.GetTypeRef("System.Reflection", "TargetInvocationException");
        var constructor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, exception.ToTypeSig()), wrapped);
        var handler = OpCodes.Newobj.ToInstruction(constructor);
        body.Instructions.Add(handler);
        body.Instructions.Add(OpCodes.Throw.ToInstruction());
        body.Instructions.Add(done);
        body.Instructions.Add(OpCodes.Ret.ToInstruction());
        body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        { TryStart = body.Instructions[0], TryEnd = handler, HandlerStart = handler, HandlerEnd = done, CatchType = exception });
        body.SimplifyBranches();
        body.UpdateInstructionOffsets();
        return body;
    }

    private static MethodDefUser AddMarker(ArtifactContext context)
    {
        var module = context.Module;
        var attribute = module.CorLibTypes.GetTypeRef("System", "Attribute");
        var type = new TypeDefUser("Cilantro.Analysis", "ReconstructedEmittedMethodAttribute", attribute)
        { Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit };
        var constructor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String))
        { Attributes = MethodAttributes.Assembly | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
        constructor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
        constructor.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), attribute)));
        constructor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type.Methods.Add(constructor); module.Types.Add(type);
        context.TryGetFact<int>(VirtualizationRebuildPass.AddedTypesFact, out var types);
        context.TryGetFact<int>(VirtualizationRebuildPass.AddedMethodsFact, out var methods);
        context.SetFact(VirtualizationRebuildPass.AddedTypesFact, types + 1);
        context.SetFact(VirtualizationRebuildPass.AddedMethodsFact, methods + 1);
        return constructor;
    }
}
