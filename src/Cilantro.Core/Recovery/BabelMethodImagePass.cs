using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Follows Babel construction to its actual generated-method invocation, without executing that body.</summary>
public sealed class BabelMethodImagePass : DeobfuscationPass
{
    public override string Name => "babel-method-images";
    public override IReadOnlyCollection<string> Dependencies => ["babel-detection", "babel-checks"];
    public override bool GatesEmission => true;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<BabelStructureFacts>("babel.structure", out var babel) || babel?.IsBabel != true)
            return (PassStatus.Success, 0, ["No Babel method images detected."]);
        using var original = ModuleDefMD.Load(context.OriginalBytes);
        var stubs = original.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody &&
            method.Body.Instructions.Any(instruction => instruction.Operand is IMethod called && Dispatcher(called))).ToArray();
        context.SetFact("babel.methodImages.detected", stubs.Length);
        if (stubs.Length == 0)
        {
            var dormant = BabelDormantMethodRuntime.Remember(context, original,
                original.GetTypes().SelectMany(type => type.Methods).Where(method => Dispatcher(method)));
            return (PassStatus.Success, 0, [dormant
                ? "No method-image dispatch stubs remain; complete reviewed empty-image runtime ownership was established."
                : "No Babel method-image dispatch stubs found."]);
        }
        if (stubs.Length > 256) return (PassStatus.Unsupported, 0, ["Babel method-image count exceeds the construction bound."]);
        var recovered = new List<(MethodDef Target, CilBody Body)>();
        var inputs = new List<BabelMethodImageResourceOwnership.Read>();
        var notes = new List<string>();
        foreach (var stub in stubs)
        {
            if (!ClosedStub(stub) || context.Module.ResolveToken(stub.MDToken) is not MethodDef target)
                return (PassStatus.Unsupported, 0, [$"Babel method-image stub {stub.MDToken} requires unsupported argument adaptation; emission withheld."]);
            var first = Capture(context, original, stub, 0, out var firstReads, out var why);
            if (first is null) return (PassStatus.Unsupported, 0, [$"Babel method image {stub.MDToken}: {Short(why)}"]);
            var second = Capture(context, original, stub, 7919, out var secondReads, out why);
            if (second is null || Description(first) != Description(second))
                return (PassStatus.Unsupported, 0, [$"Babel method-image construction trials disagreed for {stub.MDToken}: {why}"]);
            var replacement = stub.Parameters.Any(parameter => parameter.Type.IsByRef)
                ? BabelByRefAdapter.Build(stub, first, target, Dispatcher) : Lower(first, target);
            if (replacement is null) return (PassStatus.Unsupported, 0, [$"Babel method image {stub.MDToken} requires unsupported by-reference body adaptation."]);
            recovered.Add((target, replacement));
            if (firstReads.ToHashSet().SetEquals(secondReads)) inputs.AddRange(firstReads);
            notes.Add($"{stub.MDToken}: recovered {first.Body.Instructions.Count} CIL instructions and {first.Body.ExceptionHandlers.Count} exception clauses from agreeing construction trials.");
        }
        using var batch = new BodyMutationBatch(recovered.Select(item => item.Target));
        foreach (var (method, body) in recovered)
        {
            method.Body = body;
            if (!EvaluationStackAnalyzer.Analyze(method).Valid)
                return (PassStatus.Unsupported, 0, ["Restored Babel body did not pass evaluation-stack verification; original stubs retained."]);
            batch.RecordChange(context, new(Name, "restore-babel-method-image", method.FullName,
                "Restored CIL and exception clauses from the method actually reached by the original dispatch stub. Generated application CIL was not executed by recovery."));
        }
        if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed)
            return (PassStatus.Unsupported, 0, ["Restored Babel method images did not pass structural verification; original stubs retained."]);
        batch.Commit();
        BabelMethodImageResourceOwnership.Remember(context, inputs);
        BabelMethodConstructionRuntime.Remember(context, original);
        RecoveryOrphans.DeclareOwningTypes(context, stubs.SelectMany(stub => stub.Body.Instructions.Select(instruction => instruction.Operand).OfType<IMethod>())
            .Where(Dispatcher).Select(method => method.ResolveMethodDef()).OfType<MethodDef>().Select(method => context.Module.ResolveToken(method.MDToken)).OfType<MethodDef>());
        context.SetFact("babel.methodImages.restored", recovered.Count);
        BabelMethodLeafRuntime.Remember(context, original,
            original.GetTypes().SelectMany(type => type.Methods).Where(method => Dispatcher(method)), inputs);
        return (PassStatus.Success, recovered.Count, notes);
    }

    private static bool Dispatcher(IMethod method) => method.MethodSig is { Params.Count: 4 } signature &&
        signature.RetType.ElementType == ElementType.Object && signature.Params[0].ElementType == ElementType.I4 &&
        signature.Params[1].FullName == "System.Reflection.MethodBase" && signature.Params[2].ElementType == ElementType.Object &&
        signature.Params[3].FullName == "System.Object[]" && method.ResolveMethodDef() is { HasBody: true, IsStatic: true };

    private static bool ClosedStub(MethodDef method)
    {
        if (method.DeclaringType.HasGenericParameters) return BabelGenericStub.Match(method, Dispatcher) is not null;
        if (method.Parameters.Any(parameter => parameter.Type.IsByRef)) return BabelByRefAdapter.Supported(method, Dispatcher);
        if (!method.IsStatic && method.DeclaringType.IsValueType || method.HasGenericParameters || method.DeclaringType.HasGenericParameters ||
            method.Body.ExceptionHandlers.Count != 0 || method.Body.Instructions.Count > 512 || method.Parameters.Any(parameter => parameter.Type.IsByRef)) return false;
        var dispatches = 0;
        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.OpCode.Code == Code.Call && instruction.Operand is IMethod called && Dispatcher(called)) { dispatches++; continue; }
            if (instruction.IsLdcI4() || instruction.IsLdarg() || instruction.IsLdloc() || instruction.IsStloc() || instruction.OpCode.Code is
                Code.Nop or Code.Ldnull or Code.Newarr or Code.Dup or Code.Box or Code.Stelem_Ref or Code.Unbox_Any or Code.Castclass or Code.Ret or Code.Pop) continue;
            return false;
        }
        if (dispatches != 1) return false;
        var call = method.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Call && instruction.Operand is IMethod called && Dispatcher(called));
        var tail = method.Body.Instructions.Skip(method.Body.Instructions.IndexOf(call) + 1).Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        if (tail.Length == 1) return method.ReturnType.ElementType == ElementType.Object && tail[0].OpCode.Code == Code.Ret;
        if (tail.Length != 2 || tail[1].OpCode.Code != Code.Ret) return false;
        if (method.ReturnType.ElementType == ElementType.Void) return tail[0].OpCode.Code == Code.Pop;
        return tail[0].OpCode.Code == (method.ReturnType.IsValueType ? Code.Unbox_Any : Code.Castclass) &&
            tail[0].Operand is ITypeDefOrRef converted && new SigComparer().Equals(converted.ToTypeSig(), method.ReturnType);
    }

    private sealed class InvocationReached : Exception;

    private static MethodDef? Capture(ArtifactContext context, ModuleDefMD original, MethodDef stub, int seed,
        out IReadOnlyList<BabelMethodImageResourceOwnership.Read> reads, out string why)
    {
        reads = [];
        var registry = new RawDynamicMethodIntrinsic();
        var generic = stub.DeclaringType.HasGenericParameters ? BabelGenericStub.Match(stub, Dispatcher) : null;
        ParametricTypeIntrinsic? types = null;
        StaticMachine machine;
        if (generic is not null)
        {
            var names = BabelDelegateNameContract.Find(original, context.OriginalBytes);
            if (names is null) { why = "Generic construction has no proved delegate-name contract."; return null; }
            types = new(stub.DeclaringType, registry);
            machine = new BabelDelegateNameIntrinsic(names, types, "trial" + seed).CreateMachine(BootstrapMachine.Limits(4_000_000));
            types.Attach(machine);
            registry.UnknownBoxInput = (_, value) => value.Kind == StaticValueKind.Unknown;
            registry.OpaqueLocalInput = types.CertifiesRuntimeType;
        }
        else machine = new StaticMachine(BootstrapMachine.Limits(4_000_000), registry, modelTypeInitialization: true);
        machine.State.RegisterModuleMetadata(original);
        machine.State.RegisterPointerSize(context.OriginalImage.IsPe32Plus ? 8 : 4);
        machine.State.RegisterAssemblyIdentity(original.Assembly?.Name ?? original.Name, original.Assembly?.PublicKeyToken?.Data ?? []);
        machine.State.RegisterModuleFile(context.InputPath, context.OriginalBytes);
        if (!BabelCodeSourceInputs.Attach(context, machine.State))
        { why = "Explicit Babel code-source files could not be mounted in the bounded catalog."; return null; }
        machine.State.RegisterRunEnvironment(new(new(HostProfile.Parse($"{{\"facts\":{{\"guid:Seed\":{seed}}}}}", "Babel construction identities"))));
        if (context.TryGetFact<HashSet<uint>>(BabelCheckPass.NeutralizedFact, out var guards) && guards is not null)
            foreach (var guard in guards) machine.State.RegisterNeutralizedMethod(guard);
        foreach (var resource in original.Resources.OfType<EmbeddedResource>()) machine.State.RegisterResource(resource.Name, resource.CreateReader().ToArray());
        var roots = stub.Parameters.Select(parameter => machine.State.Provenance.Origin(StaticValue.Unknown, ProvenanceKind.Argument,
            "Babel construction input", parameter.Index.ToString(System.Globalization.CultureInfo.InvariantCulture))).ToArray();
        if (generic is not null)
        {
            var receiver = generic.Prepare(machine, types!);
            if (!stub.IsStatic) roots[0] = machine.State.Provenance.Origin(receiver, ProvenanceKind.Argument, "Generic receiver", "0");
        }
        var arguments = roots.Select((root, index) => stub.Parameters[index].Type.IsByRef ? machine.State.Heap.AllocateManagedCell(root) : root).ToArray();
        MethodDef? body = null;
        var invalid = false;
        var foreignTokens = new HashSet<uint>();
        machine.FrameEntered += (method, _) => { if (method.Module != original) foreignTokens.Add(method.MDToken.Raw); };
        registry.Invoking = (capture, supplied) =>
        {
            invalid = capture.Assembled is not { HasBody: true, Body.Instructions.Count: > 0 } || supplied.Count != roots.Length ||
                !new SigComparer().Equals(capture.Returns, stub.ReturnType) || capture.Parameters.Count != stub.Parameters.Count ||
                !capture.Parameters.Zip(stub.Parameters).All(pair => new SigComparer().Equals(pair.First, pair.Second.Type));
            for (var index = 0; index < supplied.Count && index < roots.Length; index++)
            {
                var expected = roots[index];
                if (stub.Parameters[index].Type.IsByRef && !machine.State.Heap.TryReadManaged(arguments[index], out expected)) { invalid = true; continue; }
                invalid |= supplied[index] != expected || expected.Kind == StaticValueKind.Unknown &&
                    !(stub.Parameters[index].Type.IsByRef
                        ? ForwardedReferenceInput(machine.State.Provenance, supplied[index].ProvenanceId, expected.ProvenanceId, arguments[index])
                        : Forwarded(machine.State.Provenance, supplied[index].ProvenanceId, expected.ProvenanceId));
            }
            body = capture.Assembled;
            throw new InvocationReached();
        };
        try
        {
            if (original.GlobalType.FindStaticConstructor() is { } initializer)
            {
                var startup = machine.Execute(initializer);
                if (!startup.Succeeded) { why = startup.Diagnostic ?? "Module initialization did not complete."; return null; }
            }
            var result = generic is not null && stub.IsStatic
                ? machine.Invoke(new MemberRefUser(original, stub.Name, stub.MethodSig, types!.Owner.ToTypeDefOrRef()), arguments)
                : machine.Execute(stub, arguments);
            why = result.Diagnostic ?? "Construction did not reach a captured application body.";
            return null;
        }
        catch (InvocationReached)
        {
            var effects = machine.State.LoaderEvidence.EffectsOf(stub.MDToken.Raw);
            invalid |= effects.WroteMappedImage || effects.WroteScratchRegion || effects.StaticFieldsWritten.Any(field =>
                field.Contains(stub.DeclaringType.FullName + "::", StringComparison.Ordinal));
            invalid |= generic is not null && !generic.Unchanged(machine.State.Heap);
            if (generic is not null && body is not null)
                invalid |= body.Body.Instructions.Any(instruction => instruction.Operand is IMemberRef member &&
                    machine.State.IsAssembled((member is ITypeDefOrRef type ? type : member.DeclaringType)?.ResolveTypeDef()?.Module));
            why = invalid ? "Construction altered application state, arguments or signature." : "Captured the actual dynamic invocation before entry.";
            if (!invalid)
                reads = BabelMethodImageResourceOwnership.Observe(original, stub, machine.State.LoaderEvidence, foreignTokens);
            return invalid ? null : body;
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or IOException)
        { why = exception.Message; return null; }
    }

    private static bool Forwarded(ProvenanceGraph graph, int current, int root)
    {
        var seen = new HashSet<int>();
        var pending = new Stack<int>();
        pending.Push(current);
        var found = false;
        while (pending.TryPop(out var id))
        {
            if (id == root) { found = true; continue; }
            if (!seen.Add(id)) continue;
            if (seen.Count > 1024 || !graph.TryReadNode(id, out var node) || node.Kind != ProvenanceKind.Argument || node.Parents.Count == 0) return false;
            foreach (var parent in node.Parents) pending.Push(parent);
        }
        return found;
    }

    private static bool ForwardedReferenceInput(ProvenanceGraph graph, int current, int root, StaticValue pointer)
    {
        var seen = new HashSet<int>();
        while (seen.Add(current) && seen.Count <= 1024 && graph.TryReadNode(current, out var node))
        {
            if (node.Kind == ProvenanceKind.ManagedReference && node.Parents.Count == 2)
                return node.Parents.Any(parent => graph.TryReadNode(parent, out var address) && address.Kind == ProvenanceKind.Argument &&
                        address.ValueKind == StaticValueKind.ManagedReference && address.ValueBits == pointer.Bits) &&
                    node.Parents.Any(parent => Forwarded(graph, parent, root));
            if (node.Kind != ProvenanceKind.Argument || node.Parents.Count != 1) return false;
            current = node.Parents[0];
        }
        return false;
    }

    private static string Description(MethodDef method)
    {
        var il = method.Body.Instructions;
        string Operand(object? operand) => operand switch
        {
            Instruction target => "@" + il.IndexOf(target), IList<Instruction> targets => string.Join(',', targets.Select(target => il.IndexOf(target))),
            Local local => "local" + local.Index, Parameter parameter => "parameter" + parameter.Index,
            IFullName member => member.FullName, _ => operand?.ToString() ?? ""
        };
        return JsonSerializer.Serialize(new { method.Body.InitLocals, Locals = method.Body.Variables.Select(local => local.Type.FullName),
            Il = il.Select(instruction => instruction.OpCode.Code + ":" + Operand(instruction.Operand)),
            Eh = method.Body.ExceptionHandlers.Select(handler => new { handler.HandlerType, Catch = handler.CatchType?.FullName,
                Start = il.IndexOf(handler.TryStart), End = il.IndexOf(handler.TryEnd), Handler = il.IndexOf(handler.HandlerStart), HandlerEnd = il.IndexOf(handler.HandlerEnd), Filter = il.IndexOf(handler.FilterStart) }) });
    }

    internal static CilBody Lower(MethodDef generated, MethodDef target)
    {
        var importer = new Importer(target.Module);
        var source = generated.Body;
        var body = new CilBody { InitLocals = source.InitLocals, MaxStack = source.MaxStack };
        var locals = source.Variables.ToDictionary(local => local, local => new Local(importer.Import(local.Type)));
        foreach (var local in source.Variables) body.Variables.Add(locals[local]);
        var instructions = source.Instructions.ToDictionary(instruction => instruction, instruction => new Instruction(instruction.OpCode));
        foreach (var instruction in source.Instructions)
        {
            var copy = instructions[instruction];
            copy.Operand = instruction.Operand switch
            {
                Instruction branch => instructions[branch], IList<Instruction> branches => branches.Select(branch => instructions[branch]).ToArray(),
                Local local => locals[local], Parameter parameter => target.Parameters[parameter.Index],
                IMethod { MethodSig: not null } method => method is MethodDef definition && target.Module.ResolveToken(definition.MDToken) is MethodDef localMethod &&
                    localMethod.FullName == definition.FullName ? localMethod : importer.Import(method),
                IField { FieldSig: not null } field => field is FieldDef definition && target.Module.ResolveToken(definition.MDToken) is FieldDef localField &&
                    localField.FullName == definition.FullName ? localField : importer.Import(field),
                ITypeDefOrRef type => importer.Import(type),
                _ => instruction.Operand
            };
            body.Instructions.Add(copy);
        }
        foreach (var handler in source.ExceptionHandlers)
            body.ExceptionHandlers.Add(new ExceptionHandler(handler.HandlerType)
            {
                TryStart = instructions[handler.TryStart], TryEnd = handler.TryEnd is null ? null : instructions[handler.TryEnd],
                HandlerStart = instructions[handler.HandlerStart], HandlerEnd = handler.HandlerEnd is null ? null : instructions[handler.HandlerEnd],
                FilterStart = handler.FilterStart is null ? null : instructions[handler.FilterStart], CatchType = handler.CatchType is null ? null : importer.Import(handler.CatchType)
            });
        return body;
    }

    private static string Short(string text)
    {
        var provenance = text.IndexOf(" | provenance:", StringComparison.Ordinal);
        if (provenance >= 0) text = text[..provenance];
        return text.Length <= 1800 ? text : text[..1800] + "…";
    }
}
