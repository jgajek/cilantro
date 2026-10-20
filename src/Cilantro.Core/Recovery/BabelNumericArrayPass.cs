using System.Buffers.Binary;
using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Recovers primitive array literals without sharing their mutable results.</summary>
public sealed class BabelNumericArrayPass : DeobfuscationPass
{
    public override string Name => "babel-numeric-arrays";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["delegate-string-completion", "numeric-tables-finalization"];
    internal const string RecoveredFact = "babel.numericArrays.recovered";
    internal const string AddedTypesFact = "babel.numericArrays.addedTypes";
    internal const string AddedFieldsFact = "babel.numericArrays.addedFields";
    private sealed record Site(MethodDef Caller, Instruction[] Input, MethodDef Factory, FieldDef Source, byte[] Bytes);
    internal sealed record Payload(string Element, int Length, byte[] Bytes);

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<BabelStructureFacts>("babel.structure", out var babel) || babel?.IsBabel != true ||
            !context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Babel numeric-array recovery/runtime removal is not enabled."]);
        using var original = ModuleDefMD.Load(context.OriginalBytes);
        var runtimes = BabelNumericArrayShape.Find(original).ToArray();
        if (runtimes.Length is 0 or > 8) return (PassStatus.Success, 0, ["No bounded Babel numeric-array family found."]);
        var methods = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToArray();
        var recovered = new List<(Site Site, Payload Data)>();
        var attributed = new HashSet<MethodDef>();
        var attributedTypes = new HashSet<TypeDef>();
        var work = new StaticWorkBudget(64_000_000);
        var notes = new List<string>();
        foreach (var runtime in runtimes)
        {
            if (context.Module.ResolveToken(runtime.Factory.MDToken) is not MethodDef factory || !methods.Contains(factory)) continue;
            var sites = methods.SelectMany(method => Sites(method, factory)).ToArray();
            if (sites.Length == 0) continue;
            if (sites.Length > 256) return (PassStatus.Unsupported, 0, ["Numeric-array site count exceeds its bound."]);
            using var proof = ModuleDefMD.Load(context.OriginalBytes);
            var copy = BabelNumericArrayShape.Find(proof).Single(item => item.Factory.MDToken == runtime.Factory.MDToken);
            if (!BabelHashStringShape.TryDescribeCodec(copy.Codec, out var codec) || !BabelNumericArrayShape.ReviewedCodec(codec) ||
                !BabelNumericArrayShape.TryDescribe(copy, out var fingerprint) || !BabelNumericArrayShape.Reviewed(fingerprint))
            { notes.Add("Unreviewed numeric-array family/codec; original array calls retained."); continue; }
            var owner = runtime.Factory.DeclaringType;
            var types = new[] { owner }.Concat(owner.NestedTypes).Concat(GeneratedRuntimeShape.Read(runtime.Codec).Types).Distinct().ToArray();
            if (!ClosedCurrent(context, types, out var allowedMethods, out var allowedFields))
            { notes.Add("Numeric-array construction has changed dependencies or mutable metadata; original calls retained."); continue; }
            foreach (var site in sites)
            {
                var first = Read(context, site, 0, allowedMethods, allowedFields, work, out var why);
                var second = first is null ? null : Read(context, site, 7919, allowedMethods, allowedFields, work, out why);
                if (first is null || second is null || first.Element != second.Element || first.Length != second.Length || !first.Bytes.AsSpan().SequenceEqual(second.Bytes))
                { notes.Add($"{site.Caller.MDToken}: array construction retained: {why}"); continue; }
                recovered.Add((site, first));
                // The reviewed codec fingerprint covers complete helper types, including
                // compression siblings which the decompression invocation never calls.
                // Attribute only original members in that closed graph; cleanup still
                // requires deadness and the absence of surviving metadata references.
                attributed.UnionWith(allowedMethods.Select(token => context.Module.ResolveToken(token)).OfType<MethodDef>());
                attributedTypes.UnionWith(types.Select(type => context.Module.ResolveToken(type.MDToken)).OfType<TypeDef>());
            }
        }
        if (recovered.Count == 0) return (PassStatus.Success, 0, ["No numeric-array literal could be completely recovered.", .. notes.Take(8)]);
        using var batch = new BodyMutationBatch(recovered.Select(item => item.Site.Caller));
        var added = new List<TypeDef>();
        var emitted = new Dictionary<Site, FieldDef?>();
        var committed = false;
        try
        {
            foreach (var (site, data) in recovered)
            {
                FieldDef? field = null;
                if (data.Bytes.Length != 0)
                {
                    var name = "NumericArrayData"; var suffix = 0;
                    while (context.Module.Types.Any(type => type.Namespace == "Cilantro.Recovered" && type.Name == name)) name = "NumericArrayData" + ++suffix;
                    var holder = new TypeDefUser("Cilantro.Recovered", name, context.Module.CorLibTypes.GetTypeRef("System", "ValueType"))
                    { Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed | TypeAttributes.ExplicitLayout | TypeAttributes.BeforeFieldInit,
                        ClassLayout = new ClassLayoutUser(1, (uint)data.Bytes.Length) };
                    field = new FieldDefUser("Data", new FieldSig(new ValueTypeSig(holder)),
                        FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.InitOnly | FieldAttributes.HasFieldRVA) { InitialValue = data.Bytes.ToArray() };
                    holder.Fields.Add(field); context.Module.Types.Add(holder); added.Add(holder);
                }
                foreach (var instruction in site.Input) { instruction.OpCode = OpCodes.Nop; instruction.Operand = null; }
                var first = site.Input[0]; first.OpCode = OpCodes.Ldc_I4; first.Operand = data.Length;
                var il = site.Caller.Body.Instructions; var at = il.IndexOf(first) + 1;
                foreach (var instruction in Materialize(context.Module, data, field).Skip(1)) il.Insert(at++, instruction);
                emitted.Add(site, field);
                batch.RecordChange(context, new(Name, "restore-babel-numeric-array", site.Caller.FullName,
                    $"Restored a fresh {data.Element}[{data.Length}] from its exact encrypted literal after independent construction and repeated-identity trials."));
            }
            var old = CilantroPipeline.BuildRewriteAllowance(context);
            if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                    old with { AddedTypeCount = old.AddedTypeCount + added.Count, AddedFieldCount = old.AddedFieldCount + added.Count }).Passed)
                return (PassStatus.Unsupported, 0, ["Numeric-array materialization failed verification; original calls restored."]);
            batch.Commit(); committed = true;
        }
        finally { if (!committed) foreach (var type in added) context.Module.Types.Remove(type); }
        context.TryGetFact<int>(AddedTypesFact, out var earlierTypes); context.SetFact(AddedTypesFact, earlierTypes + added.Count);
        context.TryGetFact<int>(AddedFieldsFact, out var earlierFields); context.SetFact(AddedFieldsFact, earlierFields + added.Count);
        context.SetFact(RecoveredFact, recovered.Count);
        foreach (var group in recovered.GroupBy(item => item.Site.Source))
            RetiredBabelArrayData.Remember(context, group.Key, group.Select(item => item.Site.Caller),
                group.Select(item => emitted[item.Site]).OfType<FieldDef>());
        RecoveryOrphans.Declare(context, attributed);
        RecoveryOrphans.DeclareTypes(context, attributedTypes);
        return (PassStatus.Success, recovered.Count, [$"Recovered {recovered.Count} fresh primitive-array literals; exact superseded inputs are attributed for guarded metadata cleanup.", .. notes.Take(8)]);
    }

    private static IEnumerable<Site> Sites(MethodDef caller, MethodDef factory)
    {
        var il = caller.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        var graph = ControlFlowGraph.Build(caller);
        for (var at = 5; at < il.Length; at++)
        {
            if (il[at].OpCode.Code != Code.Call || (il[at].Operand as IMethod)?.ResolveMethodDef() != factory) continue;
            var span = il[(at - 5)..(at + 1)];
            if (!span[0].IsLdcI4() || span[0].GetLdcI4Value() is < 1 or > 4 * 1024 * 1024 ||
                span[1].OpCode.Code != Code.Newarr || span[1].Operand is not ITypeDefOrRef element || element.FullName != "System.Byte" ||
                element.DefinitionAssembly?.FullName != caller.Module.CorLibTypes.AssemblyRef.FullName ||
                span[2].OpCode.Code != Code.Dup || span[3].OpCode.Code != Code.Ldtoken || span[3].Operand is not IField reference ||
                reference.ResolveFieldDef() is not { IsStatic: true, IsInitOnly: true, HasFieldRVA: true, InitialValue: { } bytes } field ||
                field.Module != caller.Module || bytes.Length != span[0].GetLdcI4Value() ||
                field.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() is not { IsValueType: true, IsExplicitLayout: true, ClassLayout: { } layout } storage ||
                storage.IsEnum || storage.HasGenericParameters || storage.Fields.Any(member => !member.IsStatic) || layout.ClassSize != bytes.Length ||
                span[4].OpCode.Code != Code.Call || span[4].Operand is not IMethod initialize ||
                initialize.FullName != "System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)" ||
                initialize.DeclaringType.DefinitionAssembly?.FullName != caller.Module.CorLibTypes.AssemblyRef.FullName ||
                span.Any(instruction => graph.BlockOf(instruction) != graph.BlockOf(span[0]) || !graph.HaveIdenticalExceptionRegions(instruction, span[0]))) continue;
            yield return new(caller, span, factory, field, bytes.ToArray());
        }
    }

    private static bool ClosedCurrent(ArtifactContext context, TypeDef[] originalTypes, out HashSet<uint> methods, out HashSet<string> fields)
    {
        methods = originalTypes.SelectMany(type => type.Methods).Select(method => method.MDToken.Raw).ToHashSet();
        var definitions = originalTypes.SelectMany(type => type.Fields).ToDictionary(field => field.MDToken.Raw);
        fields = [];
        string CallKey(IMethod call) => call.FullName + "@" + call.DeclaringType.DefinitionAssembly?.FullName;
        var calls = originalTypes.SelectMany(type => type.Methods).Where(method => method.HasBody).SelectMany(method => method.Body.Instructions)
            .Select(instruction => instruction.Operand).OfType<IMethod>().Where(call => call.ResolveMethodDef()?.Module != originalTypes[0].Module).Select(CallKey).ToHashSet(StringComparer.Ordinal);
        string FieldKey(IField field) => field.FullName + "@" + field.DeclaringType.DefinitionAssembly?.FullName;
        var externalFields = originalTypes.SelectMany(type => type.Methods).Where(method => method.HasBody).SelectMany(method => method.Body.Instructions)
            .Select(instruction => instruction.Operand).OfType<IField>().Where(field => field.ResolveFieldDef()?.Module != originalTypes[0].Module).Select(FieldKey).ToHashSet(StringComparer.Ordinal);
        foreach (var field in definitions.Values)
            if (context.Module.ResolveToken(field.MDToken) is FieldDef current && current.DeclaringType is not null)
            {
                if (current.Attributes != field.Attributes || current.CustomAttributes.Count != field.CustomAttributes.Count) return false;
                fields.Add(current.FullName);
            }
        foreach (var token in methods)
            if (context.Module.ResolveToken(token) is MethodDef { HasBody: true, DeclaringType: not null } current)
                foreach (var instruction in current.Body.Instructions)
                {
                    if (instruction.Operand is IField reference)
                    {
                        if (reference.ResolveFieldDef() is { } field && field.Module == context.Module)
                        { if (!definitions.ContainsKey(field.MDToken.Raw)) return false; }
                        else if (!externalFields.Contains(FieldKey(reference))) return false;
                    }
                    if (instruction.Operand is not IMethod call) continue;
                    if (call.ResolveMethodDef() is { } target && target.Module == context.Module)
                    { if (!methods.Contains(target.MDToken.Raw)) return false; }
                    else if (!calls.Contains(CallKey(call))) return false;
                }
        return true;
    }

    private static Payload? Read(ArtifactContext context, Site site, int seed, HashSet<uint> methods, HashSet<string> fields, StaticWorkBudget work, out string why)
    {
        why = "incomplete construction";
        var machine = new StaticMachine(BootstrapMachine.Limits(16_000_000), modelTypeInitialization: true);
        machine.State.RegisterModuleMetadata(context.Module);
        machine.State.RegisterPointerSize(context.OriginalImage.IsPe32Plus ? 8 : context.Module.Is32BitRequired || seed == 0 ? 4 : 8);
        machine.State.RegisterAssemblyIdentity(context.Module.Assembly?.Name ?? context.Module.Name, context.Module.Assembly?.PublicKeyToken?.Data ?? []);
        machine.State.RegisterModuleFile(context.InputPath, context.OriginalBytes);
        machine.State.RegisterRunEnvironment(new(new(HostProfile.Parse($"{{\"facts\":{{\"guid:Seed\":{seed}}}}}", "Babel numeric array construction"))));
        var resources = context.Module.Resources.OfType<EmbeddedResource>().ToArray();
        if (resources.Length > 4096 || resources.Sum(resource => (long)resource.Length) > 128 * 1024 * 1024)
        { why = "resource inputs exceed the construction budget"; return null; }
        foreach (var resource in resources) machine.State.RegisterResource(resource.Name, resource.CreateReader().ToArray());
        var foreign = false;
        machine.FrameEntered = (method, _) => foreign |= method.Module != context.Module || !methods.Contains(method.MDToken.Raw);
        StaticValue Input()
        {
            if (!machine.State.Heap.TryAllocateArray(context.Module.CorLibTypes.Byte, site.Bytes.Length, out var input)) throw new InvalidOperationException("Array input allocation failed.");
            for (var index = 0; index < site.Bytes.Length; index++) machine.State.Heap.TryWriteArray(input, index, StaticValue.FromInt32(site.Bytes[index]));
            return input;
        }
        var input = Input(); var first = machine.Execute(site.Factory, [input], work);
        if (!first.Succeeded || !TrySnapshot(machine, context.Module, first.Value, out var data) || data is null || !Unchanged(input))
        { why = first.Diagnostic ?? "unsupported array result or input mutation"; return null; }
        var evidence = machine.State.LoaderEvidence;
        if (foreign || evidence.ObservationsTruncated || machine.State.CapturedAssemblyLoads.Count != 0 ||
            evidence.Effects.Values.Any(effect => effect.WroteMappedImage || effect.WroteScratchRegion || effect.Registrations.Count != 0 || effect.StaticFieldsWritten.Any(field => !fields.Contains(field))) ||
            evidence.Observations.Any(observation => observation.Kind != LoaderObservationKind.ManagedResourceRead))
        { why = "construction used foreign state or host input"; return null; }
        foreach (var observation in evidence.Observations)
        {
            var read = JsonSerializer.Deserialize<ManagedResourceRead>(observation.Detail);
            if (read is null || context.Module.Resources.OfType<EmbeddedResource>().Count(resource => resource.Name == read.Name &&
                    resource.Length == read.Length && new RecoveredResourceOrigin(read.Name, read.Sha256).Matches(resource)) != 1) return null;
        }
        var metadata = new Dictionary<object, int>(ReferenceEqualityComparer.Instance);
        var before = PrivateState(machine, metadata);
        if (before is null) { why = "initialized runtime state could not be completely captured"; return null; }
        var nextInput = Input();
        using var aside = machine.State.Evidence.SetAside(site.Factory.MDToken.Raw);
        var next = machine.Execute(site.Factory, [nextInput], work);
        var mark = machine.State.LoaderEvidence.EffectsOf(site.Factory.MDToken.Raw);
        if (!next.Succeeded || first.Value == next.Value || !TrySnapshot(machine, context.Module, next.Value, out var other) || other is null ||
            data.Element != other.Element || data.Length != other.Length || !data.Bytes.AsSpan().SequenceEqual(other.Bytes) || !Unchanged(nextInput) ||
            foreign || mark.WroteStaticField || mark.WroteMappedImage || mark.WroteScratchRegion || mark.Registrations.Count != 0 ||
            machine.State.LoaderEvidence.Observations.Any(observation => observation.Kind != LoaderObservationKind.ManagedResourceRead) ||
            machine.State.CapturedAssemblyLoads.Count != 0 || PrivateState(machine, metadata) != before)
        { why = "array identity, content or post-initialization effects are not stable"; return null; }
        return data;

        bool Unchanged(StaticValue array) => machine.State.Heap.GetBytesSnapshot(array) is { } bytes && bytes.AsSpan().SequenceEqual(site.Bytes);
    }

    private static string? PrivateState(StaticMachine machine, Dictionary<object, int> metadata)
    {
        var snapshot = new RebuiltMethodTrial.Snapshot(machine.State.Heap, metadata, preserveIdentity: true);
        var fields = machine.State.StaticFields.OrderBy(field => field.Key, StringComparer.Ordinal)
            .Select(field => new { field.Key, Value = snapshot.Read(field.Value) }).ToArray();
        var domain = snapshot.ReadDomainState(machine.State); var network = snapshot.ReadNetworkSettings(machine.State);
        var native = snapshot.ReadNativeState(machine.State);
        return snapshot.Failure is not null || fields.Any(field => field.Value is null) || domain is null || network is null || native is null
            ? null : JsonSerializer.Serialize(new { fields, domain, network, native });
    }

    internal static bool TrySnapshot(StaticMachine machine, ModuleDef module, StaticValue value, out Payload? data)
    {
        data = null;
        if (!machine.State.Heap.HasPrimitiveArrayElement(value) || !machine.State.Heap.TryGetArrayElementType(value, out var element) ||
            module.GetTypes().Any(candidate => candidate.FullName == element) || Element(module, element) is not { } type ||
            machine.State.Heap.GetArraySnapshot(value) is not { } values || values.Count > 1_048_576) return false;
        var width = Width(type.ElementType);
        if ((long)values.Count * width > 4 * 1024 * 1024) return false;
        var bytes = new byte[values.Count * width];
        for (var index = 0; index < values.Count; index++)
        {
            var item = values[index]; var span = bytes.AsSpan(index * width, width);
            var expected = type.ElementType is ElementType.R4 ? StaticValueKind.Float32 : type.ElementType is ElementType.R8 ? StaticValueKind.Float64 :
                width == 8 ? StaticValueKind.Int64 : StaticValueKind.Int32;
            if (item.Kind != expected) return false;
            switch (width)
            {
                case 1: span[0] = unchecked((byte)item.Bits); break;
                case 2: BinaryPrimitives.WriteInt16LittleEndian(span, unchecked((short)item.Bits)); break;
                case 4: BinaryPrimitives.WriteInt32LittleEndian(span, unchecked((int)item.Bits)); break;
                case 8: BinaryPrimitives.WriteInt64LittleEndian(span, item.Bits); break;
            }
        }
        data = new(element, values.Count, bytes); return true;
    }

    internal static IReadOnlyList<Instruction> Materialize(ModuleDef module, Payload data, FieldDef? field)
    {
        var il = new List<Instruction> { Instruction.CreateLdcI4(data.Length), OpCodes.Newarr.ToInstruction(Element(module, data.Element)!.TypeDefOrRef) };
        if (field is not null)
        {
            il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Ldtoken.ToInstruction(field));
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "InitializeArray", MethodSig.CreateStatic(module.CorLibTypes.Void,
                module.CorLibTypes.GetTypeRef("System", "Array").ToTypeSig(), new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeFieldHandle"))),
                module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers"))));
        }
        return il;
    }

    private static int Width(ElementType element) => element is ElementType.Boolean or ElementType.I1 or ElementType.U1 ? 1 :
        element is ElementType.Char or ElementType.I2 or ElementType.U2 ? 2 : element is ElementType.I8 or ElementType.U8 or ElementType.R8 ? 8 : 4;

    private static CorLibTypeSig? Element(ModuleDef module, string name) => name switch
    {
        "System.Boolean" => module.CorLibTypes.Boolean, "System.SByte" => module.CorLibTypes.SByte, "System.Byte" => module.CorLibTypes.Byte,
        "System.Int16" => module.CorLibTypes.Int16, "System.UInt16" => module.CorLibTypes.UInt16, "System.Char" => module.CorLibTypes.Char,
        "System.Int32" => module.CorLibTypes.Int32, "System.UInt32" => module.CorLibTypes.UInt32, "System.Int64" => module.CorLibTypes.Int64,
        "System.UInt64" => module.CorLibTypes.UInt64, "System.Single" => module.CorLibTypes.Single, "System.Double" => module.CorLibTypes.Double, _ => null
    };
}

/// <summary>Removes the array runtime after its verified final caller disappears.</summary>
public sealed class BabelNumericArrayCleanupPass : RuntimeCleanupPass
{
    public override string Name => "babel-numeric-array-cleanup";
    public override IReadOnlyCollection<string> Dependencies => ["babel-numeric-arrays"];
    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context) =>
        context.TryGetFact<int>(BabelNumericArrayPass.RecoveredFact, out var count) && count != 0
            ? base.Execute(context) : (PassStatus.Success, 0, ["No numeric-array decoder was retired."]);
}
