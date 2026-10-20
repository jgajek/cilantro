using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Proves a bundle index is constructed only from one supplied byte stream.</summary>
/// <remarks>This does not prove that every caller supplies that stream, or that consumers keep the index immutable.</remarks>
internal static class DependencyIndexConstruction
{
    internal sealed record Construction(MethodDef Constructor, IReadOnlyList<long> Arguments, int Identity);
    internal sealed record Entry(string Name, TypeDef Type, IReadOnlyDictionary<FieldDef, long> Values)
    {
        internal Construction? Allocation { get; init; }
    }
    internal sealed record Snapshot(RecoveredResourceOrigin Source, FieldDef Table, IReadOnlyList<Entry> Entries, long Position)
    {
        internal IReadOnlyList<Entry> Publications { get; init; } = [];
        internal IReadOnlySet<FieldDef> PostConstructionFields { get; init; } = new HashSet<FieldDef>();
        internal bool CanMaterialize { get; init; }
    }

    internal static bool TryRead(MethodDef method, EmbeddedResource resource, out Snapshot? snapshot, out string reason)
    {
        snapshot = null;
        reason = "The index constructor does not have a closed input and publication shape.";
        if (!method.IsStatic || !method.HasBody || method.HasGenericParameters || method.DeclaringType.HasGenericParameters ||
            method.MethodSig.Params.Count != 1 || method.ReturnType.ElementType != ElementType.Void ||
            method.MethodSig.Params[0].ElementType != ElementType.Object && method.MethodSig.Params[0].FullName != "System.IO.Stream" ||
            resource.CreateReader().Length > 16 * 1024 * 1024) return false;
        var stores = method.Body.Instructions.Where(i => i.OpCode.Code == Code.Stsfld).ToArray();
        if (stores.Length != 1 || stores[0].Operand is not FieldDef table || !table.IsStatic ||
            table.DeclaringType != method.DeclaringType || table.FieldType.ToTypeDefOrRef() is not TypeRef tableType ||
            tableType.FullName != "System.Collections.Hashtable" || !Framework(tableType, method.Module)) return false;
        var position = method.Body.Instructions.IndexOf(stores[0]);
        while (position > 0 && method.Body.Instructions[position - 1].OpCode.Code == Code.Nop) position--;
        if (position == 0 || method.Body.Instructions[position - 1] is not { OpCode.Code: Code.Newobj, Operand: IMethod allocation } ||
            allocation.FullName != "System.Void System.Collections.Hashtable::.ctor()" ||
            allocation.DeclaringType is not TypeRef allocated || !Framework(allocated, method.Module)) return false;
        var region = method.Body.Instructions.Skip(position).Take(method.Body.Instructions.IndexOf(stores[0]) - position + 1).ToHashSet();
        if (method.Body.Instructions.Any(i => i.Operand is Instruction target && region.Contains(target) ||
            i.Operand is IList<Instruction> targets && targets.Any(region.Contains))) return false;
        if (!AssignedBeforeReads(method, table, stores[0])) return false;
        var constructors = new HashSet<MethodDef>();
        var fields = new HashSet<FieldDef>();
        var pending = new Stack<MethodDef>(); pending.Push(method);
        var seen = new HashSet<MethodDef>();
        while (pending.TryPop(out var current))
        {
            if (!seen.Add(current)) continue;
            reason = "Unsupported index construction in " + current.FullName;
            if (seen.Count > 32 || !current.HasBody || current.Body.HasExceptionHandlers ||
                current.Body.Variables.Count != 0 && !current.Body.InitLocals || current.Body.Instructions.Count > 4096) return false;
            foreach (var instruction in current.Body.Instructions)
            {
                if (instruction.OpCode.Code is Code.Ldsfld or Code.Stsfld)
                {
                    if (current != method || instruction.Operand is not IField f || f.ResolveFieldDef() != table) return false;
                    continue;
                }
                if (instruction.OpCode.Code == Code.Stfld)
                {
                    if (instruction.Operand is not FieldDef field || field.IsStatic || field.Module != method.Module ||
                        field.FieldType.ElementType is not (ElementType.I4 or ElementType.I8)) return false;
                    fields.Add(field); continue;
                }
                if (instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj)
                {
                    if (instruction.Operand is not IMethod called || called is MethodSpec) return false;
                    if (called.ResolveMethodDef() is { } local && local.Module == method.Module)
                    {
                        // Only fresh record allocation can enter module code. There
                        // are no callbacks, mutable static inputs or borrowed objects.
                        if (instruction.OpCode.Code != Code.Newobj || !local.IsInstanceConstructor || local.HasGenericParameters ||
                            local.DeclaringType.HasGenericParameters || local.DeclaringType.IsExplicitLayout ||
                            local.MethodSig.Params.Any(p => p.ElementType is not (ElementType.I4 or ElementType.I8)) ||
                            local.DeclaringType.BaseType is not TypeRef parent || parent.FullName != "System.Object" ||
                            !Framework(parent, method.Module) || local.DeclaringType.Methods.Any(m => m.Name == "Finalize" || m.HasOverrides) ||
                            local.DeclaringType.FindStaticConstructor() is { } initializer &&
                            (!initializer.HasBody || initializer.Body.HasExceptionHandlers || initializer.Body.Instructions.Any(i =>
                                i.OpCode.Code is not (Code.Nop or Code.Ret)))) return false;
                        constructors.Add(local); pending.Push(local);
                    }
                    else if (!AllowedCall(called, method.Module)) return false;
                    continue;
                }
                if (!Pure(instruction.OpCode.Code)) return false;
            }
        }
        if (constructors.Count == 0 || fields.Any(f => !constructors.Any(c => c.DeclaringType == f.DeclaringType))) return false;
        var readFailure = "The constructed table or record could not be read.";
        if (!Read(out var first) || !Read(out var second) || first is null || second is null)
        { reason = "Independent fixed-stream index construction did not complete: " + readFailure; return false; }
        if (first.Position != second.Position || first.Entries.Count != second.Entries.Count ||
            !first.Entries.Zip(second.Entries).All(pair => pair.First.Name == pair.Second.Name && pair.First.Type == pair.Second.Type &&
                pair.First.Values.Count == pair.Second.Values.Count && pair.First.Values.All(v =>
                    pair.Second.Values.TryGetValue(v.Key, out var value) && value == v.Value)))
        { reason = "Independent fixed-stream index constructions disagreed."; return false; }
        if (first.CanMaterialize != second.CanMaterialize || first.Publications.Count != second.Publications.Count ||
            !first.Publications.Zip(second.Publications).All(p => p.First.Name == p.Second.Name &&
                p.First.Allocation is { } a && p.Second.Allocation is { } b && a.Constructor == b.Constructor &&
                a.Identity == b.Identity && a.Arguments.SequenceEqual(b.Arguments)))
        { reason = "Independent construction/publication traces disagreed."; return false; }
        snapshot = first;
        reason = "Index construction is closed over the supplied resource bytes; caller and consumer ownership still require proof.";
        return true;

        bool Read(out Snapshot? result)
        {
            result = null;
            var published = new List<Entry>();
            var publicationFailed = false;
            var allocations = new Dictionary<StaticValue, (MethodDef Method, long[] Arguments)>();
            var identities = new Dictionary<StaticValue, int>();
            var tableStores = 0;
            // Evaluate the body only. The caller must preserve the real declaring
            // type's initialization; it is not a value input to this closed body.
            var machine = new StaticMachine(new StaticMachineLimits(MaximumSteps: 2_000_000),
                new PublicationIntrinsics(method.Module, (intrinsic, arguments) =>
                {
                    if (published.Count >= 256 || arguments.Count != 3 ||
                        !Capture(intrinsic.State.Heap, arguments[1], arguments[2], out var entry) || entry is null)
                        publicationFailed = true;
                    else published.Add(entry);
                }), modelTypeInitialization: false);
            machine.FrameEntered = (called, arguments) =>
            {
                if (!constructors.Contains(called)) return;
                if (arguments.Count != called.MethodSig.Params.Count + 1 || arguments[0].Kind != StaticValueKind.HeapReference ||
                    arguments.Skip(1).Select((a, n) => (a, n)).Any(p => p.a.Kind !=
                        (called.MethodSig.Params[p.n].ElementType == ElementType.I8 ? StaticValueKind.Int64 : StaticValueKind.Int32)) ||
                    allocations.ContainsKey(arguments[0]))
                { publicationFailed = true; return; }
                allocations.Add(arguments[0], (called, arguments.Skip(1).Select(a => a.AsInt64()).ToArray()));
            };
            machine.Stepped = (called, instruction) => { if (called == method && instruction == stores[0]) tableStores++; };
            machine.State.RegisterModuleMetadata(method.Module);
            machine.State.RegisterResource("Cilantro.IndexInput", resource.CreateReader().ToArray());
            if (!machine.State.TryOpenResource("Cilantro.IndexInput", out var stream)) return false;
            var execution = machine.Execute(method, [stream]);
            if (!execution.Succeeded || machine.State.RanOutOfBudget)
            { readFailure = execution.Diagnostic ?? execution.Status.ToString(); return false; }
            if (!machine.State.Heap.TryGetModelValue<Dictionary<StaticValue, StaticValue>>(machine.State.ReadStaticField(table), "Entries", out var entries) ||
                entries is null || entries.Count is 0 or > 64 ||
                !machine.State.Heap.TryGetModelValue<long>(stream, "Position", out var end)) return false;
            var output = new List<Entry>();
            foreach (var pair in entries)
            {
                if (!Capture(machine.State.Heap, pair.Key, pair.Value, out var entry) || entry is null) return false;
                output.Add(entry);
            }
            // An observer of the published table must never see a different
            // offset/mode while construction is still running. Also cover an
            // overwritten key or an earlier table that was subsequently replaced.
            if (publicationFailed || published.Count == 0 || published.Any(p => !output.Any(e => e.Name == p.Name && e.Type == p.Type &&
                e.Values.Count == p.Values.Count && e.Values.All(v => p.Values.TryGetValue(v.Key, out var value) && value == v.Value))))
            { readFailure = "An entry is incomplete or changes after publication."; return false; }
            result = new(RecoveredResourceOrigin.Capture(resource), table, output.OrderBy(e => e.Name, StringComparer.Ordinal).ToArray(), end)
            {
                Publications = published.ToArray(),
                PostConstructionFields = method.Body.Instructions.Where(i => i.OpCode.Code == Code.Stfld)
                    .Select(i => ((IField)i.Operand).ResolveFieldDef()).ToHashSet(),
                // No interned literal keys whose reference identity could differ
                // from a freshly decoded string. Pre-publication field edits are
                // retained using their validated values at each publication.
                CanMaterialize = tableStores == 1 &&
                    !seen.SelectMany(m => m.Body.Instructions).Any(i => i.OpCode.Code == Code.Ldstr)
            };
            return true;

            bool Capture(StaticHeap heap, StaticValue key, StaticValue value, out Entry? entry)
            {
                entry = null;
                if (!heap.TryGetString(key, out var name) || name.Length is 0 or > 4096 || !heap.TryGetObjectType(value, out var typeName)) return false;
                var type = constructors.Select(c => c.DeclaringType).Distinct().SingleOrDefault(t => t.FullName == typeName);
                if (type is null) return false;
                var values = new Dictionary<FieldDef, long>();
                foreach (var field in fields.Where(f => f.DeclaringType == type))
                {
                    if (!heap.TryReadAssignedField(value, field, out var stored) || stored.Kind is not (StaticValueKind.Int32 or StaticValueKind.Int64)) return false;
                    values.Add(field, stored.AsInt64());
                }
                if (!allocations.TryGetValue(value, out var allocation)) return false;
                if (!identities.TryGetValue(value, out var identity)) identities.Add(value, identity = identities.Count);
                entry = new(name, type, values) { Allocation = new(allocation.Method, allocation.Arguments, identity) }; return true;
            }
        }
    }

    private sealed class PublicationIntrinsics(ModuleDef module, Action<IntrinsicContext, IReadOnlyList<StaticValue>> observe) : IStaticIntrinsicRegistry
    {
        private readonly StaticIntrinsicRegistry defaults = StaticIntrinsicRegistry.CreateDefault();
        public bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic)
        {
            if (!defaults.TryResolve(method, out intrinsic)) return false;
            if (method.FullName == "System.Void System.Collections.Hashtable::set_Item(System.Object,System.Object)" &&
                method.DeclaringType is TypeRef type && Framework(type, module)) intrinsic = new Publication(intrinsic, observe);
            return true;
        }
    }

    private sealed class Publication(IStaticIntrinsic inner, Action<IntrinsicContext, IReadOnlyList<StaticValue>> observe) : IStaticIntrinsic
    {
        public bool Matches(IMethod method) => inner.Matches(method);
        public IntrinsicResult Invoke(IntrinsicContext context, IMethod method, IReadOnlyList<StaticValue> arguments)
        { observe(context, arguments); return inner.Invoke(context, method, arguments); }
    }

    private static bool AssignedBeforeReads(MethodDef method, FieldDef table, Instruction store)
    {
        if (method.Body.HasExceptionHandlers || method.Body.Instructions.Count == 0) return false;
        var cfg = ControlFlowGraph.Build(method);
        // Explore both assignment states. Any path to a read/return without the
        // unique fresh-table store refuses, even if a cold execution skips it.
        var pending = new Queue<(BasicBlock Block, bool Assigned)>(); pending.Enqueue((cfg.Entry, false));
        var seen = new HashSet<(BasicBlock, bool)>();
        while (pending.TryDequeue(out var item))
        {
            if (!seen.Add(item)) continue;
            var assigned = item.Assigned;
            foreach (var instruction in item.Block.Instructions)
            {
                if (instruction == store) assigned = true;
                if (!assigned && (instruction.OpCode.Code == Code.Ret || instruction.OpCode.Code == Code.Ldsfld &&
                    instruction.Operand is IField f && f.ResolveFieldDef() == table)) return false;
            }
            foreach (var edge in item.Block.Successors) pending.Enqueue((edge.Target, assigned));
        }
        return true;
    }

    private static bool Framework(TypeRef type, ModuleDef module) =>
        DependencyFrameworkScope.Matches(type, module);

    private static bool AllowedCall(IMethod called, ModuleDef module) => called.MethodSig is { HasThis: true } &&
        called.MethodSig.ParamsAfterSentinel?.Count is not > 0 && called.DeclaringType is TypeRef type && Framework(type, module) &&
        called.FullName is "System.Void System.Object::.ctor()" or
        "System.Void System.IO.BinaryReader::.ctor(System.IO.Stream)" or
        "System.Int64 System.IO.BinaryReader::ReadInt64()" or "System.Int32 System.IO.BinaryReader::ReadInt32()" or
        "System.String System.IO.BinaryReader::ReadString()" or
        "System.Int64 System.IO.Stream::Seek(System.Int64,System.IO.SeekOrigin)" or
        "System.Void System.Collections.Hashtable::.ctor()" or
        "System.Void System.Collections.Hashtable::set_Item(System.Object,System.Object)" or
        "System.Int32 System.String::get_Length()" or "System.Char System.String::get_Chars(System.Int32)" or
        "System.Char[] System.String::ToCharArray()" or
        "System.Void System.String::.ctor(System.Char[])";

    private static bool Pure(Code code) => code is
        Code.Nop or Code.Ret or Code.Ldnull or Code.Ldstr or Code.Dup or Code.Pop or
        Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0 or Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3 or
        Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3 or
        Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3 or
        Code.Ldc_I4 or Code.Ldc_I4_S or Code.Ldc_I4_M1 or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2 or
        Code.Ldc_I4_3 or Code.Ldc_I4_4 or Code.Ldc_I4_5 or Code.Ldc_I4_6 or Code.Ldc_I4_7 or Code.Ldc_I4_8 or Code.Ldc_I8 or
        Code.Add or Code.Sub or Code.Xor or Code.Conv_I4 or Code.Conv_I8 or Code.Conv_U2 or
        Code.Br or Code.Br_S or Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S or
        Code.Beq or Code.Beq_S or Code.Bne_Un or Code.Bne_Un_S or Code.Bge or Code.Bge_S or Code.Bgt or Code.Bgt_S or
        Code.Ble or Code.Ble_S or Code.Blt or Code.Blt_S or Code.Switch or
        Code.Newarr or Code.Ldlen or Code.Castclass or Code.Ldelem_U2 or Code.Stelem_I2;
}
