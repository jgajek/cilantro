using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Closed caller/field provenance for reflection rooted in loaded application bytes.</summary>
internal static class LoadedAssemblyFlow
{
    private enum Value { Unknown, Null, Assembly, Type, Method, Types, Methods, Parameters, Parameter, MetadataType, RuntimeAssembly, RuntimeAssemblies }
    private sealed record Frame(Value[] Locals, Value[] Stack);
    private sealed record Body(ControlFlowGraph Graph, HashSet<Local> Addressed, HashSet<Parameter> Changed);

    internal static IReadOnlySet<Instruction> Find(ModuleDef module)
    {
        var methods = module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody && m.Body.Instructions.Count != 0).ToArray();
        var instructions = methods.SelectMany(m => m.Body.Instructions).ToArray();
        if (!instructions.Any(i => IsByteLoad(i) || IsRuntimeAssemblies(i))) return new HashSet<Instruction>();
        var names = instructions.Select(i => i.Operand).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var exposed = ModuleReachability.Compute(module).ReflectivelyExposedTypes.ToHashSet();
        var closed = methods.Where(m => m.Parameters.Any(p => !p.IsHiddenThisParameter && Kind(p.Type) != Value.Unknown) &&
            !m.IsVirtual && !m.HasGenericParameters && !m.DeclaringType.HasGenericParameters &&
            !MemberVisibility.IsExternallyVisible(m) && !exposed.Contains(m.DeclaringType) &&
            !names.Contains(m.Name.String) && !names.Contains(m.FullName)).ToHashSet();
        var fields = module.GetTypes().SelectMany(t => t.Fields).Where(f => f.IsPrivate && !f.DeclaringType.HasGenericParameters &&
            !exposed.Contains(f.DeclaringType) && !names.Contains(f.Name.String) && !names.Contains(f.FullName) && Kind(f.FieldType) != Value.Unknown).ToHashSet();
        foreach (var instruction in instructions)
        {
            if (instruction.Operand is IMethod reference && reference.ResolveMethodDef() is { } target &&
                (reference != target || instruction.OpCode.Code is not (Code.Call or Code.Callvirt))) closed.Remove(target);
            if (instruction.Operand is IField field && field.ResolveFieldDef() is { } definition &&
                (field != definition || instruction.OpCode.Code is not (Code.Ldfld or Code.Ldsfld or Code.Stfld or Code.Stsfld))) fields.Remove(definition);
        }
        foreach (var reference in module.GetMemberRefs())
        {
            if (reference.IsMethodRef && reference.ResolveMethodDef() is { } method) closed.Remove(method);
            if (reference.IsFieldRef && reference.ResolveFieldDef() is { } field) fields.Remove(field);
        }
        var callers = closed.ToDictionary(m => m, _ => new List<Instruction>());
        var writers = fields.ToDictionary(f => f, _ => new List<Instruction>());
        foreach (var instruction in instructions)
        {
            if (instruction.Operand is MethodDef method && callers.TryGetValue(method, out var calls) &&
                instruction.OpCode.Code is Code.Call or Code.Callvirt) calls.Add(instruction);
            if (instruction.Operand is FieldDef field && writers.TryGetValue(field, out var writes) &&
                instruction.OpCode.Code is Code.Stfld or Code.Stsfld) writes.Add(instruction);
        }
        var relevant = methods.Where(m => Kind(m.ReturnType) != Value.Unknown || m.Parameters.Any(p => Kind(p.Type) != Value.Unknown) ||
            m.Body.Instructions.Any(i => i.Operand is IMethod call && (Kind(call.MethodSig?.RetType) != Value.Unknown ||
                call.MethodSig?.Params.Any(p => Kind(p) != Value.Unknown) == true || call.DeclaringType.FullName == "System.Reflection.MethodBase") ||
                i.Operand is IField field && Kind(field.FieldSig?.Type) != Value.Unknown)).ToArray();
        var bodies = relevant.ToDictionary(m => m, m => new Body(ControlFlowGraph.Build(m),
            m.Body.Instructions.Where(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S).Select(i => i.GetLocal(m.Body.Variables)).OfType<Local>().ToHashSet(),
            m.Body.Instructions.Where(i => i.OpCode.Code is Code.Ldarga or Code.Ldarga_S or Code.Starg or Code.Starg_S)
                .Select(i => i.Operand).OfType<Parameter>().ToHashSet()));
        var arguments = new Dictionary<Parameter, Value>();
        var stored = new Dictionary<FieldDef, Value>();
        var returns = new Dictionary<MethodDef, Value>();
        var localValues = new Dictionary<Local, Value>();
        var localWriters = bodies.Where(p => p.Key.Body.InitLocals).SelectMany(p => p.Key.Body.Variables
            .Where(v => Kind(v.Type) != Value.Unknown && !p.Value.Addressed.Contains(v))
            .Select(v => (Local: v, Stores: p.Key.Body.Instructions.Where(i => i.IsStloc() && i.GetLocal(p.Key.Body.Variables) == v).ToArray())))
            .ToArray();
        var accesses = new HashSet<Instruction>();
        // Facts only become known after every syntactic writer/caller/return agrees. An
        // unknown recursive dependency never certifies itself; each round adds facts.
        while (true)
        {
            var count = arguments.Count + stored.Count + returns.Count + localValues.Count;
            var inputs = new Dictionary<Instruction, Value[]>();
            accesses.Clear();
            foreach (var (method, body) in bodies) Analyze(method, body, inputs, accesses);
            // A directly constructed LINQ predicate receives runtime-array elements,
            // including potentially this assembly. This certifies metadata queries
            // only; it never grants loaded-payload provenance to the predicate.
            var predicateSites = new Dictionary<MethodDef, HashSet<Instruction>>();
            foreach (var (method, body) in bodies)
            foreach (var block in body.Graph.Blocks)
            {
                var code = block.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                for (var at = 2; at < code.Length; at++)
                {
                    if (!(IsRuntimeFirst(code[at]) || IsRuntimeFirst(code[at], any: true)) || !inputs.TryGetValue(code[at], out var values) || values.Length != 2 || values[0] != Value.RuntimeAssemblies ||
                        code[at - 2].OpCode.Code != Code.Ldftn || code[at - 2].Operand is not MethodDef predicate ||
                        !ClosedPredicate(predicate) || !PredicateConstructor(code[at - 1])) continue;
                    if (!predicateSites.TryGetValue(predicate, out var sites)) predicateSites.Add(predicate, sites = []);
                    sites.Add(code[at - 2]);
                }
            }
            foreach (var (method, body) in bodies)
            {
                var code = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                for (var at = 0; at + 10 < code.Length; at++)
                {
                    var read = code[at]; var store = code[at + 9]; var call = code[at + 10];
                    if (read.OpCode.Code != Code.Ldsfld || read.Operand is not FieldDef cache || !cache.IsStatic || cache.HasFieldRVA || cache.HasConstant ||
                        MemberVisibility.IsExternallyVisible(cache.DeclaringType) && (cache.IsPublic || cache.IsFamily || cache.IsFamilyOrAssembly) ||
                        exposed.Contains(cache.DeclaringType) || names.Contains(cache.Name.String) || names.Contains(cache.FullName) ||
                        code[at + 1].OpCode.Code != Code.Dup || code[at + 2].OpCode.Code is not (Code.Brfalse or Code.Brfalse_S) || code[at + 2].Operand != code[at + 4] ||
                        code[at + 3].OpCode.Code is not (Code.Br or Code.Br_S) || code[at + 3].Operand != call || code[at + 4].OpCode.Code != Code.Pop ||
                        code[at + 6].OpCode.Code != Code.Ldftn || code[at + 6].Operand is not MethodDef predicate || !ClosedPredicate(predicate) ||
                        !PredicateConstructor(code[at + 7]) || code[at + 8].OpCode.Code != Code.Dup || store.OpCode.Code != Code.Stsfld || store.Operand != cache ||
                        !(IsRuntimeFirst(call) || IsRuntimeFirst(call, any: true)) || !inputs.TryGetValue(call, out var values) || values.Length != 2 || values[0] != Value.RuntimeAssemblies ||
                        body.Graph.BlockOf(code[at + 6]) != body.Graph.BlockOf(store) ||
                        !Enumerable.Range(at, 11).All(index => body.Graph.HaveIdenticalExceptionRegions(read, code[index])) ||
                        module.GetMemberRefs().Any(r => r.IsFieldRef && r.ResolveFieldDef() == cache) ||
                        instructions.Any(i => i.Operand is IField field && field.ResolveFieldDef() == cache && i != read && i != store)) continue;
                    if (!predicateSites.TryGetValue(predicate, out var sites)) predicateSites.Add(predicate, sites = []);
                    sites.Add(code[at + 6]);
                }
            }
            foreach (var (predicate, sites) in predicateSites)
            {
                var parameter = predicate.Parameters[predicate.HasThis ? 1 : 0];
                if (arguments.ContainsKey(parameter) || bodies[predicate].Changed.Contains(parameter) ||
                    module.GetMemberRefs().Any(reference => reference.IsMethodRef && reference.ResolveMethodDef() == predicate) ||
                    instructions.Any(i => i.Operand is IMethod reference && reference.ResolveMethodDef() == predicate && !sites.Contains(i))) continue;
                arguments.Add(parameter, Value.RuntimeAssembly);
            }
            foreach (var method in closed)
            foreach (var parameter in method.Parameters.Where(p => !p.IsHiddenThisParameter && Kind(p.Type) != Value.Unknown))
                if (!arguments.ContainsKey(parameter) && !bodies[method].Changed.Contains(parameter) && callers[method].Count != 0 &&
                    Agree(callers[method].Select(i => inputs.TryGetValue(i, out var values) && parameter.Index < values.Length ? values[parameter.Index] : Value.Unknown)) is { } value && Compatible(value, Kind(parameter.Type)))
                    arguments.Add(parameter, value);
            foreach (var field in fields)
                if (!stored.ContainsKey(field) && writers[field].Count != 0 &&
                    Agree(writers[field].Select(i => inputs.TryGetValue(i, out var values) && values.Length != 0 ? values[^1] : Value.Unknown)) is { } value && Compatible(value, Kind(field.FieldType)))
                    stored.Add(field, value);
            // An initialized reference local starts as null. If every syntactic store
            // is loaded-origin (or null), that invariant also holds at handler entry
            // and across leave/finally edges. Addressed, mixed and circular sources
            // never acquire a fact. Do not infer mutable-array provenance here.
            foreach (var (local, stores) in localWriters)
                if (!localValues.ContainsKey(local) && Agree(stores.Select(i =>
                        inputs.TryGetValue(i, out var values) && values.Length == 1 ? values[0] : Value.Unknown)) is { } value && Compatible(value, Kind(local.Type)))
                    localValues.Add(local, value);
            foreach (var method in relevant.Where(m => !m.IsVirtual && !m.HasGenericParameters && !m.DeclaringType.HasGenericParameters && Kind(m.ReturnType) != Value.Unknown))
                if (!returns.ContainsKey(method) && Agree(method.Body.Instructions.Where(i => i.OpCode.Code == Code.Ret)
                        .Select(i => inputs.TryGetValue(i, out var values) && values.Length == 1 ? values[0] : Value.Unknown)) is { } value && Compatible(value, Kind(method.ReturnType)))
                    returns.Add(method, value);
            if (count == arguments.Count + stored.Count + returns.Count + localValues.Count) return accesses;
        }

        void Analyze(MethodDef method, Body body, Dictionary<Instruction, Value[]> inputs, HashSet<Instruction> proven)
        {
            var states = new Dictionary<BasicBlock, Frame>();
            var queue = new Queue<BasicBlock>();
            Send(body.Graph.Entry, Empty(0));
            foreach (var handler in method.Body.ExceptionHandlers)
            {
                if (handler.FilterStart is { } filter) Send(body.Graph.BlockOf(filter), Empty(1));
                if (handler.HandlerStart is { } start) Send(body.Graph.BlockOf(start), Empty(handler.HandlerType is ExceptionHandlerType.Catch or ExceptionHandlerType.Filter ? 1 : 0));
            }
            while (queue.TryDequeue(out var block))
            {
                var output = Run(block, states[block], false);
                if (output is null) continue;
                foreach (var edge in block.Successors.Where(e => e.Kind != ControlFlowEdgeKind.Exception))
                    Send(edge.Target, block.Last.OpCode.Code is Code.Leave or Code.Leave_S ||
                        !body.Graph.HaveIdenticalExceptionRegions(block.Last, edge.Target.First) ? Empty(0) : output);
            }
            foreach (var (block, state) in states) Run(block, state, true);

            Frame Empty(int stackSize) => new(method.Body.Variables.Select(v => localValues.GetValueOrDefault(v)).ToArray(), new Value[stackSize]);
            void Send(BasicBlock block, Frame frame)
            {
                if (states.TryGetValue(block, out var old))
                {
                    // Invalid stack merges are not a source of provenance.
                    if (old.Stack.Length != frame.Stack.Length) frame = Empty(Math.Max(old.Stack.Length, frame.Stack.Length));
                    var joined = new Frame(old.Locals.Zip(frame.Locals, Join).ToArray(), old.Stack.Length == frame.Stack.Length
                        ? old.Stack.Zip(frame.Stack, Join).ToArray() : frame.Stack);
                    if (old.Locals.SequenceEqual(joined.Locals) && old.Stack.SequenceEqual(joined.Stack)) return;
                    frame = joined;
                }
                states[block] = frame;
                queue.Enqueue(block);
            }
            Frame? Run(BasicBlock block, Frame frame, bool record)
            {
                var locals = frame.Locals.ToArray(); var stack = frame.Stack.ToList();
                foreach (var instruction in block.Instructions)
                {
                    if (stack.Count > 256) return null;
                    if (instruction.OpCode.Code == Code.Nop) continue;
                    if (instruction.OpCode.Code == Code.Dup) { stack.Add(stack.Count == 0 ? Value.Unknown : stack[^1]); continue; }
                    if (instruction.IsLdloc())
                    {
                        var local = instruction.GetLocal(method.Body.Variables);
                        stack.Add(local is not null && !body.Addressed.Contains(local) ? locals[local.Index] : Value.Unknown); continue;
                    }
                    if (instruction.IsLdarg())
                    {
                        var parameter = instruction.GetParameter(method.Parameters);
                        stack.Add(parameter is not null && !body.Changed.Contains(parameter) ? arguments.GetValueOrDefault(parameter) : Value.Unknown); continue;
                    }
                    instruction.CalculateStackUsage(out var pushes, out var pops);
                    if (instruction.OpCode.Code == Code.Ret) pops = method.ReturnType.ElementType == ElementType.Void ? 0 : 1;
                    if (pops < 0 || pops > stack.Count) { stack.Clear(); Array.Fill(locals, Value.Unknown); continue; }
                    var values = stack.Skip(stack.Count - pops).ToArray();
                    if (record) inputs[instruction] = values;
                    var top = values.LastOrDefault(); var receiver = values.FirstOrDefault();
                    stack.RemoveRange(stack.Count - pops, pops);
                    // Framework reflection arrays are mutable. Once an array escapes or
                    // an element/address is written, forget every local/stack alias. No
                    // array provenance is inferred through fields, arguments or returns.
                    if (values.Any(IsArray) &&
                        !(instruction.IsStloc() && instruction.GetLocal(method.Body.Variables) is { } destination && !body.Addressed.Contains(destination)) &&
                        instruction.OpCode.Code is not (Code.Ldelem_Ref or Code.Ldlen or Code.Pop or Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S))
                    {
                        for (var n = 0; n < locals.Length; n++) if (IsArray(locals[n])) locals[n] = Value.Unknown;
                        for (var n = 0; n < stack.Count; n++) if (IsArray(stack[n])) stack[n] = Value.Unknown;
                    }
                    if (instruction.IsStloc() && instruction.GetLocal(method.Body.Variables) is { } target)
                    { locals[target.Index] = body.Addressed.Contains(target) ? Value.Unknown : top; continue; }
                    var value = Value.Unknown;
                    if (instruction.OpCode.Code == Code.Ldnull) value = Value.Null;
                    if (instruction.OpCode.Code is Code.Ldfld or Code.Ldsfld && instruction.Operand is FieldDef field) value = stored.GetValueOrDefault(field);
                    if (instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is MethodDef call && !call.IsVirtual) value = returns.GetValueOrDefault(call);
                    if (IsByteLoad(instruction)) value = Value.Assembly;
                    if (IsRuntimeAssemblies(instruction)) value = Value.RuntimeAssemblies;
                    if (receiver == Value.RuntimeAssemblies && IsRuntimeFirst(instruction)) value = Value.RuntimeAssembly;
                    if (receiver == Value.Assembly && (Framework(instruction, "System.Type System.Reflection.Assembly::GetType(System.String)") ||
                        Framework(instruction, "System.Type System.Reflection.Assembly::GetType(System.String,System.Boolean)") ||
                        Framework(instruction, "System.Type System.Reflection.Assembly::GetType(System.String,System.Boolean,System.Boolean)")))
                    { value = Value.Type; if (record) proven.Add(instruction); }
                    if (receiver == Value.Type && (Framework(instruction, "System.Reflection.MethodInfo System.Type::GetMethod(System.String)") ||
                        Framework(instruction, "System.Reflection.MethodInfo System.Type::GetMethod(System.String,System.Type[])") ||
                        Framework(instruction, "System.Reflection.MethodInfo System.Type::GetMethod(System.String,System.Reflection.BindingFlags)")))
                    { value = Value.Method; if (record) proven.Add(instruction); }
                    if (receiver == Value.Method && Framework(instruction, "System.Object System.Reflection.MethodBase::Invoke(System.Object,System.Object[])") && record) proven.Add(instruction);
                    if (receiver == Value.Type && Framework(instruction, "System.Object System.Activator::CreateInstance(System.Type)") && record) proven.Add(instruction);
                    if (receiver == Value.Assembly && Framework(instruction, "System.Reflection.MethodInfo System.Reflection.Assembly::get_EntryPoint()"))
                    { value = Value.Method; if (record) proven.Add(instruction); }
                    if (receiver is Value.Assembly or Value.RuntimeAssembly && Framework(instruction, "System.String System.Reflection.Assembly::get_FullName()") && record) proven.Add(instruction);
                    if (receiver == Value.Assembly && (Framework(instruction, "System.Type[] System.Reflection.Assembly::GetTypes()") ||
                        Framework(instruction, "System.Type[] System.Reflection.Assembly::GetExportedTypes()")))
                    { value = Value.Types; if (record) proven.Add(instruction); }
                    if (receiver == Value.Type && (Framework(instruction, "System.Reflection.MethodInfo[] System.Type::GetMethods()") ||
                        Framework(instruction, "System.Reflection.MethodInfo[] System.Type::GetMethods(System.Reflection.BindingFlags)")))
                    { value = Value.Methods; if (record) proven.Add(instruction); }
                    if (receiver == Value.Method && Framework(instruction, "System.Reflection.ParameterInfo[] System.Reflection.MethodBase::GetParameters()"))
                    { value = Value.Parameters; if (record) proven.Add(instruction); }
                    if (instruction.OpCode.Code == Code.Ldelem_Ref)
                        value = receiver == Value.Types ? Value.Type : receiver == Value.Methods ? Value.Method : receiver == Value.Parameters ? Value.Parameter :
                            receiver == Value.RuntimeAssemblies ? Value.RuntimeAssembly : Value.Unknown;
                    // Attribute construction is an application invocation, like MethodBase.Invoke.
                    // Only members traced to loaded application bytes qualify; its returned
                    // objects do not inherit assembly provenance.
                    if (receiver is Value.Type or Value.Method && Framework(instruction, "System.Object[] System.Reflection.MemberInfo::GetCustomAttributes(System.Boolean)") && record) proven.Add(instruction);
                    if (Framework(instruction, "System.Type System.Object::GetType()")) value = Value.MetadataType;
                    if (receiver == Value.Parameter && Framework(instruction, "System.Type System.Reflection.ParameterInfo::get_ParameterType()"))
                    { value = Value.MetadataType; if (record) proven.Add(instruction); }
                    if (receiver is Value.Type or Value.MetadataType or Value.Method && Framework(instruction, "System.String System.Reflection.MemberInfo::get_Name()") && record) proven.Add(instruction);
                    if (values.Length == 2 &&
                        (values.All(v => v is Value.Type or Value.Null) && (Framework(instruction, "System.Boolean System.Type::op_Equality(System.Type,System.Type)") ||
                            Framework(instruction, "System.Boolean System.Type::op_Inequality(System.Type,System.Type)")) ||
                         values.All(v => v is Value.Method or Value.Null) && (Framework(instruction, "System.Boolean System.Reflection.MethodInfo::op_Equality(System.Reflection.MethodInfo,System.Reflection.MethodInfo)") ||
                            Framework(instruction, "System.Boolean System.Reflection.MethodInfo::op_Inequality(System.Reflection.MethodInfo,System.Reflection.MethodInfo)")) ||
                         values.All(v => v is Value.Assembly or Value.RuntimeAssembly or Value.Null) && (Framework(instruction, "System.Boolean System.Reflection.Assembly::op_Equality(System.Reflection.Assembly,System.Reflection.Assembly)") ||
                            Framework(instruction, "System.Boolean System.Reflection.Assembly::op_Inequality(System.Reflection.Assembly,System.Reflection.Assembly)"))) && record) proven.Add(instruction);
                    if (instruction.OpCode.Code == Code.Castclass && instruction.Operand is TypeRef cast &&
                        cast.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName &&
                        (cast.FullName == "System.Object" || Compatible(top, Kind(cast.ToTypeSig())) ||
                         top == Value.Parameter && cast.FullName == "System.Reflection.ParameterInfo" ||
                         top == Value.MetadataType && cast.FullName == "System.Type" ||
                         top is Value.Type or Value.MetadataType or Value.Method && cast.FullName == "System.Reflection.MemberInfo")) value = top;
                    for (var n = 0; n < pushes; n++) stack.Add(value);
                }
                return new(locals, stack.ToArray());
            }
        }
        bool Framework(Instruction instruction, string name) => instruction.OpCode.Code is Code.Call or Code.Callvirt &&
            instruction.Operand is IMethod call && call.FullName == name && call.DeclaringType is TypeRef type &&
            type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
        bool IsByteLoad(Instruction instruction) => Framework(instruction, "System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[])") ||
            Framework(instruction, "System.Reflection.Assembly System.AppDomain::Load(System.Byte[])");
        bool IsRuntimeAssemblies(Instruction instruction) => Framework(instruction, "System.Reflection.Assembly[] System.AppDomain::GetAssemblies()");
        bool ClosedPredicate(MethodDef predicate) => predicate.HasBody && !predicate.IsVirtual && !predicate.HasGenericParameters &&
            !predicate.DeclaringType.HasGenericParameters && predicate.MethodSig.Params.Count == 1 && Kind(predicate.MethodSig.Params[0]) == Value.Assembly &&
            predicate.ReturnType.ElementType == ElementType.Boolean && !MemberVisibility.IsExternallyVisible(predicate) && !exposed.Contains(predicate.DeclaringType) &&
            !names.Contains(predicate.Name.String) && !names.Contains(predicate.FullName);
        bool PredicateConstructor(Instruction instruction) => instruction.OpCode.Code == Code.Newobj && instruction.Operand is IMethod constructor &&
            constructor.Name == ".ctor" && constructor.DeclaringType.ToTypeSig() is GenericInstSig { GenericArguments.Count: 2 } signature &&
            CoreGeneric(signature, "System.Func`2") && Kind(signature.GenericArguments[0]) == Value.Assembly && signature.GenericArguments[1].ElementType == ElementType.Boolean;
        bool IsRuntimeFirst(Instruction instruction, bool any = false)
        {
            if (instruction.OpCode.Code != Code.Call || instruction.Operand is not MethodSpec call ||
                call.Name != (any ? "Any" : "FirstOrDefault") || call.GenericInstMethodSig?.GenericArguments is not { Count: 1 } arguments ||
                Kind(arguments[0]) != Value.Assembly || call.DeclaringType is not TypeRef owner || owner.FullName != "System.Linq.Enumerable" ||
                owner.DefinitionAssembly is not { } assembly ||
                !((assembly.Name == "System.Core" && assembly.PublicKeyOrToken?.Token.ToString() == "b77a5c561934e089") ||
                  (assembly.Name == "System.Linq" && assembly.PublicKeyOrToken?.Token.ToString() == "b03f5f7f11d50a3a")) ||
                call.Method.MethodSig is not { HasThis: false, GenParamCount: 1 } signature ||
                !(any ? signature.RetType.ElementType == ElementType.Boolean : signature.RetType is GenericMVar { Number: 0 }) ||
                signature.Params.Count is not (1 or 2) ||
                signature.Params[0] is not GenericInstSig { GenericArguments.Count: 1 } sequence ||
                !CoreGeneric(sequence, "System.Collections.Generic.IEnumerable`1") || sequence.GenericArguments[0] is not GenericMVar { Number: 0 }) return false;
            // Exclude the overload whose second argument is a caller-supplied default
            // value: it can return an arbitrary custom Assembly implementation.
            return signature.Params.Count == 1 || signature.Params[1] is GenericInstSig { GenericArguments.Count: 2 } predicate &&
                CoreGeneric(predicate, "System.Func`2") && predicate.GenericArguments[0] is GenericMVar { Number: 0 } &&
                predicate.GenericArguments[1].ElementType == ElementType.Boolean;
        }
        bool CoreGeneric(GenericInstSig signature, string name) => signature.GenericType.TypeDefOrRef is TypeRef type &&
            type.FullName == name && type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
        Value Kind(TypeSig? signature) => signature?.ToTypeDefOrRef() is TypeRef type &&
            type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName ? type.FullName switch
            { "System.Reflection.Assembly" => Value.Assembly, "System.Type" => Value.Type, "System.Reflection.MethodInfo" or "System.Reflection.MethodBase" => Value.Method, _ => Value.Unknown } : Value.Unknown;
    }

    private static bool Compatible(Value value, Value kind) => value == kind || value == Value.RuntimeAssembly && kind == Value.Assembly;
    private static Value Join(Value a, Value b) => a == b ? a : a == Value.Null ? b : b == Value.Null ? a :
        a is Value.Assembly or Value.RuntimeAssembly && b is Value.Assembly or Value.RuntimeAssembly ? Value.RuntimeAssembly : Value.Unknown;
    private static bool IsArray(Value value) => value is Value.Types or Value.Methods or Value.Parameters or Value.RuntimeAssemblies;
    private static Value? Agree(IEnumerable<Value> values)
    {
        var all = values.ToArray();
        if (all.Length == 0 || all.Contains(Value.Unknown)) return null;
        var value = all.Aggregate(Join);
        return value is Value.Unknown or Value.Null ? null : value;
    }
}
