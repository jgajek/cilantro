using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Proves that a static callback's handles stay in closed, typed delegate invocation paths.</summary>
internal static class ClosedDelegateParameterTypes
{
    internal static IReadOnlyDictionary<MethodDef, TypeSig[]> Find(ModuleDef module,
        IReadOnlySet<MethodDef> candidates, IReadOnlySet<TypeDef> exposed)
    {
        var methods = module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody && m.Body.Instructions.Count != 0).ToArray();
        var references = methods.SelectMany(m => m.Body.Instructions.Where(i => i.Operand is IMethod)
            .Select(i => (Method: m, Instruction: i, Target: ((IMethod)i.Operand).ResolveMethodDef()))).ToLookup(r => r.Target);
        var fieldUsers = methods.SelectMany(m => m.Body.Instructions.Select(i => i.Operand).OfType<IField>()
            .Select(f => (Method: m, Field: f.ResolveFieldDef()))).ToLookup(r => r.Field);
        var graphs = new Dictionary<MethodDef, ControlFlowGraph>();
        ControlFlowGraph Graph(MethodDef method)
        {
            if (!graphs.TryGetValue(method, out var graph)) graphs[method] = graph = ControlFlowGraph.Build(method);
            return graph;
        }
        var result = new Dictionary<MethodDef, TypeSig[]>();
        foreach (var target in candidates.Where(m => m.IsStatic && !m.HasGenericParameters))
        {
            var uses = references[target].ToArray();
            if (uses.Length == 0 || uses.Any(u => u.Instruction.OpCode.Code != Code.Ldftn)) continue;
            TypeSig? delegateType = null;
            TypeSig[]? parameters = null;
            var seeds = new HashSet<Instruction>();
            var valid = true;
            foreach (var use in uses)
            {
                var block = Graph(use.Method).BlockOf(use.Instruction).Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                var at = Array.IndexOf(block, use.Instruction);
                if (at < 1 || at + 1 >= block.Length || block[at - 1].OpCode.Code != Code.Ldnull ||
                    block[at + 1].OpCode.Code != Code.Newobj || block[at + 1].Operand is not IMethod ctor ||
                    !Binding(ctor, target, out var supplied) || delegateType is not null &&
                    !new SigComparer().Equals(delegateType, ctor.DeclaringType.ToTypeSig())) { valid = false; break; }
                delegateType = ctor.DeclaringType.ToTypeSig();
                parameters = supplied;
                seeds.Add(block[at + 1]);
            }
            if (!valid || delegateType is null || parameters is null) continue;
            var fields = new HashSet<FieldDef>();
            var arguments = new HashSet<Parameter>();
            var locals = new HashSet<Local>();
            var scopes = new Dictionary<MethodDef, Dictionary<(bool Method, uint Number), TypeSig>>();
            var queue = new Queue<MethodDef>(uses.Select(u => u.Method).Distinct());
            var pending = queue.ToHashSet();
            var steps = 0;
            void Enqueue(MethodDef method) { if (pending.Add(method)) queue.Enqueue(method); }
            Interpretation.GenericScope Scope(MethodDef method)
            {
                scopes.TryGetValue(method, out var bindings);
                return new Interpretation.GenericScope(
                    method.DeclaringType.GenericParameters.Select(p => bindings?.GetValueOrDefault((false, (uint)p.Number)) ?? new GenericVar(p.Number)).ToArray(),
                    method.GenericParameters.Select(p => bindings?.GetValueOrDefault((true, (uint)p.Number)) ?? new GenericMVar(p.Number)).ToArray());
            }
            bool Constrain(MethodDef method, TypeSig destination)
            {
                // Object storage can carry this delegate without changing its identity.
                if (destination.ElementType == ElementType.Object) return true;
                bool Unify(TypeSig left, TypeSig right)
                {
                    left = Scope(method).Bind(left)!;
                    if (new SigComparer().Equals(left, right)) return true;
                    if (left is GenericVar or GenericMVar && !right.ContainsGenericParameter)
                    {
                        var variable = (GenericSig)left;
                        if (variable.Number >= (left is GenericMVar ? method.GenericParameters.Count : method.DeclaringType.GenericParameters.Count)) return false;
                        if (!scopes.TryGetValue(method, out var bindings)) scopes[method] = bindings = [];
                        bindings[(left is GenericMVar, variable.Number)] = right;
                        Enqueue(method);
                        return true;
                    }
                    if (left is GenericInstSig a && right is GenericInstSig b &&
                        new SigComparer().Equals(a.GenericType, b.GenericType) && a.GenericArguments.Count == b.GenericArguments.Count)
                        return a.GenericArguments.Zip(b.GenericArguments).All(p => Unify(p.First, p.Second));
                    return false;
                }
                return Unify(destination, delegateType);
            }
            while (valid && queue.TryDequeue(out var method))
            {
                pending.Remove(method);
                if (++steps > 4096) { valid = false; break; }
                foreach (var block in Graph(method).Blocks)
                {
                    var stack = new List<bool>();
                    foreach (var instruction in block.Instructions)
                    {
                        var code = instruction.OpCode.Code;
                        if (code == Code.Nop) continue;
                        if (code == Code.Dup) { stack.Add(stack.Count != 0 && stack[^1]); continue; }
                        instruction.CalculateStackUsage(out var pushes, out var pops);
                        if (pops < 0)
                        {
                            if (stack.Any(v => v)) { valid = false; break; }
                            stack.Clear(); continue;
                        }
                        // Unknown incoming stack entries are unmarked; a marked value crossing
                        // a block boundary is rejected below, so it cannot disappear here.
                        var inputs = new bool[pops];
                        for (var n = pops - 1; n >= 0; n--)
                            if (stack.Count != 0) { inputs[n] = stack[^1]; stack.RemoveAt(stack.Count - 1); }
                        var marked = inputs.Any(v => v);
                        var output = seeds.Contains(instruction);
                        if (instruction.IsLdarg()) output |= arguments.Contains(instruction.GetParameter(method.Parameters));
                        if (instruction.IsLdloc()) output |= locals.Contains(instruction.GetLocal(method.Body.Variables));
                        if (code is Code.Ldarga or Code.Ldarga_S && instruction.Operand is Parameter address && arguments.Contains(address) ||
                            code is Code.Ldloca or Code.Ldloca_S && instruction.Operand is Local localAddress && locals.Contains(localAddress)) { valid = false; break; }
                        if (instruction.Operand is IField fieldRef && fieldRef.ResolveFieldDef() is { } field)
                        {
                            if (fields.Contains(field) && code is not (Code.Ldfld or Code.Ldsfld or Code.Stfld or Code.Stsfld)) { valid = false; break; }
                            var fieldType = fieldRef.DeclaringType.ToTypeSig() is GenericInstSig fieldOwner
                                ? new Interpretation.GenericScope(fieldOwner.GenericArguments, null).Bind(fieldRef.FieldSig.Type)!
                                : fieldRef.FieldSig.Type;
                            if (code is Code.Ldfld or Code.Ldsfld && fields.Contains(field))
                            {
                                if (!Constrain(method, fieldType)) { valid = false; break; }
                                output = true;
                            }
                            if (marked && code is Code.Stfld or Code.Stsfld && inputs[^1] &&
                                (inputs.Length == 1 || !inputs[0]))
                            {
                                if (field.Module != module || !HasClosedFieldBoundary(field) || exposed.Contains(field.DeclaringType) || !Constrain(method, fieldType)) { valid = false; break; }
                                if (fields.Add(field)) foreach (var user in fieldUsers[field]) Enqueue(user.Method);
                                marked = false;
                            }
                        }
                        if (marked && instruction.IsStloc() && instruction.GetLocal(method.Body.Variables) is { } local)
                        {
                            if (!Constrain(method, local.Type)) { valid = false; break; }
                            if (locals.Add(local)) Enqueue(method);
                            marked = false;
                        }
                        if (marked && code is Code.Starg or Code.Starg_S && instruction.Operand is Parameter assigned)
                        {
                            if (!Constrain(method, assigned.Type)) { valid = false; break; }
                            if (arguments.Add(assigned)) Enqueue(method);
                            marked = false;
                        }
                        if (marked && code is Code.Call or Code.Callvirt or Code.Newobj && instruction.Operand is IMethod called)
                        {
                            if (code == Code.Callvirt && inputs.Length > 0 && inputs[0] && inputs.Skip(1).All(v => !v) &&
                                IsInvoke(called, delegateType, parameters.Length, Scope(method))) marked = false;
                            else if (code is Code.Call or Code.Callvirt && FrameworkConsumer(called, delegateType, inputs, Scope(method))) marked = false;
                            else if (code == Code.Call && ClosedWhereJoin(block.Instructions, instruction, called, delegateType, inputs, Scope(method))) marked = false;
                            else if (called.ResolveMethodDef() is { HasBody: true, IsVirtual: false } callee && callee.Module == module &&
                                callee.Body.Instructions.Count != 0 && called.MethodSig is { } signature &&
                                inputs.Length == signature.Params.Count + (code != Code.Newobj && signature.HasThis ? 1 : 0))
                            {
                                var offset = code == Code.Newobj ? 1 : 0;
                                for (var n = 0; n < inputs.Length; n++)
                                    if (inputs[n])
                                    {
                                        if (n + offset >= callee.Parameters.Count || callee.Parameters[n + offset].IsHiddenThisParameter) { valid = false; break; }
                                        var parameter = callee.Parameters[n + offset];
                                        var suppliedType = Interpretation.GenericScope.For(called, null)?.Bind(parameter.Type) ?? parameter.Type;
                                        if (!Constrain(method, suppliedType) || !Constrain(callee, parameter.Type)) { valid = false; break; }
                                        if (arguments.Add(parameter)) Enqueue(callee);
                                    }
                                marked = false;
                            }
                        }
                        // Null tests, discards and identity comparisons do not expose a delegate.
                        if (marked && code is Code.Pop or Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S or Code.Ceq) marked = false;
                        if (marked) { valid = false; break; }
                        for (var n = 0; n < pushes; n++) stack.Add(output);
                    }
                    if (!valid || stack.Any(v => v)) { valid = false; break; }
                }
            }
            if (valid) result[target] = parameters;
        }
        return result;
    }

    private static bool ClosedWhereJoin(IReadOnlyList<Instruction> instructions, Instruction instruction, IMethod called,
        TypeSig bound, bool[] inputs, Interpretation.GenericScope current)
    {
        // Where retains its predicate in an iterator. Only accept a same-block,
        // immediate String.Join consumer: the iterator cannot be stored or exposed.
        // Reference source: System.Core/System/Linq/Enumerable.cs and mscorlib/system/string.cs.
        if (inputs.Length != 2 || inputs[0] || !inputs[1] || called is not MethodSpec where ||
            where.Name != "Where" || where.GenericInstMethodSig?.GenericArguments is not { Count: 1 } types ||
            current.Bind(types[0])?.ElementType != ElementType.String ||
            where.DeclaringType is not TypeRef owner || owner.FullName != "System.Linq.Enumerable" ||
            owner.DefinitionAssembly is not { } assembly ||
            !((assembly.Name == "System.Core" && assembly.PublicKeyOrToken?.Token.ToString() == "b77a5c561934e089") ||
              (assembly.Name == "System.Linq" && assembly.PublicKeyOrToken?.Token.ToString() == "b03f5f7f11d50a3a")) ||
            where.Method.MethodSig is not { HasThis: false, ExplicitThis: false, GenParamCount: 1, Params.Count: 2 } signature ||
            (signature.CallingConvention & CallingConvention.Mask) != CallingConvention.Default || !signature.Generic ||
            signature.ParamsAfterSentinel?.Count is > 0) return false;
        var module = called.Module;
        var sequence = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "IEnumerable`1")), module.CorLibTypes.String);
        var predicate = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System", "Func`2")), module.CorLibTypes.String, module.CorLibTypes.Boolean);
        var scope = Interpretation.GenericScope.For(where, null);
        TypeSig? Resolve(TypeSig type) => current.Bind(scope?.Bind(type) ?? type);
        var comparer = new SigComparer();
        if (!comparer.Equals(bound, predicate) || !comparer.Equals(Resolve(signature.Params[0]), sequence) ||
            !comparer.Equals(Resolve(signature.Params[1]), predicate) || !comparer.Equals(Resolve(signature.RetType), sequence)) return false;
        var at = 0;
        while (at < instructions.Count && instructions[at] != instruction) at++;
        at++;
        while (at < instructions.Count && instructions[at].OpCode.Code == Code.Nop) at++;
        return at < instructions.Count && instructions[at].OpCode.Code == Code.Call &&
            instructions[at].Operand is IMethod join && join is not MethodSpec && join.Name == "Join" &&
            join.DeclaringType is TypeRef joinOwner && joinOwner.FullName == "System.String" &&
            joinOwner.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName &&
            join.MethodSig is { HasThis: false, Params.Count: 2 } joinSignature && OrdinarySignature(joinSignature) &&
            comparer.Equals(joinSignature.RetType, module.CorLibTypes.String) &&
            comparer.Equals(joinSignature.Params[0], module.CorLibTypes.String) && comparer.Equals(joinSignature.Params[1], sequence);
    }
    private static bool HasClosedFieldBoundary(FieldDef field)
    {
        if (field.IsPrivate) return true;
        // Compiler-generated closures commonly publish fields inside a private
        // nested type. Reflection and every CIL use are checked separately.
        for (var owner = field.DeclaringType; owner is not null; owner = owner.DeclaringType)
            if (owner.IsNestedPrivate) return true;
        // Recovery preserves the analyzed application, not hypothetical calls from
        // absent friend assemblies. InternalsVisibleTo alone is not a delegate
        // escape: all observed field uses, reflection exposure and invocation
        // signatures still have to pass the flow proof above.
        return field.IsAssembly || field.IsFamilyAndAssembly ||
            !MemberVisibility.IsExternallyVisible(field.DeclaringType);
    }
    private static bool Binding(IMethod ctor, MethodDef target, out TypeSig[] parameters)
    {
        parameters = [];
        if (ctor is MethodSpec || ctor.Name != ".ctor" || ctor.MethodSig is not { HasThis: true, Params.Count: 2 } cs ||
            !OrdinarySignature(cs) || cs.RetType.ElementType != ElementType.Void || cs.Params[0].ElementType != ElementType.Object ||
            cs.Params[1].ElementType != ElementType.I || ctor.DeclaringType.ToTypeSig().ContainsGenericParameter ||
            !DelegateSignature(ctor.DeclaringType.ToTypeSig(), target.Module, out parameters, out var returns)) return false;
        if (ctor.DeclaringType.ResolveTypeDef() is { } type && type.Module == target.Module &&
            ctor.ResolveMethodDef() is not { IsRuntime: true, IsConstructor: true, IsStatic: false }) return false;
        if (!OrdinarySignature(target.MethodSig) || parameters.Length != target.MethodSig.Params.Count ||
            !new SigComparer().Equals(returns, target.ReturnType)) return false;
        for (var n = 0; n < parameters.Length; n++)
        {
            var original = target.MethodSig.Params[n];
            if (new SigComparer().Equals(original, parameters[n])) continue;
            if (original.ElementType != ElementType.Object || parameters[n].IsValueType || parameters[n].ContainsGenericParameter ||
                parameters[n].ElementType is ElementType.ByRef or ElementType.Ptr or ElementType.FnPtr or ElementType.TypedByRef) return false;
        }
        return true;
    }

    private static bool DelegateSignature(TypeSig signature, ModuleDef module, out TypeSig[] parameters, out TypeSig returns)
    {
        parameters = [];
        returns = module.CorLibTypes.Void;
        if (signature is GenericInstSig generic && generic.GenericType.TypeDefOrRef is TypeRef reference &&
            reference.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName)
        {
            if (reference.FullName == "System.Action`" + generic.GenericArguments.Count && generic.GenericArguments.Count is >= 1 and <= 16)
                parameters = generic.GenericArguments.ToArray();
            else if (reference.FullName == "System.Comparison`1" && generic.GenericArguments.Count == 1)
            { parameters = [generic.GenericArguments[0], generic.GenericArguments[0]]; returns = module.CorLibTypes.Int32; }
            else if (reference.FullName == "System.Func`" + generic.GenericArguments.Count && generic.GenericArguments.Count is >= 2 and <= 17)
            { parameters = generic.GenericArguments.SkipLast(1).ToArray(); returns = generic.GenericArguments[^1]; }
            else return false;
            return true;
        }
        if (signature.ToTypeDefOrRef()?.ResolveTypeDef() is not { IsSealed: true, HasGenericParameters: false } type ||
            type.Module != module || type.BaseType is not TypeRef parent || parent.FullName != "System.MulticastDelegate" ||
            parent.DefinitionAssembly?.FullName != module.CorLibTypes.AssemblyRef.FullName) return false;
        var invokes = type.Methods.Where(m => m.Name == "Invoke").ToArray();
        if (invokes.Length != 1 || invokes[0] is not { IsRuntime: true, IsVirtual: true, IsNewSlot: true, IsStatic: false, HasGenericParameters: false } invoke ||
            !OrdinarySignature(invoke.MethodSig)) return false;
        parameters = invoke.MethodSig.Params.ToArray(); returns = invoke.ReturnType;
        return true;
    }

    private static bool OrdinarySignature(MethodSig signature) =>
        (signature.CallingConvention & CallingConvention.Mask) == CallingConvention.Default && !signature.ExplicitThis &&
        !signature.Generic && signature.ParamsAfterSentinel?.Count is not > 0;

    private static bool FrameworkConsumer(IMethod call, TypeSig bound, bool[] inputs, Interpretation.GenericScope current)
    {
        if (call is MethodSpec || call.MethodSig is not { HasThis: true } signature || !OrdinarySignature(signature) ||
            inputs.Length != signature.Params.Count + 1 || !inputs[^1] || inputs.SkipLast(1).Any(v => v) ||
            current.Bind(call.DeclaringType.ToTypeSig()) is not GenericInstSig { ContainsGenericParameter: false } owner ||
            owner.GenericType.TypeDefOrRef is not TypeRef reference ||
            reference.DefinitionAssembly?.FullName != call.Module.CorLibTypes.AssemblyRef.FullName) return false;
        var scope = Interpretation.GenericScope.For(call, null);
        TypeSig Resolve(TypeSig type) => current.Bind(scope?.Bind(type) ?? type)!;
        TypeSig expected;
        // These exact framework overloads invoke the callback synchronously without
        // retaining the callback. Do not generalize to lazy consumers.
        // Reference source: mscorlib/system/collections/generic/list.cs (Sort)
        // and collections/Concurrent/ConcurrentDictionary.cs (GetOrAdd).
        if (reference.FullName == "System.Collections.Generic.List`1" && owner.GenericArguments.Count == 1 &&
            call.Name == "Sort" && signature.Params.Count == 1 && signature.RetType.ElementType == ElementType.Void)
            expected = new GenericInstSig(new ClassSig(call.Module.CorLibTypes.GetTypeRef("System", "Comparison`1")), owner.GenericArguments[0]);
        else if (reference.FullName == "System.Collections.Concurrent.ConcurrentDictionary`2" && owner.GenericArguments.Count == 2 &&
            call.Name == "GetOrAdd" && signature.Params.Count == 2 &&
            new SigComparer().Equals(Resolve(signature.Params[0]), owner.GenericArguments[0]) &&
            new SigComparer().Equals(Resolve(signature.RetType), owner.GenericArguments[1]))
            expected = new GenericInstSig(new ClassSig(call.Module.CorLibTypes.GetTypeRef("System", "Func`2")), owner.GenericArguments[0], owner.GenericArguments[1]);
        else return false;
        return new SigComparer().Equals(expected, bound) && new SigComparer().Equals(Resolve(signature.Params[^1]), expected);
    }
    private static bool IsInvoke(IMethod call, TypeSig bound, int count, Interpretation.GenericScope current)
    {
        if (call.Name != "Invoke" || call.MethodSig is not { HasThis: true } signature || signature.Params.Count != count ||
            call is MethodSpec || !OrdinarySignature(signature)) return false;
        var owner = current.Bind(call.DeclaringType.ToTypeSig())!;
        if (!new SigComparer().Equals(owner, bound)) return false;
        if (!DelegateSignature(owner, call.Module, out var expected, out var returns) || expected.Length != count) return false;
        var scope = Interpretation.GenericScope.For(call, null);
        return signature.Params.Select(p => current.Bind(scope?.Bind(p) ?? p)).Zip(expected).All(p => new SigComparer().Equals(p.First, p.Second)) &&
            new SigComparer().Equals(current.Bind(scope?.Bind(signature.RetType) ?? signature.RetType), returns);
    }
}
