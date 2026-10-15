using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Recognizes injected, unused singleton-guard storage and its paired accessors.</summary>
internal static class ReactorGuardHelpers
{
    internal sealed record Pair(FieldDef Field, MethodDef Getter, MethodDef Test);

    internal static IReadOnlyList<MethodDef> FindConstantMethods(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete ||
            !context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var reactor) || reactor?.IsReactor != true) return [];
        var literals = context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions).Where(i => i.OpCode.Code == Code.Ldstr)
            .Select(i => (string)i.Operand).ToHashSet(StringComparer.Ordinal);
        var result = new List<MethodDef>();
        foreach (var owner in context.Module.GetTypes().Where(t => t.IsValueType && t.HasGenericParameters))
        {
            // Reactor emits a field-free variant on generic value types: a null
            // getter paired with a true predicate. Recognition only attributes
            // declarations; ordinary reachability/reference checks still decide removal.
            var methods = owner.Methods.Where(m => m.IsStatic && !m.IsConstructor && !m.IsVirtual && !m.HasGenericParameters &&
                m.HasBody && m.MethodSig.Params.Count == 0 && m.Body.ExceptionHandlers.Count == 0 &&
                !MemberVisibility.IsExternallyVisible(m) && !literals.Contains(m.Name.String) && !literals.Contains(m.FullName)).ToArray();
            var getters = methods.Where(m => m.ReturnType.ElementType == ElementType.Object && Shape(m, Code.Ldnull, Code.Ret)).ToArray();
            var tests = methods.Where(m => m.ReturnType.ElementType == ElementType.Boolean && True(m)).ToArray();
            if (getters.Length != 1 || tests.Length != 1) continue;
            string[] names = [getters[0].Name.String, tests[0].Name.String];
            if (names[0].Length < 16 || names[0].Length != names[1].Length ||
                !(names.All(ReactorNameHeuristics.IsGeneratedName) || MatchesGeneratedFamily(names))) continue;
            result.Add(getters[0]); result.Add(tests[0]);
        }
        return result;

        static bool True(MethodDef method)
        {
            var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            return il.Length == 2 && il[0].IsLdcI4() && il[0].GetLdcI4Value() == 1 && il[1].OpCode.Code == Code.Ret;
        }
    }

    internal static int CompleteCalls(ArtifactContext context)
    {
        var pairs = Find(context).Where(p => !p.Field.DeclaringType.IsBeforeFieldInit &&
            // The dedicated pool pass proves and retires the entire initializer.
            // Adding a self type-handle here prevents that closed-pool proof.
            !ReactorGuardPool.IsOrdinaryPool(p.Field.DeclaringType) &&
            !p.Field.DeclaringType.HasGenericParameters && !p.Field.DeclaringType.IsGlobalModuleType &&
            p.Field.DeclaringType.FindStaticConstructor() is { HasBody: true }).ToArray();
        if (pairs.Length == 0) return 0;
        var exposure = ModuleReachability.Compute(context.Module);
        var getters = pairs.Where(p => !exposure.IsReflectivelyExposed(p.Field.DeclaringType))
            .SelectMany(p => new[] { (Method: p.Getter, IsTest: false), (Method: p.Test, IsTest: true) })
            .ToDictionary(p => p.Method, p => p.IsTest);
        if (getters.Count == 0) return 0;
        var identity = ArtifactIdentitySnapshot.Capture(context.Module);
        var structure = ArtifactStructuralSnapshot.Capture(context.Module);
        using var edit = new BodyMutationBatch();
        var changed = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody && !m.IsConstructor))
        {
            var il = method.Body.Instructions;
            ControlFlowGraph? graph = null;
            for (var n = 0; n + 1 < il.Count; n++)
            {
                if (il[n].OpCode.Code != Code.Call || il[n].Operand is not IMethod invoked || invoked is MethodSpec ||
                    invoked.ResolveMethodDef() is not { } called || !new SigComparer().Equals(invoked.MethodSig, called.MethodSig) ||
                    !getters.ContainsKey(called) || called.DeclaringType != method.DeclaringType ||
                    il[n + 1].OpCode.Code is not (Code.Pop or Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S) ||
                    n > 0 && il[n - 1].OpCode.OpCodeType == OpCodeType.Prefix) continue;
                graph ??= ControlFlowGraph.Build(method);
                if (graph.BlockOf(il[n]) != graph.BlockOf(il[n + 1])) continue;
                edit.Capture(method);
                // The closed, unwritten field read always contributes null.
                // Preserve the original static call's precise initializer
                // trigger, including a throwing or recursively entered initializer.
                var helpers = context.Module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers");
                var handle = new ValueTypeSig(context.Module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"));
                var ensure = new MemberRefUser(context.Module, "RunClassConstructor",
                    MethodSig.CreateStatic(context.Module.CorLibTypes.Void, handle), helpers);
                var consumer = il[n + 1];
                il[n].OpCode = OpCodes.Ldtoken; il[n].Operand = called.DeclaringType;
                if (consumer.OpCode.Code == Code.Pop)
                { consumer.OpCode = OpCodes.Call; consumer.Operand = ensure; }
                else
                {
                    // Keep the original branch and EH topology. The dedicated
                    // control-flow pass can simplify the now-explicit null later.
                    il.Insert(n + 1, OpCodes.Call.ToInstruction(ensure));
                    il.Insert(n + 2, getters[called] ? OpCodes.Ldc_I4_1.ToInstruction() : OpCodes.Ldnull.ToInstruction());
                }
                method.Body.SimplifyBranches();
                edit.RecordChange(context, new("runtime-cleanup", "retire-reactor-guard-call", method.FullName,
                    "Replaced a closed guard with its explicit type-initialization trigger and proven null/true value; preserved the original control-flow edges."));
                changed++;
            }
        }
        // This operation changes only instructions, so compare against its own
        // input declarations without permitting any metadata changes.
        if (changed == 0) return 0;
        var verification = AssemblyVerifier.Verify(context.Module, identity, structure);
        if (!verification.Passed)
        {
            context.SetFact("guard.calls.rollback", string.Join("; ", verification.Diagnostics));
            return 0;
        }
        edit.Commit();
        return changed;
    }

    internal static IReadOnlyList<Pair> Find(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete ||
            !context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var reactor) || reactor?.IsReactor != true) return [];
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var names = methods.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions)
            .Where(i => i.OpCode.Code == Code.Ldstr).Select(i => i.Operand).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var fieldUses = methods.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions
                .Where(i => i.Operand is IField).Select(i => (Method: m, Instruction: i, Field: ((IField)i.Operand).ResolveFieldDef())))
            .ToArray();
        var unresolvedNames = fieldUses.Where(p => p.Field is null).Select(p => ((IField)p.Instruction.Operand).Name.String)
            .Concat(context.Module.GetMemberRefs().Where(r => r.IsFieldRef && r.ResolveFieldDef() is null).Select(r => r.Name.String))
            .ToHashSet(StringComparer.Ordinal);
        var uses = fieldUses.Where(p => p.Field is not null).ToLookup(p => p.Field!);
        var pairs = new List<Pair>();
        foreach (var field in context.Module.GetTypes().SelectMany(t => t.Fields))
        {
            // Earlier type recovery can specialize Object storage to the owner's
            // reference type. This is the same injected pair, not a foreign singleton.
            if (!field.IsStatic || field.IsLiteral || field.HasFieldRVA || field.HasConstant || field.CustomAttributes.Count != 0 ||
                !(field.FieldType.ElementType == ElementType.Object ||
                  !field.DeclaringType.IsValueType && new SigComparer().Equals(field.FieldType, field.DeclaringType.ToTypeSig())) ||
                !(field.IsPrivate || field.IsAssembly) ||
                unresolvedNames.Contains(field.Name.String) ||
                names.Contains(field.Name.String) || names.Contains(field.FullName)) continue;
            var references = uses[field].ToArray();
            if (references.Length != 2 || references.Any(p => p.Instruction.OpCode.Code != Code.Ldsfld)) continue;
            var accessors = references.Select(p => p.Method).Distinct().ToArray();
            if (accessors.Length != 2 || accessors.Any(m => m.DeclaringType != field.DeclaringType || !m.IsStatic || m.IsConstructor ||
                m.IsVirtual || m.HasGenericParameters || m.MethodSig.Params.Count != 0 || m.Body.ExceptionHandlers.Count != 0 ||
                MemberVisibility.IsExternallyVisible(m) || names.Contains(m.Name.String) || names.Contains(m.FullName))) continue;
            // Reactor's generic-owner and value-type variants return Object, avoiding a closed
            // owner instantiation in the accessor signature. Every field use
            // across instantiations must still resolve into the same two reads.
            var getter = accessors.FirstOrDefault(m => (m.ReturnType.ToTypeDefOrRef()?.ResolveTypeDef() == field.DeclaringType ||
                (field.DeclaringType.HasGenericParameters || field.DeclaringType.IsValueType) && m.ReturnType.ElementType == ElementType.Object) &&
                (Shape(m, Code.Ldsfld, Code.Ret) ||
                 Shape(m, Code.Ldsfld, Code.Pop, Code.Ldnull, Code.Ret)));
            var test = accessors.FirstOrDefault(m => m.ReturnType.ElementType == ElementType.Boolean &&
                Shape(m, Code.Ldsfld, Code.Ldnull, Code.Ceq, Code.Ret));
            if (getter is not null && test is not null &&
                ((ReactorNameHeuristics.IsGeneratedName(getter.Name.String) && ReactorNameHeuristics.IsGeneratedName(test.Name.String)) ||
                 MatchesAccessorNameFamily(field, getter, test)) &&
                (ReactorNameHeuristics.IsGeneratedName(field.Name.String) || IsStaticGeneratedOwner(field) ||
                 MatchesGeneratedNameFamily(field, getter, test) || MatchesAccessorNameFamily(field, getter, test))) pairs.Add(new(field, getter, test));
        }
        return pairs;
    }

    private static bool Shape(MethodDef method, params Code[] codes) =>
        method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).Select(i => i.OpCode.Code).SequenceEqual(codes);

    private static bool MatchesAccessorNameFamily(FieldDef field, MethodDef getter, MethodDef test)
        => MatchesGeneratedFamily([field.Name.String, getter.Name.String, test.Name.String]);

    private static bool MatchesGeneratedFamily(string[] names)
    {
        // Correlated generated names corroborate all supported paired storage forms.
        return names[0].Length >= 16 && names.All(name => name.Length == names[0].Length &&
            name.All(char.IsAsciiLetterOrDigit) && name.Any(char.IsAsciiLetterUpper) && name.Any(char.IsAsciiLetterLower) &&
            (name.Any(char.IsAsciiDigit) || name.Zip(name.Skip(1)).Any(pair => char.IsAsciiLetterUpper(pair.First) && char.IsAsciiLetterUpper(pair.Second)))) &&
            names.Any(name => name.Any(char.IsAsciiDigit)) &&
            (names.Any(ReactorNameHeuristics.IsGeneratedName) ||
             names.All(name => name.Any(char.IsAsciiDigit) && name.Distinct().Count() >= 10));
    }

    // Random generated identifiers can have low character-class churn by chance.
    // For the already-proven paired shape, two independently generated accessor
    // names of the same length corroborate a long mixed-alphabet storage name.
    private static bool MatchesGeneratedNameFamily(FieldDef field, MethodDef getter, MethodDef test)
    {
        var name = field.Name.String;
        return ReactorNameHeuristics.IsGeneratedName(field.DeclaringType.Name.String) &&
            name.Length >= 16 && getter.Name.String.Length == name.Length && test.Name.String.Length == name.Length &&
            name.All(char.IsAsciiLetterOrDigit) && name.Any(char.IsAsciiLetterUpper) &&
            name.Any(char.IsAsciiLetterLower) && name.Any(char.IsAsciiDigit);
    }

    // A static class cannot have an application singleton instance of its own
    // type. The paired generated accessors and closed unwritten storage checks
    // above still apply; this only replaces the field-name entropy heuristic.
    private static bool IsStaticGeneratedOwner(FieldDef field)
    {
        var owner = field.DeclaringType;
        return field.IsPrivate && owner.IsAbstract && owner.IsSealed &&
            ReactorNameHeuristics.IsGeneratedName(owner.Name.String) &&
            owner.Fields.All(f => f.IsStatic) && owner.Methods.All(m => m.IsStatic);
    }
}
