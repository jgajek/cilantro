using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Proves storage/consumer closure for local DLR call sites. Binder argument
/// semantics and receiver behavior require separate proofs before any rewrite.</summary>
internal static class ClosedDynamicSiteStorage
{
    internal sealed record Site(FieldDef Field, Instruction Binder, IReadOnlyList<Instruction> Invocations);
    internal static IReadOnlyList<Site> Find(ModuleDef module, MethodDef method, IReadOnlySet<TypeDef> exposed)
    {
        var result = new List<Site>();
        if (!method.HasBody || method.Body.Instructions.Count == 0) return result;
        var flow = EvaluationStackOrigins.Analyze(method);
        if (!flow.Valid) return result;
        var all = module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        var uses = all.SelectMany(m => m.Body.Instructions.Where(i => i.Operand is IField)
            .Select(i => (Method: m, Instruction: i, Field: ((IField)i.Operand).ResolveFieldDef()))).ToLookup(x => x.Field);
        var names = all.SelectMany(m => m.Body.Instructions).Where(i => i.OpCode.Code == Code.Ldstr)
            .Select(i => (string)i.Operand).ToHashSet(StringComparer.Ordinal);
        var consumers = flow.Inputs.SelectMany(p => p.Value.SelectMany((slot, index) => slot.Where(i => i is not null)
            .Select(i => (Producer: i!, Consumer: p.Key, Slot: index)))).ToLookup(x => x.Producer);
        Instruction? Only(Instruction instruction, int slot) => flow.Inputs.TryGetValue(instruction, out var input) &&
            slot < input.Length && input[slot].Count == 1 ? input[slot].Single() : null;
        bool OnlyConsumer(Instruction producer, Instruction consumer, int slot) =>
            consumers[producer].Any() && consumers[producer].All(c => c.Consumer == consumer && c.Slot == slot);
        foreach (var field in method.Body.Instructions.Where(i => i.OpCode.Code == Code.Stsfld).Select(i =>
                     (i.Operand as IField)?.ResolveFieldDef()).OfType<FieldDef>().Distinct())
        {
            if (field.Module != module || !field.IsStatic || field.HasFieldRVA || field.HasConstant || field.HasCustomAttributes ||
                field.DeclaringType.HasGenericParameters || exposed.Contains(field.DeclaringType) ||
                names.Contains(field.Name.String) || names.Contains(field.FullName) ||
                MemberVisibility.IsExternallyVisible(field.DeclaringType) && (field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly) ||
                field.FieldSig.Type is not GenericInstSig { GenericArguments.Count: 1 } siteType ||
                !Framework(siteType.GenericType.TypeDefOrRef, "System.Runtime.CompilerServices.CallSite`1", "System.Core", "b77a5c561934e089")) continue;
            var references = uses[field].ToArray();
            var stores = references.Where(r => r.Instruction.OpCode.Code == Code.Stsfld).ToArray();
            if (stores.Length != 1 || references.Any(r => r.Method != method ||
                    r.Instruction.OpCode.Code is not (Code.Stsfld or Code.Ldsfld) || !flow.Inputs.ContainsKey(r.Instruction))) continue;
            var store = stores[0].Instruction;
            var create = Only(store, 0);
            if (create?.OpCode.Code != Code.Call || create.Operand is not IMethod factory || factory is MethodSpec || factory.Name != "Create" ||
                !new SigComparer().Equals(factory.DeclaringType.ToTypeSig(), siteType) ||
                factory.MethodSig is not { HasThis: false, ExplicitThis: false, GenParamCount: 0, Params.Count: 1, ParamsAfterSentinel: null } fs ||
                (fs.CallingConvention & CallingConvention.Mask) != CallingConvention.Default ||
                !Framework(fs.Params[0].ToTypeDefOrRef(), "System.Runtime.CompilerServices.CallSiteBinder", "System.Core", "b77a5c561934e089") ||
                !new SigComparer().Equals(new Interpretation.GenericScope(siteType.GenericArguments, null).Bind(fs.RetType), siteType) ||
                !OnlyConsumer(create, store, 0)) continue;
            var binder = Only(create, 0);
            if (binder?.OpCode.Code != Code.Call || binder.Operand is not IMethod binding || binding is MethodSpec ||
                !Framework(binding.DeclaringType, "Microsoft.CSharp.RuntimeBinder.Binder", "Microsoft.CSharp", "b03f5f7f11d50a3a") ||
                binding.MethodSig is not { HasThis: false, ExplicitThis: false, GenParamCount: 0, ParamsAfterSentinel: null } bs ||
                (bs.CallingConvention & CallingConvention.Mask) != CallingConvention.Default ||
                !new SigComparer().Equals(bs.RetType, fs.Params[0]) || !OnlyConsumer(binder, create, 0)) continue;
            var calls = new HashSet<Instruction>();
            bool SiteLoad(Instruction? instruction) => instruction?.OpCode.Code == Code.Ldsfld &&
                instruction.Operand is IField f && f.ResolveFieldDef() == field;
            bool Target(Instruction? instruction) => instruction?.OpCode.Code == Code.Ldfld &&
                instruction.Operand is IField f && f.Name == "Target" &&
                new SigComparer().Equals(f.DeclaringType.ToTypeSig(), siteType) &&
                new SigComparer().Equals(new Interpretation.GenericScope(siteType.GenericArguments, null).Bind(f.FieldSig.Type), siteType.GenericArguments[0]) &&
                SiteLoad(Only(instruction, 0));
            bool CoreDelegate(GenericInstSig type) => type.GenericType.TypeDefOrRef is TypeRef reference &&
                reference.FullName == "System.Func`" + type.GenericArguments.Count &&
                reference.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
            bool Invocation(Instruction instruction)
            {
                if (instruction.OpCode.Code != Code.Callvirt || instruction.Operand is not IMethod invoke || invoke is MethodSpec ||
                    invoke.Name != "Invoke" || !new SigComparer().Equals(invoke.DeclaringType.ToTypeSig(), siteType.GenericArguments[0]) ||
                    siteType.GenericArguments[0] is not GenericInstSig delegateType ||
                    delegateType.GenericArguments.Count < 2 ||
                    !CoreDelegate(delegateType) ||
                    !Framework(delegateType.GenericArguments[0].ToTypeDefOrRef(), "System.Runtime.CompilerServices.CallSite", "System.Core", "b77a5c561934e089") ||
                    invoke.MethodSig is not { HasThis: true, ExplicitThis: false, GenParamCount: 0, ParamsAfterSentinel: null } signature ||
                    signature.Params.Count != delegateType.GenericArguments.Count - 1 ||
                    (signature.CallingConvention & CallingConvention.Mask) != CallingConvention.Default ||
                    !Target(Only(instruction, 0)) || !SiteLoad(Only(instruction, 1))) return false;
                var scope = new Interpretation.GenericScope(delegateType.GenericArguments, null);
                if (!signature.Params.Select(scope.Bind).Zip(delegateType.GenericArguments).All(p => new SigComparer().Equals(p.First, p.Second)) ||
                    !new SigComparer().Equals(scope.Bind(signature.RetType), delegateType.GenericArguments[^1])) return false;
                calls.Add(instruction); return true;
            }
            var valid = true;
            foreach (var load in references.Where(r => r.Instruction.OpCode.Code == Code.Ldsfld).Select(r => r.Instruction))
            {
                if (!consumers[load].Any()) { valid = false; break; }
                foreach (var use in consumers[load])
                {
                    if (use.Slot == 0 && use.Consumer.OpCode.Code is Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S) continue;
                    if (use.Slot == 1 && Invocation(use.Consumer)) continue;
                    if (use.Slot == 0 && Target(use.Consumer) && consumers[use.Consumer].Any() &&
                        consumers[use.Consumer].All(c => c.Slot == 0 && Invocation(c.Consumer))) continue;
                    valid = false; break;
                }
                if (!valid) break;
            }
            if (valid && calls.Count != 0) result.Add(new(field, binder, calls.ToArray()));
        }
        return result;
    }
    private static bool Framework(ITypeDefOrRef? reference, string name, string assemblyName, string token) =>
        reference is TypeRef { ResolutionScope: AssemblyRef assembly } && reference.FullName == name &&
        assembly.Name == assemblyName && assembly.FullName.EndsWith(", PublicKeyToken=" + token, StringComparison.OrdinalIgnoreCase);
}
