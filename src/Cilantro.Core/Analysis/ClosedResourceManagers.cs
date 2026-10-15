using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Bounds generated ResourceManager access without changing application resource loading.</summary>
internal static class ClosedResourceManagers
{
    internal sealed record Result(IReadOnlySet<Instruction> Accesses, IReadOnlySet<string> ReservedNames);

    internal static Result Find(ModuleDef module)
    {
        var methods = module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        var getters = new Dictionary<MethodDef, FieldDef>();
        var accesses = new HashSet<Instruction>();
        foreach (var method in methods)
        {
            if (!TryGetter(method, out var field, out var expression) || field is null) continue;
            var writes = methods.SelectMany(m => m.Body.Instructions).Where(i => i.Operand is IField f && f.ResolveFieldDef() == field &&
                i.OpCode.Code is Code.Stsfld or Code.Ldsflda).ToArray();
            if (writes.Length != 1 || writes[0].OpCode.Code != Code.Stsfld || !expression.Contains(writes[0])) continue;
            getters.Add(method, field); accesses.UnionWith(expression);
        }
        if (getters.Count == 0) return new(accesses, new HashSet<string>(StringComparer.Ordinal));
        var fields = getters.Values.ToHashSet();
        foreach (var method in methods)
        {
            if (!method.Body.Instructions.Any(i => i.OpCode.Code == Code.Ldsfld && i.Operand is IField f &&
                    f.ResolveFieldDef() is { } field && fields.Contains(field) ||
                    i.OpCode.Code == Code.Call && i.Operand is MethodDef getter && getters.ContainsKey(getter))) continue;
            var addressed = method.Body.Instructions.Where(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S)
                .Select(i => i.GetLocal(method.Body.Variables)).ToHashSet();
            foreach (var block in ControlFlowGraph.Build(method).Blocks)
            {
                var stack = new List<bool>();
                var locals = new Dictionary<Local, bool>();
                foreach (var instruction in block.Instructions)
                {
                    if (instruction.OpCode.Code == Code.Nop) continue;
                    if (instruction.IsLdloc())
                    {
                        var local = instruction.GetLocal(method.Body.Variables);
                        stack.Add(local is not null && !addressed.Contains(local) && locals.GetValueOrDefault(local)); continue;
                    }
                    if (instruction.OpCode.Code == Code.Dup)
                    { if (stack.Count != 0) stack.Add(stack[^1]); else stack.Clear(); continue; }
                    instruction.CalculateStackUsage(out var pushes, out var pops);
                    if (pops < 0 || pops > stack.Count) { stack.Clear(); locals.Clear(); continue; }
                    var receiver = pops != 0 && stack[stack.Count - pops];
                    var top = pops != 0 && stack[^1];
                    stack.RemoveRange(stack.Count - pops, pops);
                    if (instruction.IsStloc() && instruction.GetLocal(method.Body.Variables) is { } stored)
                    { locals[stored] = !addressed.Contains(stored) && top; continue; }
                    var manager = instruction.OpCode.Code == Code.Ldsfld && instruction.Operand is IField reference &&
                        reference.ResolveFieldDef() is { } definition && fields.Contains(definition);
                    if (instruction.OpCode.Code == Code.Call && instruction.Operand is MethodDef getter && getters.ContainsKey(getter))
                    { manager = true; accesses.Add(instruction); }
                    if (instruction.OpCode.Code == Code.Castclass && top && instruction.Operand is TypeRef cast &&
                        FrameworkType(module, cast) && cast.FullName is "System.Resources.ResourceManager" or "System.Object") manager = true;
                    if (receiver && instruction.OpCode.Code == Code.Callvirt && instruction.Operand is IMethod call &&
                        call.DeclaringType is TypeRef owner && FrameworkType(module, owner) && call.FullName is
                        "System.Object System.Resources.ResourceManager::GetObject(System.String,System.Globalization.CultureInfo)" or
                        "System.Object System.Resources.ResourceManager::GetObject(System.String)" or
                        "System.String System.Resources.ResourceManager::GetString(System.String,System.Globalization.CultureInfo)" or
                        "System.String System.Resources.ResourceManager::GetString(System.String)" or
                        "System.IO.UnmanagedMemoryStream System.Resources.ResourceManager::GetStream(System.String,System.Globalization.CultureInfo)" or
                        "System.IO.UnmanagedMemoryStream System.Resources.ResourceManager::GetStream(System.String)")
                        accesses.Add(instruction);
                    for (var n = 0; n < pushes; n++) stack.Add(manager);
                }
            }
        }
        // A framework ResourceManager's manifest-resource names end in .resources,
        // including culture variants. Retain the entire family, case-insensitively,
        // rather than guessing which CultureInfo or IgnoreCase setting will be used.
        var reserved = accesses.Count == 0 ? new HashSet<string>(StringComparer.Ordinal) : module.Resources
            .Where(r => r.Name.String.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
            .Select(r => r.Name.String).ToHashSet(StringComparer.Ordinal);
        return new(accesses, reserved);
    }

    private static bool TryGetter(MethodDef method, out FieldDef? field, out HashSet<Instruction> expression)
    {
        field = null; expression = [];
        if (!method.IsStatic || method.HasGenericParameters || method.MethodSig.Params.Count != 0 ||
            method.Body.ExceptionHandlers.Count != 0 ||
            method.ReturnType.ToTypeDefOrRef() is not TypeRef resultType || !FrameworkType(method.Module, resultType) ||
            resultType.FullName != "System.Resources.ResourceManager") return false;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Length > 64) return false;
        var stores = il.Where(i => i.OpCode.Code == Code.Stsfld).ToArray();
        if (stores.Length != 1 || stores[0].Operand is not IField target || target.ResolveFieldDef() is not { IsStatic: true, IsPrivate: true } cache ||
            cache.Module != method.Module || cache.FieldType.ToTypeDefOrRef() is not TypeRef cacheType ||
            !FrameworkType(method.Module, cacheType) || cacheType.FullName != resultType.FullName) return false;
        var end = Array.IndexOf(il, stores[0]);
        var start = end - 5;
        if (end >= 3 && il[end - 3].OpCode.Code == Code.Castclass) start--;
        if (start < 0) return false;
        var at = start;
        if (il[at].OpCode.Code != Code.Ldstr || il[at++].Operand is not string ||
            il[at].OpCode.Code != Code.Ldtoken || il[at++].Operand is not TypeDef own || own.Module != method.Module ||
            !Framework(il[at++], Code.Call, "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)")) return false;
        if (at < end && il[at].OpCode.Code == Code.Castclass)
        {
            if (il[at++].Operand is not TypeRef type || !FrameworkType(method.Module, type) || type.FullName != "System.Type") return false;
        }
        if (at + 2 != end || !Framework(il[at++], Code.Callvirt, "System.Reflection.Assembly System.Type::get_Assembly()") ||
            !Framework(il[at++], Code.Newobj, "System.Void System.Resources.ResourceManager::.ctor(System.String,System.Reflection.Assembly)")) return false;
        var graph = ControlFlowGraph.Build(method);
        if (graph.BlockOf(il[start]) != graph.BlockOf(stores[0])) return false;
        expression.UnionWith(il.Skip(start).Take(end - start + 1));
        foreach (var instruction in il)
        {
            if (expression.Contains(instruction)) continue;
            if (instruction.OpCode.Code == Code.Ldsfld && instruction.Operand is IField read && read.ResolveFieldDef() == cache) continue;
            if (instruction.OpCode.Code is Code.Br or Code.Br_S or Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S or Code.Ret) continue;
            return false;
        }
        field = cache; return true;

        bool Framework(Instruction instruction, Code code, string signature) => instruction.OpCode.Code == code &&
            instruction.Operand is IMethod call && call.FullName == signature && call.DeclaringType is TypeRef type && FrameworkType(method.Module, type);
    }

    private static bool FrameworkType(ModuleDef module, TypeRef type) =>
        type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
}
