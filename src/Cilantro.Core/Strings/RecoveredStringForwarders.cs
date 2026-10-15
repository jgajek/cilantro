using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Strings;

/// <summary>Exact forwarding declarations left behind by an atomic string rewrite.</summary>
internal static class RecoveredStringForwarders
{
    private const string Fact = "strings.completedForwarders";

    internal static void Remember(ArtifactContext context, IReadOnlyCollection<MethodDef> aliases)
    {
        context.TryGetFact<Dictionary<MethodDef, MethodDef>>(Fact, out var completed);
        completed ??= [];
        foreach (var method in aliases)
        {
            if (IsForwarder(method, aliases)) completed[method] = ((IMethod)method.Body.Instructions.Single(i => i.OpCode.Code == Code.Call).Operand).ResolveMethodDef()!;
        }
        context.SetFact(Fact, completed);
    }

    internal static HashSet<MethodDef> Candidates(ArtifactContext context)
    {
        if (!context.TryGetFact<Dictionary<MethodDef, MethodDef>>(Fact, out var completed) || completed is null)
            return [];
        // Explicit name uses may be reflective invocations, rather than enumeration
        // of deliberately removable protector metadata. Keep those declarations.
        var names = context.Module.GetTypes().SelectMany(t => t.Methods)
            .Where(m => m.HasBody).SelectMany(m => m.Body.Instructions)
            .Where(i => i.OpCode.Code == Code.Ldstr).Select(i => i.Operand as string)
            .ToHashSet(StringComparer.Ordinal);
        return completed.Where(pair => pair.Key.DeclaringType is not null && !names.Contains(pair.Key.Name.String) && IsForwarder(pair.Key, [pair.Value])).Select(pair => pair.Key)
            .ToHashSet();
    }

    private static bool IsForwarder(MethodDef method, IReadOnlyCollection<MethodDef> aliases)
    {
        if (!method.IsStatic || !method.HasBody || method.Body.ExceptionHandlers.Count != 0 ||
            method.MethodSig?.Params.Count != 1 || method.MethodSig.Params[0].ElementType != ElementType.I4 ||
            method.ReturnType.ElementType is not (ElementType.Object or ElementType.String)) return false;
        var code = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (code.Length != 3 || code[1].OpCode.Code != Code.Call || code[2].OpCode.Code != Code.Ret ||
            code[1].Operand is not IMethod target || target.ResolveMethodDef() is not {} resolved ||
            resolved == method || !aliases.Contains(resolved)) return false;
        return code[0].OpCode.Code == Code.Ldarg_0 ||
            code[0].OpCode.Code is Code.Ldarg or Code.Ldarg_S &&
            code[0].Operand is Parameter parameter && parameter.Index == 0;
    }
}
