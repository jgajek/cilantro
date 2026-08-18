using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Proxy;

public sealed record ProxyValidation(
    bool Valid,
    double Score,
    IReadOnlyList<string> Diagnostics);

public static class ProxyBindingValidator
{
    public static ProxyValidation Validate(
        ModuleDefMD module,
        IReadOnlyList<ProxyBinding> bindings,
        IReadOnlyDictionary<uint, FieldDef> fields)
    {
        var diagnostics = new List<string>();
        if (bindings.Count != fields.Count)
            diagnostics.Add($"Binding count {bindings.Count} does not equal field count {fields.Count}.");
        var seen = new HashSet<uint>();
        foreach (var binding in bindings)
        {
            if (!fields.ContainsKey(binding.FieldToken))
                diagnostics.Add($"Field token 0x{binding.FieldToken:X8} is not a proxy field.");
            if (!seen.Add(binding.FieldToken))
                diagnostics.Add($"Field token 0x{binding.FieldToken:X8} is duplicated.");
            if (module.ResolveToken(binding.TargetToken) is not IMethod target)
            {
                diagnostics.Add($"Target token 0x{binding.TargetToken:X8} is not a method.");
                continue;
            }

            if (binding.CallVirtual && target.MethodSig?.HasThis == false)
                diagnostics.Add($"Static target 0x{binding.TargetToken:X8} cannot use callvirt.");
        }

        var denominator = Math.Max(1, bindings.Count + 1);
        var score = Math.Max(0, 1.0 - (double)diagnostics.Count / denominator);
        return new ProxyValidation(diagnostics.Count == 0, score, diagnostics);
    }

    public static bool IsAdapterCall(
        Instruction fieldLoad,
        Instruction call,
        FieldDef field,
        MethodDef adapter) =>
        fieldLoad.OpCode == OpCodes.Ldsfld &&
        ReferenceEquals(fieldLoad.Operand, field) &&
        call.OpCode == OpCodes.Call &&
        call.Operand is IMethod called &&
        called.MDToken.Raw == adapter.MDToken.Raw;
}
