using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Checks direct uses of a runtime PropertyInfo value. The caller must
/// establish its provenance and separately close any containers or call boundaries.</summary>
internal static class ClosedPropertyMetadataUses
{
    internal sealed record Result(bool Closed, string Reason);
    internal static bool IsClosed(MethodDef method, Instruction source) => Analyze(method, source).Closed;
    private sealed class Budget { internal int Remaining = 1024; }
    internal static Result Analyze(MethodDef method, Instruction source) => AnalyzeCore(method, source, [], new Budget());
    private static Result AnalyzeCore(MethodDef method, Instruction source, HashSet<Parameter> activeParameters, Budget budget)
    {
        if (!method.HasBody || !method.Body.Instructions.Contains(source)) return new(false, "Unclosed metadata flow");
        var flow = EvaluationStackOrigins.Analyze(method);
        if (!flow.Valid) return new(false, "Unknown evaluation stack");
        var pending = new Queue<Instruction>();
        var seen = new HashSet<Instruction>();
        pending.Enqueue(source);
        var terminals = 0;
        bool Core(ITypeDefOrRef type, string name) => CoreLibraryIdentity.Matches(method.Module, type, name);
        bool Signature(IMethod call, string name, bool setter) =>
            Core(call.DeclaringType, "System.Reflection.PropertyInfo") && call.Name == name &&
            call.MethodSig is { HasThis: true, ExplicitThis: false, GenParamCount: 0, ParamsAfterSentinel: null } sig &&
            (sig.GetCallingConvention() & CallingConvention.Mask) == CallingConvention.Default &&
            sig.Params.Count == (setter ? 3 : 2) &&
            new SigComparer().Equals(sig.RetType, setter ? method.Module.CorLibTypes.Void : method.Module.CorLibTypes.Object) &&
            new SigComparer().Equals(sig.Params[0], method.Module.CorLibTypes.Object) &&
            (!setter || new SigComparer().Equals(sig.Params[1], method.Module.CorLibTypes.Object)) &&
            sig.Params[^1] is SZArraySig array && new SigComparer().Equals(array.Next, method.Module.CorLibTypes.Object);
        while (pending.TryDequeue(out var value))
        {
            if (!seen.Add(value)) continue;
            if (seen.Count > 256 || --budget.Remaining < 0) return new(false, "Unclosed metadata flow");
            foreach (var (instruction, arguments) in flow.Inputs)
            {
                var slots = Enumerable.Range(0, arguments.Length).Where(n => arguments[n].Contains(value)).ToArray();
                if (slots.Length == 0) continue;
                if (instruction.OpCode.Code == Code.Dup) continue;
                if (instruction.IsStloc())
                {
                    var local = instruction.GetLocal(method.Body.Variables);
                    if (local is null) return new(false, "Unclosed metadata flow");
                    foreach (var use in method.Body.Instructions.Where(i => i.GetLocal(method.Body.Variables) == local))
                    {
                        if (use.IsLdloc()) pending.Enqueue(use);
                        else if (!use.IsStloc()) return new(false, "Unclosed metadata flow");
                    }
                    continue;
                }
                if (slots.Length == 1 && slots[0] == 1 && instruction.OpCode.Code is Code.Call or Code.Callvirt &&
                    instruction.Operand is IMethod lookup && lookup.Name == "get_Item" &&
                    lookup.DeclaringType.ToTypeSig() is GenericInstSig { GenericArguments.Count: 2 } dictionary &&
                    Core(dictionary.GenericType.TypeDefOrRef, "System.Collections.Generic.Dictionary`2") &&
                    Core(dictionary.GenericArguments[0].ToTypeDefOrRef(), "System.Reflection.PropertyInfo") &&
                    new SigComparer().Equals(dictionary.GenericArguments[1], method.Module.CorLibTypes.String) &&
                    lookup.MethodSig is { HasThis: true, ExplicitThis: false, GenParamCount: 0, Params.Count: 1, ParamsAfterSentinel: null } lookupSig &&
                    (lookupSig.GetCallingConvention() & CallingConvention.Mask) == CallingConvention.Default)
                {
                    var scope = new Interpretation.GenericScope(dictionary.GenericArguments, null);
                    if (new SigComparer().Equals(scope.Bind(lookupSig.Params[0]), dictionary.GenericArguments[0]) &&
                        new SigComparer().Equals(scope.Bind(lookupSig.RetType), dictionary.GenericArguments[1]) &&
                        ClosedDictionaryAliases.Analyze(method, instruction).Closed)
                    { terminals++; continue; }
                }
                if (slots.Length == 1 && instruction.OpCode.Code == Code.Call && instruction.Operand is IMethod invoked &&
                    invoked.ResolveMethodDef() is { IsStatic: true, IsVirtual: false, HasBody: true, HasGenericParameters: false } target &&
                    target.Module == method.Module && !target.DeclaringType.HasGenericParameters && !target.IsConstructor &&
                    invoked.MethodSig is { HasThis: false, ExplicitThis: false, ParamsAfterSentinel: null } forwardedSig &&
                    (forwardedSig.GetCallingConvention() & CallingConvention.Mask) == CallingConvention.Default &&
                    new SigComparer().Equals(forwardedSig, target.MethodSig) && slots[0] < target.Parameters.Count)
                {
                    var parameter = target.Parameters[slots[0]];
                    if (!activeParameters.Add(parameter)) return new(false, "Recursive metadata forwarding");
                    try
                    {
                        var reads = target.Body.Instructions.Where(i => i.GetParameter(target.Parameters) == parameter).ToArray();
                        if (reads.Length == 0 || reads.Any(i => !i.IsLdarg())) return new(false, "Parameter write or address exposure");
                        foreach (var read in reads)
                        {
                            var nested = AnalyzeCore(target, read, activeParameters, budget);
                            if (!nested.Closed) return new(false, target.FullName + ": " + nested.Reason);
                        }
                    }
                    finally { activeParameters.Remove(parameter); }
                    terminals++; continue;
                }
                if (slots.Length != 1 || slots[0] != 0) return new(false, "Metadata passed outside receiver slot: " + instruction);
                if (instruction.OpCode.Code == Code.Castclass && instruction.Operand is ITypeDefOrRef cast &&
                    (Core(cast, "System.Reflection.PropertyInfo") || Core(cast, "System.Reflection.MemberInfo")))
                { pending.Enqueue(instruction); continue; }
                if (instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod call &&
                    (Signature(call, "GetValue", false) || Signature(call, "SetValue", true)))
                { terminals++; continue; }
                if (instruction.OpCode.Code == Code.Call && instruction.Operand is IMethod attribute &&
                    Core(attribute.DeclaringType, "System.Attribute") && attribute.Name == "GetCustomAttribute" &&
                    attribute.MethodSig is { HasThis: false, ExplicitThis: false, GenParamCount: 0, Params.Count: 2, ParamsAfterSentinel: null } attributeSig &&
                    (attributeSig.GetCallingConvention() & CallingConvention.Mask) == CallingConvention.Default &&
                    Core(attributeSig.RetType.ToTypeDefOrRef(), "System.Attribute") &&
                    Core(attributeSig.Params[0].ToTypeDefOrRef(), "System.Reflection.MemberInfo") &&
                    Core(attributeSig.Params[1].ToTypeDefOrRef(), "System.Type"))
                { terminals++; continue; }
                // DeclaringType, accessors, arbitrary calls and storage/returns require
                // a separate interprocedural proof, even when currently unused.
                return new(false, instruction.ToString());
            }
        }
        return new(terminals != 0, terminals != 0 ? "Property accesses only" : "No property access terminal");
    }
}
