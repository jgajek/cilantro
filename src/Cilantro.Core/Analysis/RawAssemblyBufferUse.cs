using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Proves that a local byte buffer is consumed only by full stream reads and assembly loads.</summary>
/// <remarks>Resource-stream provenance and loader behavior must be proved separately.</remarks>
internal static class RawAssemblyBufferUse
{
    /// <summary>Recognizes a direct containing-assembly resource read at method entry.</summary>
    internal static string? ResourceName(MethodDef method, Local buffer)
    {
        if (!method.HasBody || method.Body.Instructions.Count < 21 || !IsClosed(method, buffer)) return null;
        var il = method.Body.Instructions;
        if (il[0].OpCode.Code != Code.Ldtoken || il[0].Operand is not TypeDef owner || owner.Module != method.Module ||
            !Call(1, Code.Call, "System.Type", "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)") ||
            !Call(2, Code.Callvirt, "System.Type", "System.Reflection.Assembly System.Type::get_Assembly()") ||
            il[3].OpCode.Code != Code.Ldstr || il[3].Operand is not string name ||
            method.Module.Resources.Count(r => r.Name == name) != 1 || method.Module.Resources.SingleOrDefault(r => r.Name == name) is not EmbeddedResource ||
            !Call(4, Code.Callvirt, "System.Reflection.Assembly", "System.IO.Stream System.Reflection.Assembly::GetManifestResourceStream(System.String)") ||
            !il[5].IsStloc() || il[5].GetLocal(method.Body.Variables) is not { } stream ||
            !Read(6, stream) || !Call(7, Code.Callvirt, "System.IO.Stream", "System.Int64 System.IO.Stream::get_Length()") ||
            il[8].OpCode.Code != Code.Conv_Ovf_I || il[9].OpCode.Code != Code.Newarr ||
            il[9].Operand is not ITypeDefOrRef element || !CoreLibraryIdentity.Matches(method.Module, element, "System.Byte") ||
            !il[10].IsStloc() || il[10].GetLocal(method.Body.Variables) != buffer ||
            !Read(11, stream) || !Read(12, buffer) || !il[13].IsLdcI4() || il[13].GetLdcI4Value() != 0 ||
            !Read(14, buffer) || il[15].OpCode.Code != Code.Ldlen || il[16].OpCode.Code != Code.Conv_I4 ||
            !Call(17, Code.Callvirt, "System.IO.Stream", "System.Int32 System.IO.Stream::Read(System.Byte[],System.Int32,System.Int32)") ||
            il[18].OpCode.Code != Code.Pop || !Read(19, stream) ||
            !Call(20, Code.Callvirt, "System.IO.Stream", "System.Void System.IO.Stream::Close()")) return null;
        var interior = il.Skip(1).Take(20).ToHashSet();
        if (il.Any(i => i.Operand is Instruction target && interior.Contains(target) ||
                i.Operand is IList<Instruction> targets && targets.Any(interior.Contains)) ||
            method.Body.ExceptionHandlers.Any(h => new[] { h.TryStart, h.TryEnd, h.HandlerStart, h.HandlerEnd, h.FilterStart }
                .Any(i => i is not null && interior.Contains(i)))) return null;
        var flow = EvaluationStackOrigins.Analyze(method);
        if (!flow.Valid || flow.Inputs.Any(pair => pair.Key != il[17] &&
            pair.Key.Operand is IMethod call && call.FullName == "System.Int32 System.IO.Stream::Read(System.Byte[],System.Int32,System.Int32)" &&
            pair.Value.Length == 4 && pair.Value[1].Any(origin => origin is not null && origin.IsLdloc() && origin.GetLocal(method.Body.Variables) == buffer))) return null;
        return name;
        bool Read(int at, Local local) => il[at].IsLdloc() && il[at].GetLocal(method.Body.Variables) == local;
        bool Call(int at, Code opcode, string type, string signature) => il[at].OpCode.Code == opcode &&
            il[at].Operand is IMethod called && called.FullName == signature &&
            CoreLibraryIdentity.Matches(method.Module, called.DeclaringType, type) &&
            called.MethodSig is { ExplicitThis: false, GenParamCount: 0, ParamsAfterSentinel: null } sig &&
            (sig.GetCallingConvention() & CallingConvention.Mask) == CallingConvention.Default && sig.HasThis == (opcode == Code.Callvirt);
    }
    internal static bool IsClosed(MethodDef method, Local buffer)
    {
        if (!method.HasBody || buffer.Type is not SZArraySig { Next.ElementType: ElementType.U1 }) return false;
        var il = method.Body.Instructions;
        if (il.Count(i => i.IsStloc() && i.GetLocal(method.Body.Variables) == buffer) != 1 ||
            il.Any(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S && i.GetLocal(method.Body.Variables) == buffer)) return false;
        var flow = EvaluationStackOrigins.Analyze(method);
        if (!flow.Valid) return false;
        var allowed = new HashSet<Instruction>();
        var loads = 0;
        foreach (var instruction in il)
        {
            if (instruction.Operand is not IMethod called || !flow.Inputs.TryGetValue(instruction, out var inputs)) continue;
            if (instruction.OpCode.Code == Code.Call &&
                CoreLibraryIdentity.Matches(method.Module, called.DeclaringType, "System.Reflection.Assembly") &&
                called.FullName is "System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[])" or
                    "System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[],System.Byte[])" &&
                inputs.Length > 0 && One(inputs[0]) is { } array && IsBuffer(array))
            { allowed.Add(array); loads++; }
            if (instruction.OpCode.Code != Code.Callvirt ||
                !CoreLibraryIdentity.Matches(method.Module, called.DeclaringType, "System.IO.Stream") ||
                called.FullName != "System.Int32 System.IO.Stream::Read(System.Byte[],System.Int32,System.Int32)" ||
                inputs.Length != 4 || One(inputs[1]) is not { } data || !IsBuffer(data) ||
                One(inputs[2]) is not { } zero || !zero.IsLdcI4() || zero.GetLdcI4Value() != 0 ||
                One(inputs[3]) is not { OpCode.Code: Code.Conv_I4 } conversion ||
                !flow.Inputs.TryGetValue(conversion, out var converted) || converted.Length != 1 ||
                One(converted[0]) is not { OpCode.Code: Code.Ldlen } length ||
                !flow.Inputs.TryGetValue(length, out var measured) || measured.Length != 1 ||
                One(measured[0]) is not { } sized || !IsBuffer(sized)) continue;
            // Neither length nor its converted value may escape into another computation.
            if (flow.Inputs.Any(pair => pair.Key != conversion && pair.Value.Any(set => set.Contains(length))) ||
                flow.Inputs.Any(pair => pair.Key != instruction && pair.Value.Any(set => set.Contains(conversion)))) return false;
            allowed.Add(data); allowed.Add(sized);
        }
        if (loads == 0) return false;
        foreach (var read in il.Where(IsBuffer))
        {
            if (!allowed.Contains(read)) return false;
            // A dup keeps the original producer; require each read to feed exactly one consumer.
            if (flow.Inputs.Count(pair => pair.Value.Any(set => set.Contains(read))) != 1) return false;
        }
        return true;
        bool IsBuffer(Instruction i) => i.IsLdloc() && i.GetLocal(method.Body.Variables) == buffer;
    }
    private static Instruction? One(IReadOnlySet<Instruction?> producers) => producers.Count == 1 ? producers.Single() : null;
}
