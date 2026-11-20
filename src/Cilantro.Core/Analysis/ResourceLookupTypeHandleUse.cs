using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>A framework resource-manager constructor uses a type's resource identity, not its methods.</summary>
internal static class ResourceLookupTypeHandleUse
{
    internal static bool IsClosed(MethodDef method, int index)
    {
        var il = method.Body.Instructions;
        var at = index + 1;
        void Skip() { while (at < il.Count && il[at].OpCode.Code == Code.Nop) at++; }
        Skip();
        if (at >= il.Count || il[at].OpCode.Code != Code.Call || il[at].Operand is not MemberRef conversion ||
            conversion.Name != "GetTypeFromHandle" ||
            !CoreLibraryIdentity.Matches(method.Module, conversion.DeclaringType, "System.Type") ||
            conversion.MethodSig is not { HasThis: false, ExplicitThis: false, GenParamCount: 0, Params.Count: 1, ParamsAfterSentinel: null } convert ||
            (convert.GetCallingConvention() & CallingConvention.Mask) != CallingConvention.Default ||
            !CoreLibraryIdentity.Matches(method.Module, convert.Params[0].ToTypeDefOrRef(), "System.RuntimeTypeHandle") ||
            !CoreLibraryIdentity.Matches(method.Module, convert.RetType.ToTypeDefOrRef(), "System.Type")) return false;
        at++; Skip();
        if (at >= il.Count || il[at].OpCode.Code != Code.Newobj || il[at].Operand is not MemberRef ctor ||
            ctor.Name != ".ctor" || ctor.DeclaringType is not TypeRef
                { FullName: "System.ComponentModel.ComponentResourceManager", ResolutionScope: AssemblyRef assembly } ||
            assembly.Name != "System" || assembly.Version.Major != 4 ||
            !assembly.FullName.EndsWith(", PublicKeyToken=b77a5c561934e089", StringComparison.OrdinalIgnoreCase) ||
            ctor.MethodSig is not { HasThis: true, ExplicitThis: false, GenParamCount: 0, Params.Count: 1, ParamsAfterSentinel: null } signature ||
            (signature.GetCallingConvention() & CallingConvention.Mask) != CallingConvention.Default ||
            signature.RetType.ElementType != ElementType.Void ||
            !CoreLibraryIdentity.Matches(method.Module, signature.Params[0].ToTypeDefOrRef(), "System.Type")) return false;
        // No alternate stack may enter the conversion/constructor sequence.
        var interior = il.Skip(index + 1).Take(at - index).ToHashSet();
        return !il.Any(i => i.Operand is Instruction target && interior.Contains(target) ||
                i.Operand is IList<Instruction> targets && targets.Any(interior.Contains)) &&
            !method.Body.ExceptionHandlers.Any(h => new[] { h.TryStart, h.TryEnd, h.HandlerStart, h.HandlerEnd, h.FilterStart }
                .OfType<Instruction>().Any(interior.Contains));
    }
}
