using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Identifies calls on fresh, unconfigured framework JSON serializer instances.
/// This proves instance provenance only, not the types or subsequent uses of returned objects.</summary>
internal static class DefaultJsonSerializerCalls
{
    internal static IReadOnlySet<Instruction> Find(MethodDef method)
    {
        var found = new HashSet<Instruction>();
        if (!method.HasBody) return found;
        var module = method.Module;
        var graph = ControlFlowGraph.Build(method);
        foreach (var block in graph.Blocks)
        {
            var il = block.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            for (var n = 4; n < il.Length; n++)
            {
                if (il[n].OpCode.Code != Code.Callvirt || il[n].Operand is not MethodSpec call ||
                    call.GenericInstMethodSig?.GenericArguments.Count != 1 ||
                    !new SigComparer().Equals(call.GenericInstMethodSig.GenericArguments[0], module.CorLibTypes.Object) ||
                    call.Method.Name != "Deserialize" || !FrameworkOwner(call.Method) ||
                    call.Method.MethodSig is not { HasThis: true, ExplicitThis: false, GenParamCount: 1, Params.Count: 1, ParamsAfterSentinel: null } sig ||
                    (sig.CallingConvention & CallingConvention.Mask) != CallingConvention.Default ||
                    sig.RetType is not GenericMVar { Number: 0 } ||
                    !new SigComparer().Equals(sig.Params[0], module.CorLibTypes.String)) continue;
                if (il[n - 4].OpCode.Code != Code.Newobj || il[n - 4].Operand is not IMethod ctor ||
                    ctor is MethodSpec || ctor.Name != ".ctor" || !FrameworkOwner(ctor) ||
                    ctor.MethodSig is not { HasThis: true, ExplicitThis: false, GenParamCount: 0, Params.Count: 0, ParamsAfterSentinel: null } cs ||
                    (cs.CallingConvention & CallingConvention.Mask) != CallingConvention.Default ||
                    !new SigComparer().Equals(cs.RetType, module.CorLibTypes.Void) ||
                    ctor.DeclaringType.DefinitionAssembly.FullName != call.DeclaringType.DefinitionAssembly.FullName ||
                    !il[n - 3].IsStloc() || !il[n - 2].IsLdloc()) continue;
                var local = il[n - 3].GetLocal(method.Body.Variables);
                if (local is null || il[n - 2].GetLocal(method.Body.Variables) != local ||
                    !new SigComparer().Equals(local.Type, ctor.DeclaringType.ToTypeSig())) continue;
                // The string argument must be a side-effect-free load. Calls between
                // construction and consumption could configure or publish the instance.
                var input = il[n - 1];
                if (input.OpCode.Code != Code.Ldstr && !(input.IsLdloc() &&
                    input.GetLocal(method.Body.Variables) is { } text &&
                    new SigComparer().Equals(text.Type, module.CorLibTypes.String))) continue;
                var uses = method.Body.Instructions.Where(i => i.GetLocal(method.Body.Variables) == local).ToArray();
                if (uses.Length != 2 || !uses.Contains(il[n - 3]) || !uses.Contains(il[n - 2])) continue;
                found.Add(il[n]);
            }
        }
        return found;
    }

    private static bool FrameworkOwner(IMethod method) => method.DeclaringType is TypeRef
    {
        FullName: "System.Web.Script.Serialization.JavaScriptSerializer", ResolutionScope: AssemblyRef assembly
    } && assembly.Name == "System.Web.Extensions" &&
        assembly.FullName.EndsWith(", PublicKeyToken=31bf3856ad364e35", StringComparison.OrdinalIgnoreCase);
}
