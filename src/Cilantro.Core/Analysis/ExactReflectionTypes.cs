using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Recognizes an exact runtime Type receiver, not an arbitrary Type subclass.
/// This supplies lookup scope only; it does not prove the use of the method-name argument.</summary>
internal static class ExactReflectionTypes
{
    internal static ITypeDefOrRef? Receiver(MethodDef method, Instruction lookup)
    {
        var flow = EvaluationStackOrigins.Analyze(method);
        if (!flow.Valid || !flow.Inputs.TryGetValue(lookup, out var arguments) || arguments.Length == 0) return null;
        var active = new HashSet<Instruction>();
        var budget = 256;
        bool Core(ITypeDefOrRef type, string name) => type is TypeRef && type.FullName == name &&
            type.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName;
        ITypeDefOrRef? Origins(IReadOnlySet<Instruction?> origins)
        {
            ITypeDefOrRef? result = null;
            foreach (var origin in origins)
            {
                if (origin is null || --budget < 0 || !active.Add(origin)) return null;
                var next = Producer(origin);
                active.Remove(origin);
                if (next is null || result is not null && !new SigComparer().Equals(result, next)) return null;
                result = next;
            }
            return result;
        }
        ITypeDefOrRef? Producer(Instruction instruction)
        {
            if (!flow.Inputs.TryGetValue(instruction, out var input) || input.Length != 1) return null;
            if (instruction.OpCode.Code == Code.Castclass && instruction.Operand is ITypeDefOrRef cast && Core(cast, "System.Type"))
                return Origins(input[0]);
            if (instruction.OpCode.Code != Code.Call || instruction.Operand is not IMethod call ||
                !Core(call.DeclaringType, "System.Type") || call.Name != "GetTypeFromHandle" ||
                call.MethodSig is not { HasThis: false, GenParamCount: 0, Params.Count: 1 } signature ||
                !Core(signature.RetType.ToTypeDefOrRef(), "System.Type") ||
                !Core(signature.Params[0].ToTypeDefOrRef(), "System.RuntimeTypeHandle")) return null;
            ITypeDefOrRef? token = null;
            foreach (var source in input[0])
            {
                if (source?.OpCode.Code != Code.Ldtoken || source.Operand is not ITypeDefOrRef type ||
                    type.ToTypeSig() is GenericVar or GenericMVar || token is not null && !new SigComparer().Equals(token, type)) return null;
                token = type;
            }
            return token;
        }
        return Origins(arguments[0]);
    }
}
