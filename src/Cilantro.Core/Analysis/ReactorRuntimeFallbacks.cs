using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Attributes exact fallback helpers on a doubly identified protector owner.</summary>
internal static class ReactorRuntimeFallbacks
{
    internal const string OwnersFact = "cleanup.retiredIntegrityProxyOwners";

    internal static IEnumerable<MethodDef> Find(ArtifactContext context, MethodDef proxySetup)
    {
        if (!context.TryGetFact<uint>("antitamper.memoryLoadEntryPoint", out var token) ||
            context.Module.ResolveToken(token) is not MethodDef gate ||
            gate.DeclaringType != proxySetup.DeclaringType) return [];
        var owner = proxySetup.DeclaringType;
        // The caller has recognized the proxy builder; the recorded integrity
        // rewrite independently identifies the same generated runtime owner.
        // Capture identity now, before either method is detached by cleanup.
        // ProtectorIslands still requires complete metadata isolation and refuses
        // public or reconstructed application declarations before deleting a type.
        if (owner.Module == context.Module && !owner.IsGlobalModuleType &&
            ReactorNameHeuristics.IsGeneratedName(owner.Name.String))
        {
            context.TryGetFact<IReadOnlySet<uint>>(OwnersFact, out var previous);
            context.SetFact<IReadOnlySet<uint>>(OwnersFact, new HashSet<uint>(previous ?? new HashSet<uint>()) { owner.MDToken.Raw });
        }
        return proxySetup.DeclaringType.Methods.Where(method => IsLocationFallback(method) || IsDelegateFallback(method)).ToArray();
    }

    internal static bool IsLocationFallback(MethodDef method)
    {
        if (!method.HasBody || !method.IsStatic || method.HasGenericParameters ||
            method.ReturnType.ElementType != ElementType.Object || method.MethodSig.Params.Count != 1 ||
            method.MethodSig.Params[0].ElementType != ElementType.Object ||
            method.Body.Variables.Count != 1 || method.Body.Variables[0].Type.ElementType != ElementType.Object ||
            method.Body.ExceptionHandlers.Count != 3 ||
            method.Body.ExceptionHandlers.Any(h => h.HandlerType != ExceptionHandlerType.Catch)) return false;
        var calls = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["System.String System.Reflection.Assembly::get_Location()"] = 2,
            ["System.Boolean System.IO.File::Exists(System.String)"] = 3,
            ["System.Reflection.AssemblyName System.Reflection.Assembly::GetName()"] = 2,
            ["System.String System.Reflection.AssemblyName::get_CodeBase()"] = 2,
            ["System.String System.Object::ToString()"] = 4,
            ["System.String System.String::Replace(System.String,System.String)"] = 2,
            ["System.Type System.Object::GetType()"] = 2,
            ["System.Reflection.PropertyInfo System.Type::GetProperty(System.String)"] = 2,
            ["System.Object System.Reflection.PropertyInfo::GetValue(System.Object,System.Object[])"] = 2
        };
        var literals = new List<string>();
        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.OpCode.Code is Code.Call or Code.Callvirt)
            {
                if (instruction.Operand is not IMethod call || call.DeclaringType is not TypeRef type ||
                    type.DefinitionAssembly?.FullName != method.Module.CorLibTypes.AssemblyRef.FullName ||
                    !calls.TryGetValue(call.FullName, out var count) || count == 0) return false;
                calls[call.FullName] = count - 1;
            }
            else if (instruction.OpCode.Code == Code.Ldstr && instruction.Operand is string literal) literals.Add(literal);
            else if (instruction.OpCode.Code is Code.Castclass or Code.Newarr)
            {
                if (instruction.Operand is not TypeRef type ||
                    type.DefinitionAssembly?.FullName != method.Module.CorLibTypes.AssemblyRef.FullName ||
                    type.FullName != (instruction.OpCode.Code == Code.Newarr ? "System.Object" : "System.Reflection.Assembly")) return false;
            }
            else if (!(instruction.IsLdarg() || instruction.IsLdloc() || instruction.IsStloc() ||
                       instruction.IsLdcI4() && instruction.GetLdcI4Value() == 0 ||
                       instruction.OpCode.Code is Code.Nop or Code.Pop or Code.Ret or Code.Br or Code.Br_S or
                           Code.Brfalse or Code.Brfalse_S or Code.Leave or Code.Leave_S)) return false;
        }
        return calls.Values.All(count => count == 0) && literals.Count(s => s == "Location") == 2 &&
            literals.Count(s => s == "file:///") == 2 && literals.Count(s => s == "") == 3 && literals.Count == 7;
    }

    internal static bool IsDelegateFallback(MethodDef method)
    {
        if (!method.HasBody || !method.IsStatic || method.HasGenericParameters ||
            method.Body.Variables.Count != 0 || method.Body.ExceptionHandlers.Count != 0 ||
            method.MethodSig.Params.Count != 2 ||
            !Framework(method.ReturnType.ToTypeDefOrRef(), "System.Delegate") ||
            !Framework(method.MethodSig.Params[0].ToTypeDefOrRef(), "System.IntPtr") ||
            !Framework(method.MethodSig.Params[1].ToTypeDefOrRef(), "System.Type")) return false;
        string[] expected = [
            "Ldtoken:System.Runtime.InteropServices.Marshal",
            "Call:System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)",
            "Ldstr:GetDelegateForFunctionPointer", "integer:2", "Newarr:System.Type", "Dup:", "integer:0",
            "Ldtoken:System.IntPtr", "Call:System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)", "Stelem_Ref:",
            "Dup:", "integer:1", "Ldtoken:System.Type", "Call:System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)", "Stelem_Ref:",
            "Call:System.Reflection.MethodInfo System.Type::GetMethod(System.String,System.Type[])",
            "Ldnull:", "integer:2", "Newarr:System.Object", "Dup:", "integer:0", "argument:0", "Box:System.IntPtr", "Stelem_Ref:",
            "Dup:", "integer:1", "argument:1", "Stelem_Ref:",
            "Callvirt:System.Object System.Reflection.MethodBase::Invoke(System.Object,System.Object[])",
            "Castclass:System.Delegate", "Ret:"
        ];
        var actual = new List<string>();
        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.OpCode.Code == Code.Nop) continue;
            if (instruction.IsLdcI4()) actual.Add("integer:" + instruction.GetLdcI4Value());
            else if (instruction.IsLdarg()) actual.Add("argument:" + instruction.GetParameter(method.Parameters)?.Index);
            else
            {
                var operand = instruction.Operand;
                if (operand is IMethod call && !Framework(call.DeclaringType, call.DeclaringType.FullName) ||
                    operand is ITypeDefOrRef type && !Framework(type, type.FullName)) return false;
                actual.Add(instruction.OpCode.Code + ":" + (operand is IFullName named ? named.FullName : operand?.ToString()));
            }
        }
        return actual.SequenceEqual(expected);

        bool Framework(ITypeDefOrRef? type, string name) => type is TypeRef reference && reference.FullName == name &&
            reference.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName;
    }
}
