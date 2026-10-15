using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Attributes native imports used only by closed process-query delegate factories.</summary>
internal static class ClosedNativeQueryImports
{
    internal static IReadOnlySet<MethodDef> Find(ModuleDef module)
    {
        var methods = module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var factories = methods.Where(m => m.HasBody && m.IsStatic && m.GenericParameters.Count == 1 &&
            m.MethodSig.Params.Count == 2 && m.MethodSig.Params.All(p => p.ElementType == ElementType.String)).ToArray();
        if (factories.Length == 0) return new HashSet<MethodDef>();
        var instructions = methods.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions).ToArray();
        var names = instructions.Select(i => i.Operand).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var exposed = ModuleReachability.Compute(module).ReflectivelyExposedTypes.ToHashSet();
        bool Closed(MethodDef method) => !MemberVisibility.IsExternallyVisible(method) && !exposed.Contains(method.DeclaringType) &&
            !names.Contains(method.Name.String) && !names.Contains(method.FullName) &&
            !module.GetMemberRefs().Any(r => r.IsMethodRef && r.ResolveMethodDef() == method);
        var accepted = new Dictionary<MethodDef, MethodDef[]>();
        foreach (var factory in factories.Where(Closed))
        {
            var il = factory.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            if (il.Length < 8 || !il[0].IsLdarg() || il[0].GetParameterIndex() != 0 ||
                il[1].OpCode.Code != Code.Call || il[1].Operand is not MethodDef load ||
                !Import(load, "LoadLibrary", "System.IntPtr", "System.String") ||
                !il[2].IsLdarg() || il[2].GetParameterIndex() != 1 ||
                il[3].OpCode.Code != Code.Call || il[3].Operand is not MethodDef address ||
                !Import(address, "GetProcAddress", "System.IntPtr", "System.IntPtr", "System.String") ||
                il[4].OpCode.Code != Code.Ldtoken || il[4].Operand is not TypeSpec { TypeSig: GenericMVar { Number: 0 } } ||
                !Framework(il[5], "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)") ||
                !Framework(il[6], "System.Delegate System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer(System.IntPtr,System.Type)") ||
                !Closed(load) || !Closed(address)) continue;
            // Only the delegate/null return and catch scaffolding may follow. No
            // arbitrary calls, argument rewrites or alternate entries into the factory.
            var prefixEnd = factory.Body.Instructions.IndexOf(il[6]);
            bool InPrefix(Instruction instruction) => instruction != null && factory.Body.Instructions.IndexOf(instruction) <= prefixEnd;
            if (il.Skip(7).Any(i => i.OpCode.Code is not (Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3 or
                    Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3 or Code.Leave or Code.Leave_S or Code.Pop or Code.Ldnull or Code.Ret) ||
                    i.Operand is Instruction target && InPrefix(target)) ||
                factory.Body.ExceptionHandlers.Any(h => InPrefix(h.HandlerStart) || InPrefix(h.FilterStart) ||
                    h.TryStart != factory.Body.Instructions[0] && InPrefix(h.TryStart))) continue;
            var calls = instructions.Where(i => i.Operand is IMethod m && m.ResolveMethodDef() == factory).ToArray();
            if (calls.Length == 0 || calls.Any(i => i.OpCode.Code != Code.Call || i.Operand is not MethodSpec)) continue;
            var valid = true;
            foreach (var caller in methods.Where(m => m.HasBody && m.Body.Instructions.Any(calls.Contains)))
            {
                var graph = ControlFlowGraph.Build(caller);
                foreach (var call in caller.Body.Instructions.Where(calls.Contains))
                {
                    var block = graph.BlockOf(call).Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                    var at = Array.IndexOf(block, call);
                    var spec = (MethodSpec)call.Operand;
                    if (at < 2 || block[at - 2].OpCode.Code != Code.Ldstr || block[at - 1].OpCode.Code != Code.Ldstr ||
                        spec.GenericInstMethodSig?.GenericArguments.Count != 1 ||
                        !Query((string)block[at - 2].Operand, (string)block[at - 1].Operand, spec.GenericInstMethodSig.GenericArguments[0])) valid = false;
                }
            }
            if (valid) accepted.Add(factory, [load, address]);
        }
        var result = new HashSet<MethodDef>();
        foreach (var import in accepted.Values.SelectMany(v => v).Distinct())
        {
            var uses = methods.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions
                .Where(i => i.Operand is IMethod reference && reference.ResolveMethodDef() == import).Select(i => (Method: m, Instruction: i))).ToArray();
            if (uses.Length != 0 && uses.All(use => use.Instruction.OpCode.Code == Code.Call && accepted.ContainsKey(use.Method))) result.Add(import);
        }
        return result;

        bool Framework(Instruction instruction, string signature) => instruction.OpCode.Code == Code.Call &&
            instruction.Operand is IMethod call && call.FullName == signature && call.DeclaringType is TypeRef type &&
            type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
    }

    private static bool Import(MethodDef method, string name, string result, params string[] parameters) =>
        method.IsStatic && method.IsPinvokeImpl && !method.HasBody && !method.HasGenericParameters &&
        method.ImplMap?.Module.Name.String.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase) == true &&
        (method.ImplMap.Name == name || name == "LoadLibrary" && method.ImplMap.Name is { String: "LoadLibraryA" or "LoadLibraryW" }) &&
        method.ReturnType.FullName == result && method.ReturnType.ElementType == ElementType.I &&
        method.MethodSig.Params.Count == parameters.Length && method.MethodSig.Params.Zip(parameters)
            .All(pair => pair.First.ElementType == (pair.Second == "System.IntPtr" ? ElementType.I : ElementType.String)) &&
        method.ParamDefs.All(p => !p.HasMarshalType);

    private static bool Query(string library, string export, TypeSig argument)
    {
        var type = argument.ToTypeDefOrRef()?.ResolveTypeDef();
        var invokes = type?.Methods.Where(m => m.Name == "Invoke").ToArray();
        if (type is null || type.HasGenericParameters || !type.IsDelegate ||
            type.BaseType is not TypeRef parent || parent.DefinitionAssembly?.FullName != type.Module.CorLibTypes.AssemblyRef.FullName ||
            invokes is not { Length: 1 } || invokes[0] is not { } invoke || invoke.HasBody ||
            !invoke.IsRuntime || invoke.ParamDefs.Any(p => p.HasMarshalType)) return false;
        var parameters = invoke.MethodSig.Params.Select(p => p.FullName).ToArray();
        if (library.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase))
            return invoke.ReturnType.ElementType == ElementType.Boolean &&
                (export == "IsDebuggerPresent" && parameters.Length == 0 ||
                 export == "CheckRemoteDebuggerPresent" && invoke.MethodSig.Params is { Count: 2 } debuggerParameters &&
                 debuggerParameters[0].ElementType == ElementType.I && debuggerParameters[1] is ByRefSig { Next.ElementType: ElementType.Boolean });
        // NtQueryInformationProcess writes process information into caller-provided
        // storage; it neither loads assemblies nor reads their resource tables.
        // Admit only the observed blittable six-pointer buffer representation, not
        // arbitrary object/custom-marshaler signatures or arbitrary ntdll exports.
        // https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
        if (library.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase) && export == "NtQueryInformationProcess" &&
            invoke.ReturnType.ElementType == ElementType.I4 && parameters.Length == 5 &&
            invoke.MethodSig.Params[0].ElementType == ElementType.I && invoke.MethodSig.Params[1].ElementType == ElementType.I4 &&
            invoke.MethodSig.Params[3].ElementType == ElementType.I4 && invoke.MethodSig.Params[4] is ByRefSig { Next.ElementType: ElementType.I4 } &&
            invoke.MethodSig.Params[2] is ByRefSig { Next: ValueTypeSig buffer } &&
            buffer.TypeDefOrRef.ResolveTypeDef() is { IsSequentialLayout: true, HasGenericParameters: false } storage &&
            storage.BaseType is TypeRef baseType && baseType.FullName == "System.ValueType" &&
            baseType.DefinitionAssembly?.FullName == storage.Module.CorLibTypes.AssemblyRef.FullName &&
            storage.ClassLayout is null && storage.Methods.Count == 0 && storage.Fields.Count == 6 &&
            storage.Fields.All(field => !field.IsStatic && !field.HasMarshalType && field.FieldType.ElementType == ElementType.I)) return true;
        return false;
    }
}
