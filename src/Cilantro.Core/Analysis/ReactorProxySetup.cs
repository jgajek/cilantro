using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Identifies Reactor's token-arithmetic delegate initializer, including unused emitted copies.</summary>
internal static class ReactorProxySetup
{
    internal static IEnumerable<MethodDef> Find(ArtifactContext context)
    {
        if (!context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var facts) || facts?.IsReactor != true)
            yield break;
        foreach (var type in context.Module.GetTypes())
        {
            // Namespace spelling is not ownership evidence: Reactor may retain a
            // low-churn namespace around an otherwise characteristic builder.
            if (!type.IsGlobalModuleType && ReactorNameHeuristics.IsGeneratedName(type.Name.String))
                foreach (var method in type.Methods.Where(method => IsRetiredMapBuilder(context.Module, method)))
                    yield return method;
            if (type.IsGlobalModuleType || !type.FullName.Split('.', '/', '`', '+').Where(part => part.Length != 0)
                    .All(ReactorNameHeuristics.IsGeneratedName)) continue;
            if (type.FindStaticConstructor() is not { HasBody: true } initializer) continue;
            var setup = InitializerPath(initializer);
            // Recovery may make the framework receiver types explicit. These casts
            // cannot change the result of the immediately preceding exact API call.
            setup = setup.Where((instruction, index) => !(index > 0 &&
                instruction.OpCode.Code == Code.Castclass && instruction.Operand is TypeRef cast &&
                cast.DefinitionAssembly?.FullName == context.Module.CorLibTypes.AssemblyRef.FullName &&
                (cast.FullName == "System.Type" && Calls(setup[index - 1], "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)") ||
                 cast.FullName == "System.Reflection.Assembly" && Calls(setup[index - 1], "System.Reflection.Assembly System.Type::get_Assembly()") ||
                 cast.FullName == "System.Reflection.Module" && Calls(setup[index - 1], "System.Reflection.Module System.Reflection.Assembly::get_ManifestModule()")))).ToArray();
            if (setup.Length != 6 || setup[0].OpCode.Code != Code.Ldtoken || setup[0].Operand != type ||
                !Calls(setup[1], "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)") ||
                !Calls(setup[2], "System.Reflection.Assembly System.Type::get_Assembly()") ||
                !Calls(setup[3], "System.Reflection.Module System.Reflection.Assembly::get_ManifestModule()") ||
                setup[4].OpCode.Code != Code.Stsfld || setup[4].Operand is not IField field ||
                field.ResolveFieldDef() is not { IsStatic: true } moduleField || moduleField.DeclaringType != type ||
                moduleField.FieldType.FullName != "System.Reflection.Module" || setup[5].OpCode.Code != Code.Ret)
                continue;
            foreach (var method in type.Methods.Where(m => m.HasBody && m.IsStatic && !m.IsConstructor &&
                         m.ReturnType.ElementType == ElementType.Void && m.MethodSig.Params.Count == 1 &&
                         m.MethodSig.Params[0].ElementType == ElementType.I4))
            {
                var body = method.Body.Instructions;
                if (!body.Any(i => i.OpCode.Code == Code.Ldsfld && i.Operand is IField f && f.ResolveFieldDef() == moduleField) ||
                    !body.Any(i => i.IsLdcI4() && i.GetLdcI4Value() == 0x02000000) ||
                    !body.Any(i => i.IsLdcI4() && i.GetLdcI4Value() == 0x06000000)) continue;
                string[] operations = [
                    "System.Type System.Reflection.Module::ResolveType(System.Int32)",
                    "System.Reflection.MethodBase System.Reflection.Module::ResolveMethod(System.Int32)",
                    "System.Int32 System.Reflection.MemberInfo::get_MetadataToken()",
                    "System.Reflection.FieldInfo[] System.Type::GetFields()",
                    "System.Delegate System.Delegate::CreateDelegate(System.Type,System.Reflection.MethodInfo)",
                    "System.Void System.Reflection.FieldInfo::SetValue(System.Object,System.Object)"
                ];
                if (operations.All(operation => body.Any(i => Calls(i, operation)))) yield return method;
            }
        }

        bool Calls(Instruction instruction, string name) => instruction.OpCode.Code is Code.Call or Code.Callvirt &&
            instruction.Operand is IMethod method && method.FullName == name && method.DeclaringType is TypeRef type &&
            type.DefinitionAssembly?.FullName == context.Module.CorLibTypes.AssemblyRef.FullName;
    }

    // Some builds emit an unused copy of the encrypted delegate-map builder even
    // though its named map is absent. Attribute only that distinctive method;
    // the ordinary reachability/reference checks still decide whether it can go.
    private static bool IsRetiredMapBuilder(ModuleDef module, MethodDef method)
    {
        if (!method.HasBody || !method.IsStatic || method.IsConstructor || method.HasGenericParameters ||
            method.ReturnType.ElementType != ElementType.Void || method.MethodSig.Params.Count != 1 ||
            method.MethodSig.Params[0].ToTypeDefOrRef() is not TypeRef parameter ||
            parameter.FullName != "System.RuntimeTypeHandle" ||
            parameter.DefinitionAssembly?.FullName != module.CorLibTypes.AssemblyRef.FullName) return false;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Length < 5 || !il[0].IsLdarg() || il[0].GetParameter(method.Parameters)?.Index != 0 ||
            !Calls(il[1], "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)")) return false;
        var reads = il.Select((instruction, index) => (instruction, index)).Where(p =>
            Calls(p.instruction, "System.IO.Stream System.Reflection.Assembly::GetManifestResourceStream(System.String)")).ToArray();
        if (reads.Length != 1) return false;
        var at = reads[0].index;
        if (at < 4 || il[at - 4].OpCode.Code != Code.Ldtoken || il[at - 4].Operand != method.DeclaringType ||
            !Calls(il[at - 3], "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)") ||
            !Calls(il[at - 2], "System.Reflection.Assembly System.Type::get_Assembly()") ||
            il[at - 1].OpCode.Code != Code.Ldstr || il[at - 1].Operand is not string name ||
            name.Length == 0 || module.Resources.Any(resource => resource.Name == name)) return false;
        string[] operations = [
            "System.Reflection.FieldInfo[] System.Type::GetFields(System.Reflection.BindingFlags)",
            "System.Int32 System.Reflection.MemberInfo::get_MetadataToken()",
            "System.Reflection.MethodBase System.Reflection.Module::ResolveMethod(System.Int32,System.Type[],System.Type[])",
            "System.Delegate System.Delegate::CreateDelegate(System.Type,System.Reflection.MethodInfo)",
            "System.Void System.Reflection.FieldInfo::SetValue(System.Object,System.Object)",
            "System.Reflection.ParameterInfo[] System.Reflection.MethodBase::GetParameters()",
            "System.Reflection.Emit.ILGenerator System.Reflection.Emit.DynamicMethod::GetILGenerator()",
            "System.Delegate System.Reflection.Emit.DynamicMethod::CreateDelegate(System.Type)"
        ];
        return operations.All(operation => il.Any(instruction => Calls(instruction, operation)));

        bool Calls(Instruction instruction, string signature) => instruction.OpCode.Code is Code.Call or Code.Callvirt &&
            instruction.Operand is IMethod call && call.FullName == signature && call.DeclaringType is TypeRef type &&
            type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
    }

    private static Instruction[] InitializerPath(MethodDef method)
    {
        if (method.Body.ExceptionHandlers.Count != 0) return [];
        var code = method.Body.Instructions;
        var positions = code.Select((instruction, index) => (instruction, index)).ToDictionary(p => p.instruction, p => p.index);
        var seen = new HashSet<int>(); var path = new List<Instruction>();
        for (var index = 0; index < code.Count && seen.Add(index);)
        {
            var instruction = code[index];
            if (instruction.OpCode.Code is Code.Br or Code.Br_S)
            {
                if (instruction.Operand is not Instruction target || !positions.TryGetValue(target, out index)) return [];
                continue;
            }
            if (instruction.OpCode.Code != Code.Nop) path.Add(instruction);
            if (instruction.OpCode.Code == Code.Ret) return path.ToArray();
            if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Throw) return [];
            index++;
        }
        return [];
    }
}
