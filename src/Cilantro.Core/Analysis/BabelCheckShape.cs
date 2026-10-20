using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

internal static class BabelCheckShape
{
    internal sealed record Check(MethodDef Method, string Kind, GeneratedRuntimeShape.Graph Graph);

    internal static IEnumerable<Check> Find(ModuleDef module)
    {
        var roots = module.GetTypes().SelectMany(type => type.Methods).Where(method => method.IsStaticConstructor && method.HasBody)
            .SelectMany(method => method.Body.Instructions.Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef()))
            .OfType<MethodDef>().Where(method => method.Module == module && method.IsStatic && method.HasBody && method.MethodSig.Params.Count == 0 &&
                method.ReturnType.ElementType == ElementType.Void).Distinct();
        foreach (var root in roots)
        {
            var calls = root.Body.Instructions.Select(instruction => instruction.Operand).OfType<IMethod>().ToArray();
            var debugging = calls.Any(called => called.DeclaringType.FullName == "System.Threading.Thread" && called.Name == ".ctor") &&
                calls.Any(called => called.DeclaringType.FullName == "System.Threading.Monitor" && called.Name == "Enter") &&
                root.DeclaringType.Methods.Where(method => method.HasBody).Any(method => method.Body.Instructions.Any(instruction => instruction.Operand is string text && text == "COR_PROFILER"));
            var integrity = calls.Any(called => called.FullName == "System.IntPtr System.Runtime.InteropServices.Marshal::GetHINSTANCE(System.Reflection.Module)") &&
                calls.Any(called => called.FullName == "System.String System.Reflection.Module::get_FullyQualifiedName()") &&
                root.DeclaringType.Methods.Where(method => method.HasBody).Any(method => method.Body.Instructions.Any(instruction => instruction.Operand is IMethod called &&
                    called.FullName == "System.Void System.Environment::FailFast(System.String)"));
            if (debugging || integrity) yield return new(root, debugging ? "debugging" : "integrity", GeneratedRuntimeShape.Read(root, integrity));
        }
    }

    internal static bool Supported(Check check) => check.Kind == "debugging" ? check.Graph.Fingerprint is
        "3d22dc35d9a48fd8d2250b9ecce83d46244ce7393ef8393359da33dd04562ff5" or
        "86ff0392bb9f0e5ee5c14da433721a3af816bbc7d6bd55abadcce0f97101030c" or
        "94ca816fcb675a3cd84034a9018440920bef090d94ead3f9e79f0a6d79682cc1" or
        // Reviewed legacy families: profiler guards, managed/native debugger
        // probes, watchdog threads and a FailFast-only detected path.
        "dee914ee812a9e6212d99f7d71ac8a1dfb92619ed35a7856c39bcabde3666b84" or
        "745bd26530cd6f51d3242dd28c351fb51def98216c7b5ad574f09cc0b20b3242" :
        ReadOnlyIntegrity(check) && check.Graph.Fingerprint is
            "e254fc116d2cb1bdb109b6395d8ed3987b6bbd7d3baf49d883e0b2591685f187" or
            "0e41b949d682871ed46faf789d593137a254615e99ad38fcca43a5e8f762a3d0" or
            "ee18306f63f6ad7b3c55fbd0025c99190937cf6cf230c81a1f2aabf99c2df522" or
            "49571048868f3c827bb32f2f5c6eb2640e9b2c4590f1569a3057827abc3bfeee";

    // Integer constants bind this read-only probe to the original image. Its
    // successful return is selected only after interpreting it on that image.
    private static bool ReadOnlyIntegrity(Check check) => check.Graph.Types.Count == 1 &&
        check.Graph.Types[0].Fields.Count == 0 && check.Graph.Types[0].Methods.All(method => method.HasBody && !method.IsPinvokeImpl &&
            method.Body.Instructions.All(instruction => instruction.Operand switch
            {
                IField { FieldSig: not null } => false,
                ITypeDefOrRef type when instruction.OpCode.Code == Code.Ldtoken => type.ResolveTypeDef() == check.Method.DeclaringType,
                IMethod called => called.ResolveMethodDef() is { } local && local.DeclaringType == check.Method.DeclaringType || called.FullName is
                    "System.Void System.Object::.ctor()" or "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)" or
                    "System.Reflection.Module System.Type::get_Module()" or "System.IntPtr System.Runtime.InteropServices.Marshal::GetHINSTANCE(System.Reflection.Module)" or
                    "System.Void* System.IntPtr::op_Explicit(System.IntPtr)" or "System.String System.Reflection.Module::get_FullyQualifiedName()" or
                    "System.Int32 System.String::get_Length()" or "System.Char System.String::get_Chars(System.Int32)" or "System.Void System.Environment::FailFast(System.String)",
                _ => instruction.OpCode.Code is not (Code.Newobj or Code.Calli or Code.Stind_I or Code.Stind_I1 or Code.Stind_I2 or Code.Stind_I4 or Code.Stind_I8 or
                    Code.Stind_R4 or Code.Stind_R8 or Code.Stind_Ref or Code.Stobj or Code.Cpblk or Code.Initblk or Code.Ldstr)
            }));
}
