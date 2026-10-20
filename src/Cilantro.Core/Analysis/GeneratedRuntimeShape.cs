using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Fingerprints complete generated type families, including interop, layout and virtual dispatch.</summary>
internal static class GeneratedRuntimeShape
{
    internal sealed record Graph(IReadOnlyList<TypeDef> Types, string Fingerprint);
    internal static Graph Read(MethodDef root, bool maskIntegerConstants = false) => ReadCore(root, maskIntegerConstants, false, out _);
    internal static Graph ReadCanonical(MethodDef root) => ReadCore(root, false, true, out _);
    internal static Graph ReadCanonicalScopedNames(MethodDef root) => ReadCore(root, false, true, out _, scopedTypeNames: true);
    internal static Graph ReadCanonicalFamily(MethodDef root) => ReadCore(root, false, true, out _, 128, true);
    internal static Graph ReadCanonicalGenericFamily(MethodDef root) => ReadCore(root, false, true, out _, 32, true, true);
    internal static Graph ReadGenericFamily(MethodDef root) => ReadCore(root, false, false, out _, 32, true, true);
    internal static Graph ReadCanonicalType(MethodDef root) => ReadCore(root, false, true, out _, 1, true, true, singleType: true);
    internal static string DescribeCanonicalGenericFamily(MethodDef root)
    {
        ReadCore(root, false, true, out var description, 32, true, true);
        return description;
    }
    internal static Graph ReadCanonicalWithIntegerParameters(MethodDef root) => ReadCore(root, true, true, out _);
    internal static string DescribeCanonical(MethodDef root)
    {
        ReadCore(root, false, true, out var description);
        return description;
    }

    private static Graph ReadCore(MethodDef root, bool maskIntegerConstants, bool canonicalControlFlow, out string description,
        int maximumTypes = 32, bool metadataClosure = false, bool genericTypes = false, bool singleType = false, bool scopedTypeNames = false)
    {
        description = "";
        var module = root.Module;
        var types = new List<TypeDef>();
        var pending = new Queue<TypeDef>();
        var oversized = false;
        void Add(TypeDef type) { if (type.Module == module && (!singleType || type == root.DeclaringType) && !types.Contains(type)) { types.Add(type); pending.Enqueue(type); } }
        void Referenced(ITypeDefOrRef? reference) { if (reference?.ResolveTypeDef() is { } type) Add(type); }
        void SignatureTypes(TypeSig? signature, int depth = 0)
        {
            if (signature is null || depth > 32) { if (depth > 32) oversized = true; return; }
            Referenced(signature.ToTypeDefOrRef());
            if (signature is GenericInstSig instance)
                foreach (var argument in instance.GenericArguments) SignatureTypes(argument, depth + 1);
            if (signature is ModifierSig modifier) Referenced(modifier.Modifier);
            SignatureTypes(signature.Next, depth + 1);
        }
        Add(root.DeclaringType);
        while (pending.TryDequeue(out var type) && types.Count <= maximumTypes)
        {
            if (type.HasGenericParameters && !genericTypes || type.GenericParameters.Count > 8 ||
                type.Methods.Any(method => method.GenericParameters.Count > 8) || type.Methods.Count > 64 || type.Fields.Count > 64 ||
                type.Methods.Any(method => method.HasBody && method.Body.Instructions.Count > 4096)) { oversized = true; break; }
            foreach (var nested in type.NestedTypes) Add(nested);
            if (metadataClosure)
            {
                Referenced(type.BaseType);
                foreach (var item in type.Interfaces) Referenced(item.Interface);
                foreach (var field in type.Fields) SignatureTypes(field.FieldType);
            }
            if (genericTypes)
            {
                foreach (var attribute in type.CustomAttributes.Concat(type.Fields.SelectMany(field => field.CustomAttributes))
                             .Concat(type.Methods.SelectMany(method => method.CustomAttributes)))
                    Referenced(attribute.Constructor.DeclaringType);
                foreach (var constraint in type.GenericParameters.Concat(type.Methods.SelectMany(method => method.GenericParameters))
                             .SelectMany(parameter => parameter.GenericParamConstraints)) Referenced(constraint.Constraint);
            }
            foreach (var method in type.Methods)
            {
                foreach (var parameter in method.MethodSig.Params) Referenced(parameter.ToTypeDefOrRef());
                Referenced(method.ReturnType.ToTypeDefOrRef());
                if (metadataClosure)
                {
                    SignatureTypes(method.ReturnType);
                    foreach (var parameter in method.MethodSig.Params) SignatureTypes(parameter);
                    if (method.HasBody) foreach (var local in method.Body.Variables) SignatureTypes(local.Type);
                }
                if (!method.HasBody) continue;
                foreach (var instruction in method.Body.Instructions)
                    switch (instruction.Operand)
                    {
                        case IMethod called: Referenced(called.DeclaringType); break;
                        case IField field: Referenced(field.DeclaringType); break;
                        case ITypeDefOrRef reference: Referenced(reference); break;
                    }
            }
        }
        if (oversized || types.Count > maximumTypes)
        {
            return new(types, "checker graph exceeds the static bounds");

        }
        var methods = types.SelectMany(type => type.Methods).Select((method, index) => (method, index)).ToDictionary(item => item.method, item => item.index);
        var fields = types.SelectMany(type => type.Fields).Select((field, index) => (field, index)).ToDictionary(item => item.field, item => item.index);
        string RoleText(string text)
        {
            if (scopedTypeNames) return RuntimeTypeRoles.Replace(text, types.Select((type, index) => (type.FullName, "$type" + index)).ToArray());
            foreach (var type in types.OrderByDescending(type => type.FullName.Length)) text = text.Replace(type.FullName, "$type" + types.IndexOf(type), StringComparison.Ordinal);
            return text;
        }
        string Signature(TypeSig signature) => RoleText(signature.FullName);
        string Owner(ITypeDefOrRef? reference) => reference?.ResolveTypeDef() is { } type && types.Contains(type)
            ? "$type" + types.IndexOf(type) : reference?.FullName + "@" + reference?.DefinitionAssembly?.FullName;
        string Operand(MethodDef method, Instruction instruction) => instruction.Operand switch
        {
            null => "",
            Instruction target => "@" + method.Body.Instructions.IndexOf(target),
            IList<Instruction> targets => string.Join(",", targets.Select(target => "@" + method.Body.Instructions.IndexOf(target))),
            Local local => "local:" + local.Index,
            Parameter parameter => "parameter:" + parameter.Index,
            IMethod called when called.ResolveMethodDef() is { } target && methods.TryGetValue(target, out var role) => "method:" + role,
            IField reference when reference.ResolveFieldDef() is { } field && fields.TryGetValue(field, out var role) => "field:" + role,
            IMethod called => (canonicalControlFlow ? RoleText(called.FullName) : called.FullName) + "@" + Owner(called.DeclaringType),
            IField field => (canonicalControlFlow ? RoleText(field.FullName) : field.FullName) + "@" + Owner(field.DeclaringType),
            ITypeDefOrRef reference => Owner(reference),
            string text => text,
            IFormattable value => value.ToString(null, CultureInfo.InvariantCulture),
            _ => instruction.Operand.ToString() ?? ""
        };
        var canonical = canonicalControlFlow ? methods.Keys.Where(method => method.HasBody).ToDictionary(method => method,
            method => CanonicalRuntimeBody.Read(method, instruction => maskIntegerConstants && (instruction.IsLdcI4() || instruction.OpCode.Code == Code.Ldc_I8)
                ? "$integer-parameter" : Operand(method, instruction), Signature, Owner)) : [];
        description = JsonSerializer.Serialize(new
        {
            Root = methods[root],
            Types = types.Select(type => new
            {
                type.Attributes, Base = Owner(type.BaseType), type.PackingSize, type.ClassSize,
                Interfaces = type.Interfaces.Select(item => Owner(item.Interface)).ToArray(),
                Fields = type.Fields.Select(field => new { field.Attributes, Type = Signature(field.FieldType), field.FieldOffset,
                    Marshal = field.MarshalType?.ToString(), Initial = Convert.ToHexString(field.InitialValue ?? []) }).ToArray(),
                Methods = type.Methods.Select(method => new
                {
                    method.Attributes, method.ImplAttributes, method.MethodSig.CallingConvention, method.MethodSig.GenParamCount,
                    DispatchName = method.IsVirtual || method.IsConstructor ? method.Name.String : null,
                    Return = Signature(method.ReturnType), Parameters = method.MethodSig.Params.Select(Signature).ToArray(),
                    Import = method.ImplMap?.Module.Name + "!" + method.ImplMap?.Name, ImportAttributes = method.ImplMap?.Attributes,
                    ParameterMetadata = method.ParamDefs.Select(parameter => parameter.Sequence + ":" + parameter.Attributes + ":" +
                        parameter.MarshalType?.GetType().FullName + ":" + parameter.MarshalType).ToArray(),
                    Overrides = method.Overrides.Select(item => (canonicalControlFlow ? RoleText(item.MethodDeclaration.FullName) : item.MethodDeclaration.FullName) + "@" + Owner(item.MethodDeclaration.DeclaringType)).ToArray(),
                    InitLocals = canonical.TryGetValue(method, out var body) ? body.InitLocals : method.HasBody && method.Body.InitLocals,
                    Locals = canonical.TryGetValue(method, out body) ? body.Locals : method.HasBody ? method.Body.Variables.Select(local => Signature(local.Type)).ToArray() : [],
                    Instructions = canonical.TryGetValue(method, out body) ? body.Instructions : method.HasBody ? method.Body.Instructions.Select(instruction => maskIntegerConstants &&
                        (instruction.IsLdcI4() || instruction.OpCode.Code == Code.Ldc_I8) ? "integer-constant" : instruction.OpCode.Code + ":" + Operand(method, instruction)).ToArray() : [],
                    Handlers = canonical.TryGetValue(method, out body) ? body.Handlers.Cast<object>().ToArray() : method.HasBody ? method.Body.ExceptionHandlers.Select(handler => new
                    {
                        handler.HandlerType, Catch = Owner(handler.CatchType), TryStart = method.Body.Instructions.IndexOf(handler.TryStart),
                        TryEnd = method.Body.Instructions.IndexOf(handler.TryEnd), HandlerStart = method.Body.Instructions.IndexOf(handler.HandlerStart),
                        HandlerEnd = method.Body.Instructions.IndexOf(handler.HandlerEnd), Filter = method.Body.Instructions.IndexOf(handler.FilterStart)
                    }).Cast<object>().ToArray() : []
                }).ToArray()
            }).ToArray()
        });
        return new(types, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(description))));
    }
}
