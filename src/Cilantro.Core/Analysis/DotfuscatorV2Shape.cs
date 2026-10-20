using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Complete managed decoder/bridge templates for the reviewed v2 codec.</summary>
internal static partial class DotfuscatorV2Shape
{
    internal sealed record Runtime(MethodDef Decoder, MethodDef Parts, MethodDef Mixer, TypeDef NativeType,
        string EnvironmentFile, uint Seed, string Fingerprint, IReadOnlyList<MethodDef> Methods);

    // Fingerprints cover every instruction, local, handler and call in the closed
    // generated graph. Only generated identifiers, the environment filename and
    // the explicitly extracted xorshift seed vary. Unknown implementations refuse.
    internal static bool Supported(Runtime runtime) => runtime.Fingerprint is
        "5847145b09c15ba9749d1cd237881048e8e85e5ef2be002305dfb1ce28af9d9e" or
        "5e45be2b37aa99e3f1bc7cac488cccca911e753ec4a48703106779a08655bc9a" or
        "d8ece9cd3afba19307bec6cc57ad0fac3160fc6b434f734984e99ab0c6a5ce58";

    [GeneratedRegex("^environment[0-9a-fA-F]{8}\\.bin$", RegexOptions.CultureInvariant)]
    private static partial Regex EnvironmentName();

    internal static IEnumerable<Runtime> Find(ModuleDef module) => FindCore(module, null);

    internal static string Describe(Runtime runtime)
    {
        var description = "";
        foreach (var candidate in FindCore(runtime.Decoder.Module, value => description = value))
            if (candidate.Decoder == runtime.Decoder && candidate.Parts == runtime.Parts) return description;
        return "";
    }

    private static IEnumerable<Runtime> FindCore(ModuleDef module, Action<string>? observed)
    {
        var methods = module.GetTypes().SelectMany(t => t.Methods).ToArray();
        foreach (var decoder in methods.Where(m => m.IsStatic && m.HasBody && m.MethodSig is { Params.Count: 3 } sig &&
                     sig.RetType.ElementType == ElementType.String && sig.Params[0].ElementType == ElementType.String &&
                     sig.Params[1].ElementType == ElementType.I4 && sig.Params[2].FullName == "System.Byte[][]"))
        {
            var callers = methods.Where(m => m.HasBody && m.Body.Instructions.Any(i =>
                i.OpCode.Code == Code.Call && i.Operand is IMethod called && called.ResolveMethodDef() == decoder));
            var parts = callers.SelectMany(m => m.Body.Instructions).Where(i => i.OpCode.Code == Code.Call && i.Operand is IMethod)
                .Select(i => ((IMethod)i.Operand).ResolveMethodDef()).OfType<MethodDef>()
                .Where(m => m.IsStatic && m.HasBody && m.MethodSig is { Params.Count: 1 } sig &&
                    sig.RetType.FullName == "System.Byte[][]" && sig.Params[0].FullName == "System.Reflection.MethodBase")
                .Distinct().ToArray();
            foreach (var part in parts)
            {
                var pending = new Queue<MethodDef>();
                var roles = new Dictionary<MethodDef, int>();
                void Add(MethodDef method) { if (method.Module == module && roles.TryAdd(method, roles.Count)) pending.Enqueue(method); }
                Add(decoder); Add(part);
                while (pending.TryDequeue(out var method) && roles.Count <= 128)
                {
                    if (!method.HasBody) continue;
                    foreach (var i in method.Body.Instructions)
                        if (i.Operand is IMethod reference && reference.ResolveMethodDef() is { } target) Add(target);
                }
                var native = roles.Keys.Where(m => m.IsPinvokeImpl && m.ImplMap?.Name == "__eck" &&
                    m.ImplMap.Module.Name.String is "Runtime.Extensions.dll" or "Runtime.Extensions").Select(m => m.DeclaringType).Distinct().ToArray();
                if (native.Length != 1 || roles.Count > 128) continue;
                // Initialization is an implicit edge of every static bridge call.
                if (native[0].FindStaticConstructor() is { } initializer) Add(initializer);
                while (pending.TryDequeue(out var method) && roles.Count <= 128)
                    if (method.HasBody)
                        foreach (var i in method.Body.Instructions)
                            if (i.Operand is IMethod reference && reference.ResolveMethodDef() is { } target) Add(target);
                if (roles.Count > 128 || roles.Keys.Any(m => m.HasGenericParameters || m.HasBody && m.Body.Instructions.Count > 4096)) continue;
                var mixers = roles.Keys.Where(m => m.IsStatic && m.HasBody && m.MethodSig is { Params.Count: 1 } sig &&
                    sig.RetType.FullName == "System.Byte[]" && sig.Params[0].FullName == "System.Byte[]" &&
                    m.Body.Instructions.FirstOrDefault()?.IsLdcI4() == true).ToArray();
                var files = roles.Keys.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions)
                    .Where(i => i.OpCode.Code == Code.Ldstr && i.Operand is string text && EnvironmentName().IsMatch(text))
                    .Select(i => (string)i.Operand).Distinct(StringComparer.Ordinal).ToArray();
                if (mixers.Length != 1 || files.Length != 1) continue;
                var mixer = mixers[0];
                var nativeType = native[0];
                var fields = new Dictionary<FieldDef, int>();
                string Type(TypeSig sig) => sig.FullName;
                string Owner(ITypeDefOrRef? type) => type?.ResolveTypeDef() is { } definition && definition.Module == module
                    ? definition == decoder.DeclaringType ? "$host" : definition == nativeType ? "$native" : "$local:" + definition.FullName
                    : type?.FullName + "@" + type?.DefinitionAssembly?.FullName;
                string Operand(MethodDef method, Instruction i) => i.Operand switch
                {
                    null => "",
                    Instruction target => "@" + method.Body.Instructions.IndexOf(target),
                    IList<Instruction> targets => string.Join(",", targets.Select(t => "@" + method.Body.Instructions.IndexOf(t))),
                    Local local => "local:" + local.Index,
                    Parameter parameter => "parameter:" + parameter.Index,
                    IMethod called when called.ResolveMethodDef() is { } target && roles.TryGetValue(target, out var role) => "method:" + role,
                    IField reference when reference.ResolveFieldDef() is { } field && field.Module == module => Field(field),
                    IMethod called => called.FullName + "@" + Owner(called.DeclaringType),
                    IField field => field.FullName + "@" + Owner(field.DeclaringType),
                    ITypeDefOrRef type => Owner(type),
                    string text => text == files[0] ? "$environment" : text,
                    _ when method == mixer && i == mixer.Body.Instructions[0] => "$seed",
                    IFormattable number => number.ToString(null, CultureInfo.InvariantCulture),
                    _ => i.Operand.ToString() ?? ""
                };
                string Field(FieldDef field)
                {
                    if (!fields.TryGetValue(field, out var role)) fields.Add(field, role = fields.Count);
                    return $"field:{role}:{Owner(field.DeclaringType)}:{field.Attributes}:{Type(field.FieldType)}:{Convert.ToHexString(field.InitialValue ?? [])}";
                }
                string Import(MethodDef method)
                {
                    var library = method.ImplMap?.Module.Name.String;
                    // Windows resolves this system DLL without regard to case.
                    // Export names and all other native library names stay exact.
                    if (string.Equals(library, "kernel32.dll", StringComparison.OrdinalIgnoreCase)) library = "kernel32.dll";
                    return library + "!" + method.ImplMap?.Name;
                }
                var description = JsonSerializer.Serialize(roles.Select(entry => new
                {
                    Role = entry.Value, Owner = Owner(entry.Key.DeclaringType), entry.Key.Attributes, entry.Key.ImplAttributes,
                    Return = Type(entry.Key.ReturnType), Parameters = entry.Key.MethodSig.Params.Select(Type).ToArray(),
                    Import = Import(entry.Key),
                    ImportAttributes = entry.Key.ImplMap?.Attributes,
                    ParameterMetadata = entry.Key.ParamDefs.Select(p => p.Sequence + ":" + p.Attributes + ":" +
                        (p.MarshalType is null ? "" : p.MarshalType.GetType().FullName + ":" + p.MarshalType)).ToArray(),
                    InitLocals = entry.Key.HasBody && entry.Key.Body.InitLocals,
                    Locals = entry.Key.HasBody ? entry.Key.Body.Variables.Select(v => Type(v.Type)).ToArray() : [],
                    Instructions = entry.Key.HasBody ? entry.Key.Body.Instructions.Select(i => i.OpCode.Code + ":" + Operand(entry.Key, i)).ToArray() : [],
                    Handlers = entry.Key.HasBody ? entry.Key.Body.ExceptionHandlers.Select(h => new {
                        h.HandlerType, Catch = h.CatchType?.FullName,
                        TryStart = entry.Key.Body.Instructions.IndexOf(h.TryStart), TryEnd = entry.Key.Body.Instructions.IndexOf(h.TryEnd),
                        HandlerStart = entry.Key.Body.Instructions.IndexOf(h.HandlerStart), HandlerEnd = entry.Key.Body.Instructions.IndexOf(h.HandlerEnd),
                        Filter = entry.Key.Body.Instructions.IndexOf(h.FilterStart)
                    }).ToArray() : []
                }).ToArray());
                observed?.Invoke(description);
                yield return new(decoder, part, mixer, nativeType, files[0],
                    unchecked((uint)mixer.Body.Instructions[0].GetLdcI4Value()), Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(description))), roles.Keys.ToArray());
            }
        }
    }
}
