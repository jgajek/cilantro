using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

internal static class DotfuscatorResourceShape
{
    internal sealed record Runtime(TypeDef Manager, long Seed, IReadOnlySet<string> Keys, string Fingerprint);

    internal static bool Supported(Runtime runtime) => runtime.Fingerprint is
        "dedd235058b4b45fb57e67c9443040dc655799793adda94e8ab83a65a2cd3301" or
        "d0c484d537134ca9af85e0e07ff515c8fb722b63240adaedd223e95ddb8a4e44" or
        "4801a6599f3651b42bbae772f6acb25169705342782d2ad23f310da5c3b38051";

    internal static IEnumerable<Runtime> Find(ModuleDef module)
    {
        foreach (var manager in module.GetTypes().Where(type => type.BaseType?.FullName == "System.Resources.ResourceManager"))
        {
            var constructors = manager.Methods.Where(method => method.IsInstanceConstructor && method.HasBody).ToArray();
            if (constructors.Length != 4 || manager.HasGenericParameters || manager.FindStaticConstructor() is not null) continue;
            var literals = constructors.Select(method => method.Body.Instructions.Where(i => i.OpCode.Code == Code.Ldstr)
                .Select(i => (string)i.Operand).ToArray()).ToArray();
            if (literals.Any(items => items.Length != 2) || literals.Any(items => !items.SequenceEqual(literals[0])) ||
                !long.TryParse(literals[0][0], NumberStyles.None, CultureInfo.InvariantCulture, out var seed) ||
                literals[0][1].Length > 65536) continue;
            var keyText = literals[0][1];
            var types = new List<TypeDef> { manager };
            foreach (var method in manager.Methods.Where(method => method.HasBody))
                foreach (var instruction in method.Body.Instructions)
                    if (instruction.Operand is IMethod called && called.ResolveMethodDef() is { } target &&
                        target.Module == module && !types.Contains(target.DeclaringType)) types.Add(target.DeclaringType);
            if (types.Count != 2 || types.Any(type => type.Methods.Count > 32 || type.Fields.Count > 16 ||
                    type.Methods.Any(method => !method.HasBody || method.Body.Instructions.Count > 2048))) continue;
            var methods = types.SelectMany(type => type.Methods).Select((method, index) => (method, index))
                .ToDictionary(item => item.method, item => item.index);
            var fields = types.SelectMany(type => type.Fields).Select((field, index) => (field, index))
                .ToDictionary(item => item.field, item => item.index);
            string Owner(ITypeDefOrRef? type) => type?.ResolveTypeDef() is { } local && types.Contains(local)
                ? "$type" + types.IndexOf(local) : type?.FullName + "@" + type?.DefinitionAssembly?.FullName;
            string Operand(MethodDef method, Instruction instruction) => instruction.Operand switch
            {
                null => "",
                Instruction target => "@" + method.Body.Instructions.IndexOf(target),
                IList<Instruction> targets => string.Join(",", targets.Select(target => "@" + method.Body.Instructions.IndexOf(target))),
                Local local => "local:" + local.Index,
                Parameter parameter => "parameter:" + parameter.Index,
                IMethod called when called.ResolveMethodDef() is { } target && methods.TryGetValue(target, out var role) => "method:" + role,
                IField reference when reference.ResolveFieldDef() is { } field && fields.TryGetValue(field, out var role) => "field:" + role,
                IMethod called => called.FullName + "@" + Owner(called.DeclaringType),
                IField field => field.FullName + "@" + Owner(field.DeclaringType),
                ITypeDefOrRef type => Owner(type),
                string text => text == literals[0][0] ? "$seed" : text == keyText ? "$keys" : text,
                IFormattable number => number.ToString(null, CultureInfo.InvariantCulture),
                _ => instruction.Operand.ToString() ?? ""
            };
            var description = JsonSerializer.Serialize(types.Select(type => new
            {
                type.Attributes, Base = Owner(type.BaseType), Interfaces = type.Interfaces.Select(item => Owner(item.Interface)).ToArray(),
                Fields = type.Fields.Select(field => new { field.Attributes, Type = field.FieldType.FullName, Initial = Convert.ToHexString(field.InitialValue ?? []) }).ToArray(),
                Methods = type.Methods.Select(method => new
                {
                    method.Attributes, method.ImplAttributes, Name = method.IsPrivate ? "$helper" : method.Name.String,
                    Signature = method.MethodSig.ToString(), method.Body.InitLocals,
                    Locals = method.Body.Variables.Select(local => local.Type.FullName).ToArray(),
                    Instructions = method.Body.Instructions.Select(instruction => instruction.OpCode.Code + ":" + Operand(method, instruction)).ToArray(),
                    Handlers = method.Body.ExceptionHandlers.Select(handler => new
                    {
                        handler.HandlerType, Catch = Owner(handler.CatchType),
                        TryStart = method.Body.Instructions.IndexOf(handler.TryStart), TryEnd = method.Body.Instructions.IndexOf(handler.TryEnd),
                        HandlerStart = method.Body.Instructions.IndexOf(handler.HandlerStart), HandlerEnd = method.Body.Instructions.IndexOf(handler.HandlerEnd),
                        Filter = method.Body.Instructions.IndexOf(handler.FilterStart)
                    }).ToArray()
                }).ToArray()
            }).ToArray());
            yield return new(manager, seed, keyText.Split('+').ToHashSet(StringComparer.Ordinal),
                Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(description))));
        }
    }
}
