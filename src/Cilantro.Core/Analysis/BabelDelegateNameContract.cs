using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Proves the private delegate-name formatter's complete consumers on proof copies.</summary>
internal sealed record BabelDelegateNameContract(MethodDef Formatter, MethodDef Caller, MethodDef Builder,
    FieldDef Cache, FieldDef Module, FieldDef Name)
{
    // Formatter, cache caller, delegate builder. Framework assembly identities remain in the proof.
    private static readonly HashSet<string> Reviewed =
    [
        "C4C7A1C43919BB6413C347B4191474F39351FC602502F5196A049E57E4DFDAF0/BFBB1227DDCCE5DB782AEF7E1A492F4CF74B82907B3334B6E13691C75299BF08/FCF61C68FB016F410A12CC6FB581AB8DB0D183A7430A2B70480F5D81BD564FAE",
        "B262C83F79DC3FE5E8892C4F872D0FAE50BF77AA17EBD91A58E00870CEF14CF3/902089B831AA3FA7E0E32E1AF0B6F704991C0960F8533F6E166470B6C991A7B3/FF9503EA974F2C6636B31BAB2E9978A3DB08460E85FA70392B1ADAC50BFA547A",
        "3F78CBA9369DF7C7BDD922A069CF96A948016A833BF29AA9DD0DB125BA3DB49A/793D5649B0B91ADD93881764137EDE94ADA911ED0FB929A70F55CA9D5FA97E28/3825893B90FAE47239FE89A7484C1F2734D7149F8F7447C744CFC68E2BEA5228"
    ];

    internal static BabelDelegateNameContract? Find(ModuleDefMD original, byte[] image)
    {
        using var proof = ModuleDefMD.Load(image);
        var methods = proof.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToArray();
        foreach (var formatter in methods.Where(method => method.IsStatic && method.ReturnType.ElementType == ElementType.String &&
            Parameters(method, "System.Type", "System.Type[]") && method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called && called.FullName == "System.String System.Type::get_FullName()")))
        {
            var callers = methods.Where(method => method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called && called.ResolveMethodDef() == formatter)).ToArray();
            if (callers.Length != 1) continue;
            var caller = callers[0];
            if (caller.IsStatic || caller.HasGenericParameters || caller.MethodSig.Params.Count != 2 || caller.ReturnType.FullName != "System.Type") continue;
            var names = Fields(caller, "System.String");
            var caches = Fields(caller, "System.Collections.Hashtable");
            var builders = caller.Body.Instructions.Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef()).OfType<MethodDef>()
                .Where(method => !method.IsStatic && method.ReturnType.FullName == "System.Type" && Parameters(method, "System.String", "System.Type", "System.Type[]"))
                .Distinct().ToArray();
            if (names.Length != 1 || caches.Length != 1 || builders.Length != 1 || builders[0].DeclaringType != caller.DeclaringType) continue;
            var builder = builders[0]; var modules = Fields(builder, "System.Reflection.Emit.ModuleBuilder");
            if (modules.Length != 1 || caches[0].DeclaringType != caller.DeclaringType || modules[0].DeclaringType != caller.DeclaringType ||
                caller.MethodSig.Params[0].ToTypeDefOrRef()?.ResolveTypeDef() != names[0].DeclaringType ||
                caller.MethodSig.Params[1].ToTypeDefOrRef()?.ResolveTypeDef() is not { } signatureOwner) continue;
            // The only reads are the reviewed caller. One descriptor-reader store may initialize
            // the name; dynamic freshness is checked again before summarizing the formatter.
            var uses = methods.SelectMany(method => method.Body.Instructions.Where(instruction =>
                instruction.Operand is IField field && field.ResolveFieldDef() == names[0]).Select(instruction => (method, instruction))).ToArray();
            if (uses.Any(use => use.method != caller && use.instruction.OpCode.Code != Code.Stfld) ||
                uses.Count(use => use.method != caller) != 1 || uses.Any(use => use.instruction.OpCode.Code is not (Code.Ldfld or Code.Stfld))) continue;
            var targets = new[] { formatter, caller, builder };
            if (targets.Any(method => original.ResolveToken(method.MDToken) is not MethodDef source || Raw(source) != Raw(method))) continue;
            if (new[] { names[0], caches[0], modules[0] }.Any(field => original.ResolveToken(field.MDToken) is not FieldDef source ||
                source.FieldSig is null || source.FullName != field.FullName || source.Attributes != field.Attributes || source.DeclaringType?.MDToken != field.DeclaringType.MDToken)) continue;
            if (!References(original, formatter.MDToken, true).SequenceEqual(References(proof, formatter.MDToken, true)) ||
                !References(original, names[0].MDToken, false).SequenceEqual(References(proof, names[0].MDToken, false))) continue;
            try
            {
                var roles = new Dictionary<TypeDef, string>
                { [caller.DeclaringType] = "factory", [names[0].DeclaringType] = "descriptor", [signatureOwner] = "signature" };
                if (roles.Count != 3 || targets.Any(method => !GeneratedRuntimeBodyNormalization.TryNormalize(method, false, out _))) continue;
                var fingerprint = string.Join('/', targets.Select(method => Fingerprint(method, roles)));
                if (!Reviewed.Contains(fingerprint)) continue;
                return new((MethodDef)original.ResolveToken(formatter.MDToken), (MethodDef)original.ResolveToken(caller.MDToken),
                    (MethodDef)original.ResolveToken(builder.MDToken), (FieldDef)original.ResolveToken(caches[0].MDToken),
                    (FieldDef)original.ResolveToken(modules[0].MDToken), (FieldDef)original.ResolveToken(names[0].MDToken));
            }
            catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or KeyNotFoundException or IndexOutOfRangeException)
            { /* A malformed or changed contract supplies no summary. */ }
        }
        return null;
    }

    private static bool Parameters(MethodDef method, params string[] types) => method.MethodSig.Params.Select(type => type.FullName).SequenceEqual(types);
    private static IEnumerable<string> References(ModuleDef module, MDToken token, bool methodReference) => module.GetTypes()
        .SelectMany(type => type.Methods).Where(method => method.HasBody).SelectMany(method => method.Body.Instructions.Select((instruction, index) =>
        {
            IMemberDef? target = methodReference ? (instruction.Operand as IMethod)?.ResolveMethodDef() : (instruction.Operand as IField)?.ResolveFieldDef();
            return target?.Module == module && target.MDToken == token ? method.MDToken + ":" + index + ":" + instruction.OpCode.Code : null;
        })).OfType<string>();
    private static FieldDef[] Fields(MethodDef method, string type) => method.Body.Instructions.Select(instruction =>
        (instruction.Operand as IField)?.ResolveFieldDef()).OfType<FieldDef>().Where(field => field.FieldType.FullName == type).Distinct().ToArray();

    private static string Fingerprint(MethodDef method, Dictionary<TypeDef, string> roles)
    {
        string Text(string value)
        {
            foreach (var role in roles.OrderByDescending(pair => pair.Key.FullName.Length)) value = value.Replace(role.Key.FullName, "$" + role.Value, StringComparison.Ordinal);
            return value;
        }
        string Owner(ITypeDefOrRef? type) => type is null ? "" : type.ResolveTypeDef() is { } definition && roles.TryGetValue(definition, out var role)
            ? "$" + role : type.FullName + "@" + type.DefinitionAssembly?.FullName;
        string Operand(Instruction instruction) => instruction.Operand switch
        {
            IMethod reference when reference.ResolveMethodDef() is { } target && roles.ContainsKey(target.DeclaringType) =>
                Owner(target.DeclaringType) + "/method:" + target.DeclaringType.Methods.IndexOf(target) + ":" + Text(target.MethodSig.ToString()) + ":" + target.Attributes + ":" + target.ImplAttributes,
            IField reference when reference.ResolveFieldDef() is { } field && roles.ContainsKey(field.DeclaringType) =>
                Owner(field.DeclaringType) + "/field:" + field.DeclaringType.Fields.IndexOf(field) + ":" + Text(field.FieldType.FullName) + ":" + field.Attributes,
            IMethod reference => reference.FullName + "@" + reference.DeclaringType.DefinitionAssembly?.FullName,
            IField reference => reference.FullName + "@" + reference.DeclaringType.DefinitionAssembly?.FullName,
            ITypeDefOrRef type => Owner(type), Parameter parameter => "parameter:" + parameter.Index,
            _ => instruction.Operand?.ToString() ?? ""
        };
        var body = CanonicalRuntimeBody.Read(method, Operand, signature => Text(signature.FullName), Owner);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(body))));
    }

    private static string Raw(MethodDef method)
    {
        if (!method.HasBody || method.MethodSig is null) return "missing body or signature";
        var il = method.Body.Instructions;
        string Operand(object? operand) => operand switch
        {
            Instruction target => "@" + il.IndexOf(target), IList<Instruction> targets => string.Join(',', targets.Select(target => il.IndexOf(target))),
            Local local => "local:" + local.Index, Parameter parameter => "parameter:" + parameter.Index,
            IFullName member => member.FullName, _ => operand?.ToString() ?? ""
        };
        return JsonSerializer.Serialize(new { method.Attributes, method.ImplAttributes, method.Body.InitLocals, Signature = method.MethodSig.ToString(),
            Locals = method.Body.Variables.Select(local => local.Type.FullName), Instructions = il.Select(instruction => instruction.OpCode.Code + ":" + Operand(instruction.Operand)),
            Handlers = method.Body.ExceptionHandlers.Select(handler => new { handler.HandlerType, Catch = handler.CatchType?.FullName,
                Start = il.IndexOf(handler.TryStart), End = il.IndexOf(handler.TryEnd), Handler = il.IndexOf(handler.HandlerStart), HandlerEnd = il.IndexOf(handler.HandlerEnd), Filter = il.IndexOf(handler.FilterStart) }) });
    }
}
