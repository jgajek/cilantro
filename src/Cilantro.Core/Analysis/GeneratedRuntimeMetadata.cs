using System.Text.Json;
using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

/// <summary>Metadata not represented by the generated runtime instruction graph.</summary>
internal static class GeneratedRuntimeMetadata
{
    internal static string Describe(TypeDef type)
    {
        string Signature(TypeSig? signature) => signature is null ? "" : signature.ElementType + ":" + signature.FullName + "@" +
            signature.ToTypeDefOrRef()?.DefinitionAssembly?.FullName + (signature.Next is { } next ? ":" + Signature(next) : "") +
            (signature is GenericInstSig instance ? "<" + string.Join(",", instance.GenericArguments.Select(Signature)) + ">" : "");
        string Argument(CAArgument argument) => argument.Type.FullName + ":" + (argument.Value is IList<CAArgument> array
            ? string.Join(",", array.Select(Argument)) : Convert.ToString(argument.Value, System.Globalization.CultureInfo.InvariantCulture));
        string Attributes(IList<CustomAttribute> attributes) => string.Join(";", attributes.Select(attribute =>
        {
            // Force lazy decoding before observing the fallback raw blob. Otherwise
            // equivalent attributes differ merely because one reader parsed them first.
            var arguments = attribute.ConstructorArguments.Select(Argument).ToArray();
            var named = attribute.NamedArguments.Select(argument => argument.Name + ":" + argument.IsField + ":" + Argument(argument.Argument)).ToArray();
            return attribute.Constructor.FullName + "@" + attribute.Constructor.DeclaringType.DefinitionAssembly?.FullName + ":" +
                Convert.ToHexString(attribute.RawData ?? []) + ":" + string.Join(",", arguments) + ":" + string.Join(",", named);
        }));
        return JsonSerializer.Serialize(new
        {
            Type = Attributes(type.CustomAttributes),
            Fields = type.Fields.Select(field => new { field.Name, Signature = Signature(field.FieldType), Attributes = Attributes(field.CustomAttributes), ConstantType = field.Constant?.Type,
                Constant = Convert.ToString(field.Constant?.Value, System.Globalization.CultureInfo.InvariantCulture) }),
            Methods = type.Methods.Select(method => new { method.Name, Return = Signature(method.ReturnType), ParametersTypes = method.MethodSig.Params.Select(Signature),
                Attributes = Attributes(method.CustomAttributes), Security = method.DeclSecurities.Count,
                Parameters = method.ParamDefs.Select(parameter => Attributes(parameter.CustomAttributes)) })
        });
    }
}
