using System.Globalization;
using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Complete structural recognition of the supported managed bootstrap implementation.</summary>
/// <remarks>Generated identifiers and payload bytes are not part of the template. Unknown bodies refuse.</remarks>
internal static class ManagedBootstrapShape
{
    private static readonly Lazy<string> Template = new(() => {
        using var stream = typeof(ManagedBootstrapShape).Assembly.GetManifestResourceStream("Cilantro.Core.ManagedBootstrapTemplate.json")
            ?? throw new InvalidOperationException("Managed bootstrap template missing.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Trim();
    });
    internal static bool Matches(ModuleDef module) => Describe(module) is { } actual && actual == Template.Value;

    internal static string? Describe(ModuleDef module)
    {
        var types = module.GetTypes().Where(t => !t.IsGlobalModuleType).ToArray();
        if (types.Length != 1 || module.GlobalType.Methods.Count != 0 || module.GlobalType.Fields.Count != 0 ||
            module.Resources.Count != 1 || module.Resources[0] is not EmbeddedResource resource || !module.IsILOnly || module.NativeEntryPoint != 0 || module.EntryPoint is not null) return null;
        var owner = types[0];
        if (owner.Methods.Count != 5 || owner.Fields.Count != 2 || owner.HasGenericParameters || owner.Interfaces.Count != 0 || owner.Properties.Count != 0 || owner.Events.Count != 0) return null;
        var starts = owner.Methods.Where(m => m.IsStatic && !m.IsConstructor && m.ReturnType.ElementType == ElementType.Void && m.Parameters.Count == 0).ToArray();
        if (starts.Length != 1 || !starts[0].HasBody) return null;
        var startup = starts[0];
        var callbacks = startup.Body.Instructions.Where(i => i.OpCode.Code == Code.Ldftn).Select(i => (i.Operand as IMethod)?.ResolveMethodDef()).Distinct().ToArray();
        if (callbacks.Length != 1 || callbacks[0] is not { } callback || callback.DeclaringType != owner) return null;
        var constructors = owner.Methods.Where(m => m.IsInstanceConstructor).ToArray();
        var initializers = owner.Methods.Where(m => m.IsStaticConstructor).ToArray();
        if (constructors.Length != 1 || initializers.Length != 1 || callback == startup || callback.IsConstructor) return null;
        var roles = new Dictionary<MethodDef,string>{{startup,"start"},{callback,"resolve-assembly"},{constructors[0],"constructor"},{initializers[0],"initializer"}};
        var remaining = owner.Methods.Where(m => !roles.ContainsKey(m)).ToArray();
        if (remaining.Length != 1) return null;
        roles.Add(remaining[0],"resolve-resource");
        var fields = new Dictionary<FieldDef,string>();
        foreach (var field in owner.Fields) {
            if (field.InitialValue is {Length:>0} || !field.IsStatic) return null;
            var role = field.FieldType.FullName switch { "System.Object" => "lock", "System.Reflection.Assembly" => "assembly", _ => null };
            if (role is null || fields.ContainsValue(role)) return null;
            fields[field] = role;
        }
        if (owner.Methods.Any(m => !m.HasBody || m.HasGenericParameters || m.ImplMap is not null)) return null;
        string Operand(MethodDef method, object? value) => value switch {
            null => "",
            Instruction target => "@" + method.Body.Instructions.IndexOf(target),
            IList<Instruction> targets => string.Join(",",targets.Select(t => "@"+method.Body.Instructions.IndexOf(t))),
            Local local => "local:"+local.Index,
            Parameter parameter => "parameter:"+parameter.Index,
            IMethod called when called.ResolveMethodDef() is { } resolved && roles.TryGetValue(resolved,out var role) => "method:"+role,
            IField field when field.ResolveFieldDef() is { } resolved && fields.TryGetValue(resolved,out var role) => "field:"+role,
            ITypeDefOrRef type when type == owner => "owner",
            string text when text == resource.Name.String => "$payload-resource",
            string text => "literal:"+text,
            ITypeDefOrRef type => type.FullName+"@"+type.DefinitionAssembly?.FullName,
            IMemberRef member => member.FullName+"@"+member.DeclaringType?.DefinitionAssembly?.FullName,
            IFormattable formatted => formatted.ToString(null,CultureInfo.InvariantCulture),
            _ => value.ToString() ?? ""
        };
        string TypeKey(TypeSig type) => type.FullName+"@"+type.ToTypeDefOrRef()?.DefinitionAssembly?.FullName;
        return JsonSerializer.Serialize(new {
            TypeAttributes=owner.Attributes, Base=owner.BaseType?.FullName+"@"+owner.BaseType?.DefinitionAssembly?.FullName,
            Fields=fields.OrderBy(p=>p.Value,StringComparer.Ordinal).Select(p=>new {Role=p.Value,p.Key.Attributes,Type=TypeKey(p.Key.FieldType)}),
            Methods=roles.OrderBy(p=>p.Value,StringComparer.Ordinal).Select(p=>new {
                Role=p.Value,p.Key.Attributes,p.Key.ImplAttributes,Signature=p.Key.MethodSig.ToString(),Return=TypeKey(p.Key.ReturnType),Parameters=p.Key.MethodSig.Params.Select(TypeKey),p.Key.Body.InitLocals,
                Locals=p.Key.Body.Variables.Select(v=>TypeKey(v.Type)),
                Instructions=p.Key.Body.Instructions.Select(i=>new {Op=i.OpCode.Code.ToString(),Operand=Operand(p.Key,i.Operand)}),
                Handlers=p.Key.Body.ExceptionHandlers.Select(h=>new {h.HandlerType,Catch=h.CatchType?.FullName,TryStart=Operand(p.Key,h.TryStart),TryEnd=Operand(p.Key,h.TryEnd),HandlerStart=Operand(p.Key,h.HandlerStart),HandlerEnd=Operand(p.Key,h.HandlerEnd),Filter=Operand(p.Key,h.FilterStart)})
            })
        });
    }
}
