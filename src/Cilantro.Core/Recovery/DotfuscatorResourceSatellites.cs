using System.Globalization;
using System.Security.Cryptography;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Reads resource-only culture companions as data, never as executable libraries.</summary>
internal static class DotfuscatorResourceSatellites
{
    internal const string Fact = "dotfuscator.resources.satellites";
    internal sealed record Restored(string Source, string Culture, string FileName, byte[] Bytes, int Entries, string SourceSha256, int Containers = 1);

    internal static bool TryRestore(ArtifactContext context, DotfuscatorResourceShape.Runtime runtime,
        out IReadOnlyList<Restored> satellites, out string why)
    {
        satellites = [];
        why = "";
        var restored = new List<Restored>();
        try
        {
            var assembly = context.Module.Assembly;
            if (assembly is null) throw new InvalidDataException("Resource owner has no assembly identity.");
            var contractVersion = ContractVersion(assembly);
            var requiredCulture = RequiredNeutralSatellite(assembly);
            var name = assembly.Name.String + ".resources.dll";
            if (name.Any(character => "<>:\"/\\|?*".Contains(character)) || Path.GetFileName(name) != name)
                throw new InvalidDataException("Invalid satellite assembly name.");
            var directory = Path.GetDirectoryName(context.InputPath)!;
            long total = 0;
            var visited = 0;
            foreach (var folder in Directory.EnumerateDirectories(directory))
            {
                if (++visited > 512) throw new InvalidDataException("Satellite directory search exceeds 512 directories.");
                var path = Path.Combine(folder, name);
                if (!File.Exists(path)) continue;
                if ((File.GetAttributes(folder) & System.IO.FileAttributes.ReparsePoint) != 0 ||
                    (File.GetAttributes(path) & System.IO.FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("Satellite companions cannot be symbolic links.");
                var culture = Path.GetFileName(folder);
                if (CultureInfo.GetCultureInfo(culture).Name != culture || culture.Length == 0)
                    throw new InvalidDataException("Satellite directory is not a canonical culture name.");
                var length = new FileInfo(path).Length;
                total += length;
                if (length > DotfuscatorResourceCodec.MaximumLength || total > 64L * 1024 * 1024 || restored.Count >= 128)
                    throw new InvalidDataException("Satellite companions exceed the input bounds.");
                var original = File.ReadAllBytes(path);
                using var module = ModuleDefMD.Load(original, new ModuleCreationOptions { TryToLoadPdbFromDisk = false });
                if (module.Assembly is not { } identity || identity.Name.String != assembly.Name.String + ".resources" ||
                    identity.Culture.String != culture || identity.Version != contractVersion ||
                    !(identity.PublicKeyToken?.Data ?? []).SequenceEqual(assembly.PublicKeyToken?.Data ?? []) ||
                    identity.Modules.Count != 1 || module.ManagedEntryPoint is not null || module.NativeEntryPoint != 0 ||
                    module.Types.Count != 1 || !module.GlobalType.IsGlobalModuleType ||
                    module.GlobalType.HasMethods || module.GlobalType.HasFields || module.GlobalType.HasNestedTypes ||
                    module.Resources.Count == 0 || module.Resources.Any(resource => resource is not EmbeddedResource))
                    throw new InvalidDataException($"{culture}: satellite is not a matching resource-only assembly.");
                var entries = 0;
                foreach (var resource in module.Resources.OfType<EmbeddedResource>().ToArray())
                {
                    if (!resource.Name.String.EndsWith("." + culture + ".resources", StringComparison.Ordinal))
                        throw new InvalidDataException($"{culture}: unreviewed satellite resource name.");
                    if (!DotfuscatorResourceCodec.TryRestore(resource.CreateReader().ToArray(), runtime.Seed, runtime.Keys,
                            out var bytes, out var count, out var reason))
                        throw new InvalidDataException($"{culture}/{resource.Name}: {reason}");
                    module.Resources[module.Resources.IndexOf(resource)] = new EmbeddedResource(resource.Name, bytes, resource.Attributes);
                    entries += count;
                }
                using var output = new MemoryStream();
                module.Write(output);
                if (output.Length > DotfuscatorResourceCodec.MaximumLength)
                    throw new InvalidDataException("Restored satellite exceeds the output bound.");
                var image = output.ToArray();
                using var roundTrip = ModuleDefMD.Load(image);
                if (roundTrip.Assembly.FullName != identity.FullName ||
                    !ResourceInspector.Inspect(roundTrip).Select(resource => (resource.Name, resource.Sha256))
                        .SequenceEqual(ResourceInspector.Inspect(module).Select(resource => (resource.Name, resource.Sha256))))
                    throw new InvalidDataException("Restored satellite did not round-trip.");
                restored.Add(new(path, culture, name, image, entries, Convert.ToHexStringLower(SHA256.HashData(original)), module.Resources.Count));
            }
            if (requiredCulture is not null && !restored.Any(satellite => satellite.Culture == requiredCulture))
                throw new InvalidDataException($"Required fallback satellite '{requiredCulture}' is unavailable.");
            satellites = restored.OrderBy(satellite => satellite.Culture, StringComparer.Ordinal).ToArray();
            return true;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or
            BadImageFormatException or InvalidOperationException or NotSupportedException or OverflowException or dnlib.DotNet.Writer.ModuleWriterException)
        {
            why = exception.Message;
            return false;
        }
    }

    internal static Version ContractVersion(AssemblyDef assembly)
    {
        var contracts = assembly.CustomAttributes.Where(attribute => attribute.TypeFullName == "System.Resources.SatelliteContractVersionAttribute").ToArray();
        if (contracts.Length == 0) return assembly.Version;
        if (contracts.Length != 1) throw new InvalidDataException("Ambiguous satellite contract version attributes.");
        var attribute = contracts[0];
        var constructor = attribute.Constructor;
        var signature = constructor?.MethodSig;
        if (constructor is null || constructor.Name != ".ctor" || constructor.DeclaringType is not TypeRef ||
            constructor.DeclaringType.DefinitionAssembly is not AssemblyRef scope || !FrameworkScope(scope) ||
            signature is null || signature.CallingConvention != CallingConvention.HasThis || signature.GenParamCount != 0 ||
            signature.RetType.ElementType != ElementType.Void || signature.Params.Count != 1 ||
            signature.Params[0].ElementType != ElementType.String || signature.ParamsAfterSentinel is { Count: > 0 } ||
            attribute.ConstructorArguments.Count != 1 || attribute.ConstructorArguments[0].Type.ElementType != ElementType.String ||
            attribute.NamedArguments.Count != 0)
            throw new InvalidDataException("Unreviewed satellite contract version attribute identity or signature.");
        var value = attribute.ConstructorArguments[0].Value;
        var text = value switch { UTF8String utf8 => utf8.String, string literal => literal, _ => null };
        if (text is null || text.Length > 64 || !Version.TryParse(text, out var version) ||
            version.Major > ushort.MaxValue || version.Minor > ushort.MaxValue || version.Build > ushort.MaxValue || version.Revision > ushort.MaxValue)
            throw new InvalidDataException("Invalid satellite contract version.");
        return new Version(version.Major, version.Minor, Math.Max(version.Build, 0), Math.Max(version.Revision, 0));
    }

    internal static string? RequiredNeutralSatellite(AssemblyDef assembly)
    {
        var attributes = assembly.CustomAttributes.Where(attribute => attribute.TypeFullName == "System.Resources.NeutralResourcesLanguageAttribute").ToArray();
        if (attributes.Length == 0) return null;
        if (attributes.Length != 1) throw new InvalidDataException("Ambiguous neutral resource language attributes.");
        var attribute = attributes[0];
        var constructor = attribute.Constructor;
        var signature = constructor?.MethodSig;
        if (constructor is null || constructor.Name != ".ctor" || constructor.DeclaringType is not TypeRef ||
            constructor.DeclaringType.DefinitionAssembly is not AssemblyRef scope || !FrameworkScope(scope) ||
            signature is null || signature.CallingConvention != CallingConvention.HasThis || signature.GenParamCount != 0 ||
            signature.RetType.ElementType != ElementType.Void || signature.Params.Count is not (1 or 2) ||
            signature.Params[0].ElementType != ElementType.String || signature.ParamsAfterSentinel is { Count: > 0 } ||
            attribute.ConstructorArguments.Count != signature.Params.Count || attribute.NamedArguments.Count != 0 ||
            attribute.ConstructorArguments[0].Type.ElementType != ElementType.String)
            throw new InvalidDataException("Unreviewed neutral resource language attribute identity or signature.");
        var text = attribute.ConstructorArguments[0].Value switch { UTF8String utf8 => utf8.String, string literal => literal, _ => null };
        if (text is null || text.Length > 128) throw new InvalidDataException("Invalid neutral resource culture.");
        var culture = CultureInfo.GetCultureInfo(text).Name;
        if (signature.Params.Count == 1) return null;
        const string fallback = "System.Resources.UltimateResourceFallbackLocation";
        var argument = attribute.ConstructorArguments[1];
        if (signature.Params[1].FullName != fallback || argument.Type.FullName != fallback ||
            signature.Params[1].ElementType != ElementType.ValueType || argument.Type.ElementType != ElementType.ValueType ||
            signature.Params[1].ToTypeDefOrRef()?.DefinitionAssembly is not AssemblyRef enumScope || !FrameworkScope(enumScope) ||
            argument.Type.ToTypeDefOrRef()?.DefinitionAssembly is not AssemblyRef argumentScope || !FrameworkScope(argumentScope) ||
            argument.Value is not int location || location is not (0 or 1))
            throw new InvalidDataException("Unreviewed neutral resource fallback location.");
        if (location == 0) return null;
        if (culture.Length == 0) throw new InvalidDataException("Invariant satellite fallback is not reviewed.");
        return culture;
    }

    private static bool FrameworkScope(AssemblyRef scope)
    {
        if (!UTF8String.IsNullOrEmpty(scope.Culture)) return false;
        var token = PublicKeyBase.ToPublicKeyToken(scope.PublicKeyOrToken)?.ToString();
        return (scope.Name.String, token) is
            ("mscorlib", "b77a5c561934e089") or
            ("System.Private.CoreLib", "7cec85d7bea7798e") or
            ("System.Runtime", "b03f5f7f11d50a3a") or
            ("System.Resources.ResourceManager", "b03f5f7f11d50a3a") or
            ("netstandard", "cc7b13ffcd2ddd51");
    }
}
