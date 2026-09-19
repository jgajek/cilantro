using System.Security.Cryptography;
using dnlib.DotNet;

namespace Cilantro.Core;

public sealed record FieldData(uint Token, string Field, int Length, string Sha256, string Kind);

public sealed class FieldRvaRecoveryPass : DeobfuscationPass
{
    public override string Name => "field-rva-recovery";
    public override IReadOnlyCollection<string> Dependencies => ["method-protection"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var fields = context.Module.GetTypes()
            .SelectMany(type => type.Fields)
            .Where(field => field.HasFieldRVA && field.InitialValue is { Length: > 0 })
            .Select(field => new FieldData(
                field.MDToken.Raw,
                field.FullName,
                field.InitialValue.Length,
                Convert.ToHexStringLower(SHA256.HashData(field.InitialValue)),
                Classify(field.InitialValue)))
            .ToArray();
        context.SetFact("fieldRva.catalog", fields);
        foreach (var field in fields.Where(item => item.Kind is "aes-key-candidate" or "aes-iv-candidate"))
        {
            context.AddEvidence(new Evidence(
                "cryptography",
                $"{field.Kind} in {field.Field} ({field.Length} bytes).",
                $"0x{field.Token:X8}",
                0.7));
        }

        return (PassStatus.Success, 0, [$"Cataloged {fields.Length} initialized fields."]);
    }

    private static string Classify(byte[] data) => data.Length switch
    {
        16 when Entropy.Calculate(data) > 3.2 => "aes-iv-candidate",
        24 or 32 when Entropy.Calculate(data) > 3.5 => "aes-key-candidate",
        _ => "initialized-data"
    };
}
