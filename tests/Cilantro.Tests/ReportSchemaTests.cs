using System.Reflection;
using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

/// <summary>
/// Holds the published schemas to the types they describe.
/// </summary>
/// <remarks>
/// <para>
/// A schema is a promise, and the way a promise like this breaks is not that somebody edits it
/// wrongly — it is that somebody adds a field to a record, ships it, and never touches the schema at
/// all. Nothing fails, the file on disk quietly grows a field the published shape does not mention,
/// and a caller written against the schema finds out months later.
/// </para>
/// <para>
/// So the check is against the types rather than against a document: every property the serializer
/// will write has to be in the schema, and everything the schema promises has to exist. It does not
/// validate a report — that would need a validator the project does not depend on — and it does not
/// need to, because the drift worth catching is this one.
/// </para>
/// </remarks>
public sealed class ReportSchemaTests
{
    public static TheoryData<string, string, Type> Shapes => new()
    {
        { "run.schema.json", string.Empty, typeof(RunManifest) },
        { "run.schema.json", "outputs", typeof(RunOutputs) },
        { "error.schema.json", string.Empty, typeof(RunFailure) },
        { "analysis.schema.json", string.Empty, typeof(ArtifactReport) },
        { "analysis.schema.json", "resource", typeof(ResourceInfo) },
        { "analysis.schema.json", "payload", typeof(PayloadInfo) },
        { "analysis.schema.json", "evidence", typeof(Evidence) },
        { "analysis.schema.json", "pass", typeof(PassResult) },
        { "analysis.schema.json", "recovery", typeof(RecoveryReportMetrics) },
        { "analysis.schema.json", "hostProfile", typeof(HostProfileReport) },
        { "analysis.schema.json", "hostFact", typeof(HostFactReport) },
        { "analysis.schema.json", "declarations", typeof(DeclarationReport) },
        { "blockers.schema.json", string.Empty, typeof(BlockerReport) },
        { "blockers.schema.json", "blocker", typeof(Blocker) },
        { "blockers.schema.json", "remedy", typeof(Remedy) },
        { "config.schema.json", string.Empty, typeof(ConfigReport) },
        { "config.schema.json", "constant", typeof(RecoveredConstant) }
    };

    [Theory]
    [MemberData(nameof(Shapes))]
    public void TheSchemaSaysExactlyWhatTheTypeWrites(string file, string definition, Type type)
    {
        var schema = Shape(file, definition);
        var written = type
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => property.GetIndexParameters().Length == 0)
            .Select(property => property.Name)
            .Where(name => name != "EqualityContract")
            .ToHashSet(StringComparer.Ordinal);
        var promised = schema.GetProperty("properties").EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(
            string.Join(", ", written.Except(promised).Order()),
            string.Empty);
        Assert.Equal(
            string.Join(", ", promised.Except(written).Order()),
            string.Empty);
    }

    /// <summary>
    /// Everything in a report is there in every report, so that a reader has one thing to check for
    /// rather than two. A field that can be absent is written as null.
    /// </summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public void EverythingPromisedIsAlwaysPresent(string file, string definition, Type type)
    {
        _ = type;
        var schema = Shape(file, definition);
        var promised = schema.GetProperty("properties").EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        var required = schema.GetProperty("required").EnumerateArray()
            .Select(element => element.GetString()!)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(string.Join(", ", promised.Except(required).Order()), string.Empty);
    }

    /// <summary>
    /// The version a document carries is the version the schema accepts, or a caller checking it
    /// before parsing would refuse the very thing it was written for.
    /// </summary>
    [Fact]
    public void TheVersionInTheDocumentIsTheOneTheSchemaAllows()
    {
        var manifest = Shape("run.schema.json", string.Empty)
            .GetProperty("properties").GetProperty("Schema").GetProperty("pattern").GetString()!;
        var failure = Shape("error.schema.json", string.Empty)
            .GetProperty("properties").GetProperty("Schema").GetProperty("pattern").GetString()!;

        Assert.Matches(manifest, RunManifest.Current);
        Assert.Matches(failure, RunFailure.Current);
    }

    /// <summary>
    /// The names in a schema are the names the serializer writes, which is worth checking against a
    /// real serialization rather than against the property names alone: a naming policy applied
    /// later would silently move every field.
    /// </summary>
    [Fact]
    public void WhatIsSerializedIsSpeltTheWayTheSchemaSpellsIt()
    {
        var remedy = Declaring.Budget("steps", 750_000);

        var written = JsonSerializer.Serialize(remedy, CilantroPipeline.ReportJsonOptions);

        using var document = JsonDocument.Parse(written);
        var promised = Shape("blockers.schema.json", "remedy")
            .GetProperty("properties").EnumerateObject()
            .Select(property => property.Name);
        foreach (var name in promised)
            Assert.True(document.RootElement.TryGetProperty(name, out _), name);
        // And the value is JSON rather than a string holding JSON, which is the whole reason it is
        // carried as text inside the tool.
        Assert.Equal(
            JsonValueKind.Number,
            document.RootElement.GetProperty("Value").ValueKind);
    }

    private static JsonElement Shape(string file, string definition)
    {
        var text = File.ReadAllText(Path.Combine(Checkout.Root, "schema", file));
        var root = JsonDocument.Parse(text).RootElement;
        return definition.Length == 0 ? root : root.GetProperty("$defs").GetProperty(definition);
    }
}
