using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cilantro.Core;

/// <summary>
/// A piece of JSON carried as text and written into a report as JSON rather than as a string.
/// </summary>
/// <remarks>
/// <para>
/// Reports hold a few values whose shape belongs to whoever reads them rather than to the tool: what
/// to write into a declarations file, for one, which is a number in one case and an object in
/// another. The obvious way to carry such a thing is a <c>JsonNode</c>, and it is the wrong way here,
/// because the tool interprets everything twice and compares the accounts of the two runs. A node
/// compares by reference, so two runs that produced the same value would look like they disagreed.
/// </para>
/// <para>
/// Text compares by value and survives that check. What it costs is that the text has to be written
/// out raw, or a report would carry <c>"{\"inert\":true}"</c> where it means <c>{"inert": true}</c>
/// and its reader would have to parse twice to get at one value.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonTextConverter))]
public readonly record struct JsonText(string Text)
{
    /// <summary>The JSON literal for a whole number.</summary>
    public static JsonText Of(long number) =>
        new(number.ToString(System.Globalization.CultureInfo.InvariantCulture));

    /// <summary>The JSON literal for a string, quoted and escaped.</summary>
    public static JsonText Of(string value) => new(JsonSerializer.Serialize(value));

    /// <summary>JSON as it was written, with no promise that it is compact or indented.</summary>
    public override string ToString() => Text;
}

/// <summary>Writes a <see cref="JsonText"/> as the JSON it is, and reads any JSON back into one.</summary>
internal sealed class JsonTextConverter : JsonConverter<JsonText>
{
    public override JsonText Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        return new JsonText(document.RootElement.GetRawText());
    }

    public override void Write(Utf8JsonWriter writer, JsonText value, JsonSerializerOptions options)
    {
        if (string.IsNullOrEmpty(value.Text))
        {
            writer.WriteNullValue();
            return;
        }

        writer.WriteRawValue(value.Text);
    }
}
