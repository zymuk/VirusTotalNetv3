using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Internal.Json;

/// <summary>
/// Converts strings while tolerating VirusTotal data quirks: the literal <c>"null"</c>
/// text becomes <c>null</c>, and numbers/booleans are normalized to their string form
/// instead of failing.
/// </summary>
internal sealed class TolerantStringConverter : JsonConverter<string?>
{
    /// <inheritdoc />
    public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                return null;
            case JsonTokenType.String:
                var value = reader.GetString();
                return string.Equals(value, "null", StringComparison.OrdinalIgnoreCase) ? null : value;
            case JsonTokenType.Number:
                return reader.GetDecimal().ToString(CultureInfo.InvariantCulture);
            case JsonTokenType.True:
                return bool.TrueString;
            case JsonTokenType.False:
                return bool.FalseString;
            default:
                throw new JsonException($"Unexpected token '{reader.TokenType}' when reading a string.");
        }
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, string? value, JsonSerializerOptions options)
    {
        if (value is null)
            writer.WriteNullValue();
        else
            writer.WriteStringValue(value);
    }
}