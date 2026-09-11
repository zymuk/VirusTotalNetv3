using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.v3.Internal.Json;

/// <summary>
/// Converts Unix timestamps (seconds since epoch) — the format used by VirusTotal for most
/// date/time fields — to/from <see cref="DateTimeOffset"/>.
/// Tolerates numeric, string-typed (<c>"1704067200"</c>) and <c>null</c> inputs.
/// </summary>
internal sealed class UnixTimeSecondsConverter : JsonConverter<DateTimeOffset>
{
    /// <inheritdoc />
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                return default;
            case JsonTokenType.Number:
                return DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64());
            case JsonTokenType.String:
                return long.TryParse(reader.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
                    ? DateTimeOffset.FromUnixTimeSeconds(seconds)
                    : default;
            default:
                throw new JsonException($"Unexpected token '{reader.TokenType}' when reading a Unix timestamp.");
        }
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        => writer.WriteNumberValue(value.ToUnixTimeSeconds());
}