using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.v3.Internal.Json;

/// <summary>
/// Converts crammed calendar dates — the <c>YYYYmmdd</c> format used by VirusTotal
/// (e.g. <c>first_submission_date</c>) — to/from <see cref="DateTime"/>.
/// Additionally accepts ISO <c>yyyy-MM-dd</c> and <c>null</c> as a fallback.
/// </summary>
internal sealed class YearMonthDayConverter : JsonConverter<DateTime>
{
    private static readonly string[] Formats = { "yyyyMMdd", "yyyy-MM-dd" };

    /// <inheritdoc />
    public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                return default;
            case JsonTokenType.String:
                return DateTime.TryParseExact(
                    reader.GetString(), Formats, CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var date)
                    ? date
                    : default;
            default:
                throw new JsonException($"Unexpected token '{reader.TokenType}' when reading a calendar date.");
        }
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.ToString("yyyyMMdd", CultureInfo.InvariantCulture));
}