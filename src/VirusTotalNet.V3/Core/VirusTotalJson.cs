using System.Text.Json;
using System.Text.Json.Serialization;
using VirusTotalNet.V3.Internal.Json;

namespace VirusTotalNet.V3.Core;

/// <summary>
/// Shared <see cref="JsonSerializerOptions"/> tuned for the VirusTotal API v3 data quirks
/// (string-typed numbers, Unix timestamps, crammed dates, literal <c>"null"</c> values).
/// Options are read-only after first use and safe to share.
/// </summary>
public static class VirusTotalJson
{
    /// <summary>Recommended serializer options for all VirusTotal API v3 payloads.</summary>
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    /// <summary>Creates a fresh, fully configured <see cref="JsonSerializerOptions"/> instance.</summary>
    public static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            PropertyNameCaseInsensitive = true,
            NumberHandling = JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.AllowNamedFloatingPointLiterals,
            AllowTrailingCommas = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        options.Converters.Add(new UnixTimeSecondsConverter());
        options.Converters.Add(new YearMonthDayConverter());
        options.Converters.Add(new TolerantStringConverter());
        return options;
    }
}