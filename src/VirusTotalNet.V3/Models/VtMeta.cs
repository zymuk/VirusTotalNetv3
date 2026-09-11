using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Models;

/// <summary>The <c>meta</c> object of the API envelope, holding pagination and endpoint-specific metadata.</summary>
public sealed class VtMeta
{
    /// <summary>Number of objects returned by a collection/relationship endpoint, when present.</summary>
    public long? Count { get; set; }

    /// <summary>Pagination cursor reported by the API, when present.</summary>
    public string? Cursor { get; set; }

    /// <summary>Any meta fields not mapped by properties above, preserved losslessly (e.g. <c>file_info</c>).</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}