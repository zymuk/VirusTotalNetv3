using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Models;

/// <summary>The <c>links</c> object of the API envelope, exposing pagination and self links.</summary>
public sealed class VtLinks
{
    /// <summary>Absolute URL of the current resource.</summary>
    public string? Self { get; set; }

    /// <summary>Absolute URL of the next page of results, when present.</summary>
    public string? Next { get; set; }

    /// <summary>Absolute URL of the related resource, when present (mostly used by relationships).</summary>
    public string? Related { get; set; }

    /// <summary>Any link fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}