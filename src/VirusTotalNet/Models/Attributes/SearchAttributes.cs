using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.v3.Models.Attributes;

/// <summary>
/// Attributes of a search result. Search hits can be any object type, so every field is
/// preserved losslessly via <see cref="Raw"/> rather than mapped property-by-property.
/// </summary>
public sealed class SearchAttributes
{
    /// <summary>All attribute fields of the search hit, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}