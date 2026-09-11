using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Models.Attributes;

/// <summary>Attributes of a saved search (<c>saved_search</c> object).</summary>
public sealed class SavedSearchAttributes
{
    /// <summary>Name of the saved search.</summary>
    public string? Name { get; set; }

    /// <summary>Search query string.</summary>
    public string? Query { get; set; }

    /// <summary>Timestamp the search was created (Unix seconds).</summary>
    public DateTimeOffset? CreatedAt { get; set; }

    /// <summary>User who created the search (if available).</summary>
    public string? CreatedBy { get; set; }

    /// <summary>Any attribute fields not mapped above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}
