using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Models.Attributes;

/// <summary>Attributes of a <c>collection</c> object.</summary>
public sealed class CollectionAttributes
{
    /// <summary>Name of the collection.</summary>
    public string? Name { get; set; }

    /// <summary>Description of the collection.</summary>
    public string? Description { get; set; }

    /// <summary>Creation timestamp (Unix seconds).</summary>
    public DateTimeOffset? CreatedAt { get; set; }

    /// <summary>Last modification timestamp (Unix seconds).</summary>
    public DateTimeOffset? UpdatedAt { get; set; }

    /// <summary>Any attribute fields not mapped above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}