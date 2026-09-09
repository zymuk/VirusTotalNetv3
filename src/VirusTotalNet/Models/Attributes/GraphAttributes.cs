using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.v3.Models.Attributes;

/// <summary>Attributes of a <c>graph</c> object.</summary>
public sealed class GraphAttributes
{
    /// <summary>Name of the graph.</summary>
    public string? Name { get; set; }

    /// <summary>Description of the graph.</summary>
    public string? Description { get; set; }

    /// <summary>Creation timestamp (Unix seconds).</summary>
    public DateTimeOffset? CreatedAt { get; set; }

    /// <summary>Last modification timestamp (Unix seconds).</summary>
    public DateTimeOffset? UpdatedAt { get; set; }

    /// <summary>Whether the graph is private.</summary>
    public bool? Private { get; set; }

    /// <summary>Any attribute fields not mapped above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}