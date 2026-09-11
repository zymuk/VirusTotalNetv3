using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Models.Attributes;

/// <summary>Attributes of a threat actor (<c>threat_actor</c> object). Limited to fields seen in v3.</summary>
public sealed class ThreatActorAttributes
{
    /// <summary>Name of the threat actor.</summary>
    public string? Name { get; set; }

    /// <summary>Summary description of the actor.</summary>
    public string? Description { get; set; }

    /// <summary>Reputation score from 0 (unknown) to 100 (high confidence malicious).</summary>
    public int? Reputation { get; set; }

    /// <summary>First seen timestamp (Unix seconds).</summary>
    public DateTimeOffset? FirstSeen { get; set; }

    /// <summary>Last seen timestamp (Unix seconds).</summary>
    public DateTimeOffset? LastSeen { get; set; }

    /// <summary>Count of affiliated malware families.</summary>
    public int? MalwareFamiliesCount { get; set; }

    /// <summary>Any attribute fields not mapped above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}
