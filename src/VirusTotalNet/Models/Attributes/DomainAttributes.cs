using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.v3.Models.Attributes;

/// <summary>
/// Attributes of a <c>domain</c> object (see <see cref="DomainObject"/>). Fields not yet mapped
/// are preserved losslessly in <see cref="VtObject{TA}.Raw"/>.
/// </summary>
public sealed class DomainAttributes
{
    /// <summary>Registrar of the domain.</summary>
    public string? Registrar { get; set; }

    /// <summary>Timestamp of the last analysis (Unix seconds).</summary>
    public DateTimeOffset? LastAnalysisDate { get; set; }

    /// <summary>Date the domain was created (Unix seconds).</summary>
    public DateTimeOffset? CreationDate { get; set; }

    /// <summary>How many times the domain has been submitted.</summary>
    public long? TimesSubmitted { get; set; }

    /// <summary>How many times the domain has been detected as malicious.</summary>
    public long? TotalVotesMalicious { get; set; }

    /// <summary>How many times the domain has been detected as harmless.</summary>
    public long? TotalVotesHarmless { get; set; }

    /// <summary>Aggregated detection statistics across all engines.</summary>
    public LastAnalysisStats? LastAnalysisStats { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}

/// <summary>Attributes of a DNS <c>resolution</c> record (domain ↔ IP address).</summary>
public sealed class ResolutionAttributes
{
    /// <summary>Timestamp of the resolution record (Unix seconds).</summary>
    public DateTimeOffset? Date { get; set; }

    /// <summary>Timestamp of the last time the domain resolved to this IP (Unix seconds).</summary>
    public DateTimeOffset? LastResolved { get; set; }

    /// <summary>The IP address the domain resolved to.</summary>
    public string? IpAddress { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}