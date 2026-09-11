using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Models.Attributes;

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

    /// <summary>Timestamp of the last resolution observed (Unix seconds).</summary>
    public DateTimeOffset? LastResolved { get; set; }

    /// <summary>The IP address the domain resolved to (present on domain resolutions).</summary>
    public string? IpAddress { get; set; }

    /// <summary>The domain the IP resolved to (present on IP-address resolutions).</summary>
    public string? Domain { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}

/// <summary>Attributes of an <c>ip_address</c> object (see <see cref="IpObject"/>).</summary>
public sealed class IpAttributes
{
    /// <summary>Country code the IP is geolocated in.</summary>
    public string? Country { get; set; }

    /// <summary>CIDR network the IP belongs to.</summary>
    public string? Network { get; set; }

    /// <summary>Owner of the autonomous system the IP belongs to.</summary>
    public string? AsOwner { get; set; }

    /// <summary>Autonomous system number of the IP.</summary>
    public long? Asn { get; set; }

    /// <summary>Regional Internet Registry (e.g. ARIN, RIPE, APNIC).</summary>
    public string? RegionalInternetRegistry { get; set; }

    /// <summary>Timestamp of the last analysis (Unix seconds).</summary>
    public DateTimeOffset? LastAnalysisDate { get; set; }

    /// <summary>How many times the IP has been submitted.</summary>
    public long? TimesSubmitted { get; set; }

    /// <summary>Aggregated detection statistics across all engines.</summary>
    public LastAnalysisStats? LastAnalysisStats { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}