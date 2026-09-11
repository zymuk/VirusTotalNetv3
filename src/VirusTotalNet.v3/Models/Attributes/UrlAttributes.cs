using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.v3.Models.Attributes;

/// <summary>
/// Attributes of a <c>url</c> object (see <see cref="UrlObject"/>). Fields not yet mapped are
/// preserved losslessly in <see cref="VtObject{TA}.Raw"/>.
/// </summary>
public sealed class UrlAttributes
{
    /// <summary>The URL itself.</summary>
    public string? Url { get; set; }

    /// <summary>How many times the URL has been submitted to VirusTotal.</summary>
    public long? TimesSubmitted { get; set; }

    /// <summary>Number of submitters sharing the same URL (summary may omit it for group submissions).</summary>
    public long? TotalVotesHashes { get; set; }

    /// <summary>Timestamp of the last analysis (Unix seconds).</summary>
    public DateTimeOffset? LastAnalysisDate { get; set; }

    /// <summary>SHA-256 of the response body of the last analysis.</summary>
    public string? LastHttpResponseContentSha256 { get; set; }

    /// <summary>HTTP status code observed during the last analysis.</summary>
    public int? LastHttpResponseCode { get; set; }

    /// <summary>Aggregated detection statistics across all engines.</summary>
    public LastAnalysisStats? LastAnalysisStats { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}