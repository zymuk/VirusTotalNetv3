using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Models.Attributes;

/// <summary>Well-known analysis status values (see <see cref="AnalysisAttributes.Status"/>).</summary>
public static class AnalysisStatus
{
    /// <summary>The analysis job is waiting to be picked up.</summary>
    public const string Queued = "queued";

    /// <summary>The analysis job is currently running.</summary>
    public const string InProgress = "in-progress";

    /// <summary>The analysis job has finished and results are available.</summary>
    public const string Completed = "completed";
}

/// <summary>
/// Attributes of an <c>analysis</c> object (see <see cref="AnalysisObject"/>): the status of the
/// job, aggregated verdict stats, and per-engine results. Fields not yet mapped are preserved
/// losslessly in <see cref="VtObject{TA}.Raw"/>.
/// </summary>
public sealed class AnalysisAttributes
{
    /// <summary>Current status of the analysis: <c>queued</c>, <c>in-progress</c>, or <c>completed</c>.</summary>
    public string? Status { get; set; }

    /// <summary>Time the analysis was created (Unix timestamp, seconds).</summary>
    public DateTimeOffset? Date { get; set; }

    /// <summary>Aggregated verdict statistics for this analysis.</summary>
    public LastAnalysisStats? Stats { get; set; }

    /// <summary>Per-engine detection results.</summary>
    public JsonElement? Results { get; set; }

    /// <summary>A map of files involved in this analysis.</summary>
    public JsonElement? Files { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}