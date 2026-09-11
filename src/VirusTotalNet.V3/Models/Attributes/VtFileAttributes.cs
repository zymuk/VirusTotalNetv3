using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Models.Attributes;

/// <summary>
/// Attributes of a <c>file</c> object: core identity fields plus detection statistics.
/// Named <c>VtFileAttributes</c> to avoid clashing with <see cref="System.IO.FileAttributes"/>.
/// Fields not yet mapped are preserved losslessly in <see cref="VtObject{TA}.Raw"/>.
/// </summary>
public sealed class VtFileAttributes
{
    /// <summary>Type of the file, typically its extension without the leading dot (e.g. <c>exe</c>).</summary>
    public string? Type { get; set; }

    /// <summary>True when the file is a self-extracting package.</summary>
    public bool? SelfExtracting { get; set; }

    /// <summary>Original file name, when known.</summary>
    public string? OriginalFileName { get; set; }

    /// <summary>File size in bytes.</summary>
    public long? Size { get; set; }

    /// <summary>MD5 digest of the file.</summary>
    public string? Md5 { get; set; }

    /// <summary>SHA-1 digest of the file.</summary>
    public string? Sha1 { get; set; }

    /// <summary>SHA-256 digest of the file.</summary>
    public string? Sha256 { get; set; }

    /// <summary>Aggregated detection statistics across all engines.</summary>
    public LastAnalysisStats? LastAnalysisStats { get; set; }

    /// <summary>
    /// Per-engine results of the last analysis, keyed by engine name
    /// (<c>attributes.last_analysis_results</c>).
    /// </summary>
    public Dictionary<string, LastAnalysisResult>? LastAnalysisResults { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}

/// <summary>Aggregated antivirus engine verdict counts for the last analysis.</summary>
public sealed class LastAnalysisStats
{
    /// <summary>Number of engines that flagged the sample as malicious.</summary>
    public int? Malicious { get; set; }

    /// <summary>Number of engines that flagged the sample as suspicious.</summary>
    public int? Suspicious { get; set; }

    /// <summary>Number of engines with no verdict.</summary>
    public int? Undetected { get; set; }

    /// <summary>Number of engines that flagged it as harmless.</summary>
    public int? Harmless { get; set; }

    /// <summary>Number of engines that failed to analyse the sample.</summary>
    [JsonPropertyName("type-unsupported")]
    public int? TypeUnsupported { get; set; }

    /// <summary>Number of engines that timed out.</summary>
    public int? Timeout { get; set; }
}

/// <summary>
/// Detection result of a single antivirus engine from the last analysis
/// (<c>attributes.last_analysis_results</c> value).
/// </summary>
public sealed class LastAnalysisResult
{
    /// <summary>Verdict category: <c>malicious</c>, <c>suspicious</c>, <c>harmless</c>, <c>undetected</c>, ...</summary>
    public string? Category { get; set; }

    /// <summary>Human-readable engine name (e.g. <c>Avast</c>).</summary>
    public string? EngineName { get; set; }

    /// <summary>Engine binary version (e.g. <c>23.9.8494.0</c>).</summary>
    public string? EngineVersion { get; set; }

    /// <summary>When the engine signature database was last updated (raw date/time as returned).</summary>
    public string? EngineUpdate { get; set; }

    /// <summary>Detection mode: <c>blacklist</c>, <c>heuristic</c>, ...</summary>
    public string? Method { get; set; }

    /// <summary>Threat/signature name when the engine flagged the sample, <c>null</c> otherwise.</summary>
    public string? Result { get; set; }
}