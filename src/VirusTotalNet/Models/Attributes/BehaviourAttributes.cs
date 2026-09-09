using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.v3.Models.Attributes;

/// <summary>
/// Attributes of a <c>behaviour</c> object (see <see cref="BehaviourObject"/>), produced by
/// sandbox analyses when a file is executed. Fields vary per sandbox; unknown ones are
/// preserved losslessly in <see cref="VtObject{TA}.Raw"/>.
/// </summary>
public sealed class BehaviourAttributes
{
    /// <summary>Name of the sandbox that produced this behaviour report.</summary>
    public string? SandboxName { get; set; }

    /// <summary>The sandbox verdict (e.g. <c>malicious</c>, <c>harmless</c>).</summary>
    public string? SandboxVerdict { get; set; }

    /// <summary>SHA-256 of the sample executed in this behaviour report.</summary>
    public string? SampleSha256 { get; set; }

    /// <summary>Timestamp the behaviour was observed (Unix seconds).</summary>
    public DateTimeOffset? AnalysisDate { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}