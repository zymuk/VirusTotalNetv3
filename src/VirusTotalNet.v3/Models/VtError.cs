using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.v3.Models;

/// <summary>The <c>error</c> object returned by the API for failed requests.</summary>
public sealed class VtError
{
    /// <summary>Machine-readable error code, e.g. <c>QuotaExceededError</c>.</summary>
    public string? Code { get; set; }

    /// <summary>Human-readable summary of the error.</summary>
    public string? Message { get; set; }

    /// <summary>Optional, more detailed explanation of the error.</summary>
    public string? Detail { get; set; }

    /// <summary>
    /// HTTP status of the failed response. Not part of the API payload — the client stamps it when
    /// it produces the envelope, and <see cref="VirusTotalNet.v3.Core.VtClient"/> uses it for
    /// exception mapping.
    /// </summary>
    [JsonIgnore]
    public HttpStatusCode? StatusCode { get; set; }

    /// <summary>Any error fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}