using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.v3.Models;

/// <summary>
/// Single object of the VirusTotal API v3 envelope (<c>{ data, meta, links, error }</c>).
/// The same shape is used for every endpoint, so one parse path covers the whole API.
/// For array payloads use <see cref="List{T}"/> (or <see cref="VtCollection{T}"/>) as <typeparamref name="T"/>.
/// </summary>
/// <typeparam name="T">Typed payload carried in <c>data</c>; for object endpoints a <see cref="VtObject{TA}"/> subclass, for collections a <see cref="List{T}"/>.</typeparam>
public sealed class VtResponse<T>
{
    /// <summary>Payload of the response: a single object, an object list, or <c>null</c>.</summary>
    public T? Data { get; set; }

    /// <summary>Endpoint-specific metadata including pagination counters.</summary>
    public VtMeta? Meta { get; set; }

    /// <summary>Self/pagination links.</summary>
    public VtLinks? Links { get; set; }

    /// <summary>Error details, present when the request was rejected.</summary>
    public VtError? Error { get; set; }

    /// <summary>Any envelope fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}