using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.v3.Models;

/// <summary>A <c>url</c> object returned by the VirusTotal API v3, e.g. from <c>GET /urls/{id}</c>.</summary>
public sealed class UrlObject : VtObject<UrlAttributes>
{
}