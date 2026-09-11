using VirusTotalNet.V3.Models.Attributes;

namespace VirusTotalNet.V3.Models;

/// <summary>A <c>domain</c> object returned by the VirusTotal API v3, e.g. from <c>GET /domains/{domain}</c>.</summary>
public sealed class DomainObject : VtObject<DomainAttributes>
{
}

/// <summary>A <c>resolution</c> object mapping a domain to an IP address, e.g. from <c>GET /domains/{domain}/resolutions</c>.</summary>
public sealed class ResolutionObject : VtObject<ResolutionAttributes>
{
}