using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.v3.Models;

/// <summary>An <c>ip_address</c> object returned by the VirusTotal API v3, e.g. from <c>GET /ip_addresses/{ip}</c>.</summary>
public sealed class IpObject : VtObject<IpAttributes>
{
}