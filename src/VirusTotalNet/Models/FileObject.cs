using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.v3.Models;

/// <summary>A <c>file</c> object returned by the VirusTotal API v3, e.g. from <c>GET /files/{id}</c>.</summary>
public sealed class FileObject : VtObject<VtFileAttributes>
{
}