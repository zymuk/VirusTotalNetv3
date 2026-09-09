using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.v3.Models;

/// <summary>
/// An <c>analysis</c> object returned by the VirusTotal API v3, e.g. the immediate result of
/// submitting a scan (<see cref="Clients.IFileClient.ScanFileAsync"/>). Poll the analysis id
/// to get the completed report.
/// </summary>
public sealed class AnalysisObject : VtObject<AnalysisAttributes>
{
}