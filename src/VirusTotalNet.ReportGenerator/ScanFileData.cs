using VirusTotalNet.v3.Models;

namespace VirusTotalNet.ReportGenerator;

public sealed class ScanFileData
{
    public string FileName { get; set; } = string.Empty;
    public string PathFile { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public DateTime FileDateTime { get; set; }
    public string Md5 { get; set; } = string.Empty;
    public string Sha1 { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public FileObject Report { get; set; } = new();

    public int DetectedCount
        => Report.Attributes?.LastAnalysisResults?.Values
            .Count(r => r.Category is "malicious" or "suspicious") ?? 0;

    public int TotalCount
        => Report.Attributes?.LastAnalysisResults?.Count ?? 0;
}