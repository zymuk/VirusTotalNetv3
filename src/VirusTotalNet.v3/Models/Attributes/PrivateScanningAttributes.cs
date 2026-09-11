namespace VirusTotalNet.v3.Models.Attributes;

public sealed class PrivateFileAttributes
{
    public long Size { get; set; }
    public string? TypeTag { get; set; }
    public string? TypeName { get; set; }
    public string? Md5 { get; set; }
    public string? Sha1 { get; set; }
    public string? Sha256 { get; set; }
    public LastAnalysisStats? LastAnalysisStats { get; set; }
    public string? Permalink { get; set; }
    public int? Date { get; set; }
    public string? VerboseMsg { get; set; }
    public Dictionary<string, LastAnalysisResult>? LastAnalysisResults { get; set; }
}
