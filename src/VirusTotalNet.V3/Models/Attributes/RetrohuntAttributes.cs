namespace VirusTotalNet.V3.Models.Attributes;

public sealed class RetrohuntJobAttributes
{
    public string? Rules { get; set; }
    public string? Corpus { get; set; }
    public string? NotificationEmail { get; set; }
    public int? Progress { get; set; }
    public string? Status { get; set; }
    public int? Date { get; set; }
    public RetrohuntTimeRange? TimeRange { get; set; }
}

public sealed class RetrohuntTimeRange
{
    public int? Start { get; set; }
    public int? End { get; set; }
}
