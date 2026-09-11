namespace VirusTotalNet.v3.ReportGenerator;

public class ScanStep
{
    public string toolAntivirus { get; set; } = string.Empty;

    public string resultDescription { get; set; } = string.Empty;

    public string description { get; set; } = string.Empty;

    public ResultEnum result { get; set; }

    public string vesion { get; set; } = string.Empty;

    public DateTime updateDate { get; set; }
}