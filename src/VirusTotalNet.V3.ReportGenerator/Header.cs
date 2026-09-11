namespace VirusTotalNet.V3.ReportGenerator;

public class Header
{
    public DateTime startDateTime { get; set; }

    public string executionTime { get; set; } = string.Empty;

    public string fileScannedList { get; set; } = string.Empty;

    public string fileList { get; set; } = string.Empty;

    public string description { get; set; } = string.Empty;

    public string summaryScanCase { get; set; } = string.Empty;

    public string scanCaseUndetected { get; set; } = string.Empty;

    public string scanCaseDetected { get; set; } = string.Empty;

    public string shortName { get; set; } = string.Empty;

    public string longName { get; set; } = string.Empty;
}