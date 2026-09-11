using System.Xml.Serialization;

namespace VirusTotalNet.ReportGenerator;

public class ScanFile
{
    public List<ScanStepsScanStep> scanSteps { get; set; } = new();

    public long fileSize { get; set; }

    public DateTime fileDateTime { get; set; }

    public string fileName { get; set; } = string.Empty;

    public string pathFile { get; set; } = string.Empty;

    public string md5 { get; set; } = string.Empty;

    public string permalink { get; set; } = string.Empty;

    public int positives { get; set; }

    public string resource { get; set; } = string.Empty;

    public DateTime scanDate { get; set; }

    public string scanId { get; set; } = string.Empty;

    public string sha1 { get; set; } = string.Empty;

    public string sha256 { get; set; } = string.Empty;

    public int total { get; set; }

    public string verboseMsg { get; set; } = string.Empty;
}