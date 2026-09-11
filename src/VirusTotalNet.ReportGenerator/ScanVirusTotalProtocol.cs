using System.Collections.Generic;

namespace VirusTotalNet.ReportGenerator;

public class ScanVirusTotalProtocol
{
    public ScanVirusTotalProtocolHeader header { get; set; } = new();

    public List<ScanFile> scanFile { get; set; } = new();
}