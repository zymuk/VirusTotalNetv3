using System.Collections.Generic;

namespace VirusTotalNet.V3.ReportGenerator;

public class ScanVirusTotalProtocol
{
    public ScanVirusTotalProtocolHeader header { get; set; } = new();

    public List<ScanFile> scanFile { get; set; } = new();
}