using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;
using VirusTotalNet.ReportGenerator;

namespace VirusTotalNet.Tests;

public class ReportProtocolTests
{
    [Fact]
    public void SerializeProtocol_RootElementMatchesExpectedFormat()
    {
        var protocol = new ScanVirusTotalProtocol
        {
            header = new ScanVirusTotalProtocolHeader
            {
                startDateTime = new DateTime(2026, 9, 11, 11, 54, 48, DateTimeKind.Local),
                executionTime = "00:01:11",
                fileScannedList = "sample.exe; large.bin",
                fileList = @"D:\sample.exe; D:\large.bin",
                summaryScanCase = "Total 2 (2 of 2 files)",
                scanCaseUndetected = "2 Undetected",
                scanCaseDetected = "0 Detected",
                shortName = "AABBCCDD"
            },
            scanFile = new List<ScanFile>
            {
                new ScanFile
                {
                    scanSteps = new List<ScanStepsScanStep>
                    {
                        new ScanStepsScanStep
                        {
                            toolAntivirus = "Avast",
                            resultDescription = "Win32:Evo-Gen",
                            result = ResultEnum.Detected,
                            vesion = "23.9.8494.0",
                            updateDate = new DateTime(2026, 9, 10, 0, 0, 0, DateTimeKind.Unspecified)
                        },
                        new ScanStepsScanStep
                        {
                            toolAntivirus = "Microsoft",
                            resultDescription = "Undetected",
                            result = ResultEnum.Undetected,
                            vesion = "1.26080",
                            updateDate = new DateTime(2026, 9, 11, 0, 0, 0, DateTimeKind.Unspecified)
                        }
                    },
                    fileSize = 1024,
                    fileDateTime = new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Local),
                    fileName = "sample.exe",
                    pathFile = @"D:\sample.exe",
                    md5 = "ab4c9af86d963e369cccfaf4a4d92cb2",
                    permalink = "https://www.virustotal.com/gui/file/sha256hash/detection/f-sha256hash-12345",
                    positives = 1,
                    resource = "sha256hash",
                    scanDate = new DateTime(2026, 9, 11, 4, 51, 28, DateTimeKind.Unspecified),
                    scanId = "sha256hash-12345",
                    sha1 = "859bc2bb8b4bac5a140429cfaa43f49714c12e21",
                    sha256 = "sha256hash",
                    total = 2,
                    verboseMsg = "Scan finished, information embedded"
                }
            }
        };

        var xml = SerializeProtocol(protocol);

        var doc = XDocument.Parse(xml);
        Assert.Equal("doc", doc.Root?.Name.LocalName);

        var root = doc.Root?.Element("ScanVirusTotalProtocol");
        Assert.NotNull(root);

        var header = root?.Element("header");
        Assert.NotNull(header);
        Assert.Equal("2 Undetected", header!.Element("scanCaseUndetected")?.Value);
        Assert.Equal("0 Detected", header.Element("scanCaseDetected")?.Value);
        Assert.Equal("Total 2 (2 of 2 files)", header.Element("summaryScanCase")?.Value);
        Assert.Equal("AABBCCDD", header.Element("shortName")?.Value);
        Assert.Contains("2026-09-11T11:54:48", header.Element("startDateTime")?.Value ?? "");

        var scanFile = root?.Element("scanFile")?.Element("ScanFile");
        Assert.NotNull(scanFile);
        Assert.Equal("sample.exe", scanFile!.Element("fileName")?.Value);
        Assert.Equal("sha256hash", scanFile.Element("resource")?.Value);
        Assert.Equal("sha256hash-12345", scanFile.Element("scanId")?.Value);
        Assert.Equal("1", scanFile.Element("positives")?.Value);
        Assert.Equal("2", scanFile.Element("total")?.Value);
        Assert.Contains("virustotal.com", scanFile.Element("permalink")?.Value ?? "");

        var steps = scanFile.Element("scanSteps")?.Elements("ScanStepsScanStep").ToList();
        Assert.NotNull(steps);
        Assert.Equal(2, steps!.Count);

        var detected = steps.Single(s => s.Element("toolAntivirus")?.Value == "Avast");
        Assert.Equal("Detected", detected.Element("result")?.Value);
        Assert.Equal("Win32:Evo-Gen", detected.Element("resultDescription")?.Value);

        var clean = steps.Single(s => s.Element("toolAntivirus")?.Value == "Microsoft");
        Assert.Equal("Undetected", clean.Element("result")?.Value);
        Assert.Equal("Undetected", clean.Element("resultDescription")?.Value);
        Assert.Equal("1.26080", clean.Element("vesion")?.Value);
        Assert.Contains("2026-09-11", clean.Element("updateDate")?.Value ?? "");
    }

    [Fact]
    public void AddStyleSheetForProtocol_WrapsWithDocElement()
    {
        var tmpPath = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tmpPath, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<ScanVirusTotalProtocol />");
            ProtocolUtil.AddStyleSheetForProtocol(tmpPath, "<?xml-stylesheet href=\"#\" ?>\n<doc>\n<xsl:stylesheet id=\"stylesheet\"></xsl:stylesheet>");
            var content = File.ReadAllText(tmpPath);
            Assert.Contains("</doc>", content);
            Assert.Contains("xsl:stylesheet", content);
            Assert.StartsWith("<?xml", content);
        }
        finally
        {
            File.Delete(tmpPath);
        }
    }

    private static string SerializeProtocol(ScanVirusTotalProtocol protocol)
    {
        var serializer = new XmlSerializer(typeof(ScanVirusTotalProtocol));

        var xml = new StringWriter();
        using (var writer = XmlWriter.Create(xml, new XmlWriterSettings { Indent = true }))
        {
            serializer.Serialize(writer, protocol);
        }

        var raw = xml.ToString();

        // Simulate SaveProtocol + ProtocolUtil.AddStyleSheetForProtocol pipeline
        var lines = raw.Split(Environment.NewLine).ToList();
        var styleSheet = "<?xml-stylesheet type=\"text/xsl\" href=\"#stylesheet\"?>\n<doc>\n<xsl:stylesheet id=\"stylesheet\" version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"></xsl:stylesheet>";
        lines.Insert(1, styleSheet);
        lines.Insert(lines.Count, "</doc>");
        return string.Join(Environment.NewLine, lines);
    }
}