using System.Xml.Linq;
using VirusTotalNet.ReportGenerator;
using VirusTotalNet.v3.Models;
using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.Tests;

public class ReportBuilderTests
{
    [Fact]
    public void BuildReport_WritesHeaderAndScanFile_AggregatesStats()
    {
        var file = new ScanFileData
        {
            FileName = "sample.exe",
            PathFile = @"D:\samples\sample.exe",
            FileSize = 1024,
            FileDateTime = new DateTime(2024, 1, 2, 3, 4, 5),
            Md5 = "ab4c9af86d963e369cccfaf4a4d92cb2",
            Sha1 = "9256d0cd9e0c1e5457a51b3b4bcbb5c2d0c4e1c2",
            Sha256 = "ba627fd9da492137132bc300d18fedf481a68273db5ca23cab046ee6d42a2084",
            Report = new FileObject
            {
                Attributes = new VtFileAttributes
                {
                    LastAnalysisResults = new Dictionary<string, LastAnalysisResult>
                    {
                        ["Avast"] = new()
                        {
                            Category = "malicious",
                            EngineName = "Avast",
                            EngineVersion = "23.9.8494.0",
                            EngineUpdate = "2026-09-10T00:00:00+00:00",
                            Result = "Win32:Evo-Gen"
                        },
                        ["Microsoft"] = new()
                        {
                            Category = "undetected",
                            EngineName = "Microsoft",
                            EngineVersion = "1.26080",
                            EngineUpdate = null,
                            Result = null
                        }
                    }
                }
            }
        };

        var xml = ReportBuilder.BuildReport([file], TimeSpan.FromSeconds(71));

        var doc = XDocument.Parse(xml);
        Assert.Equal("doc", doc.Root?.Name.LocalName);
        var root = doc.Root?.Element("ScanVirusTotalProtocol");
        Assert.NotNull(root);
        Assert.Equal(string.Empty, root!.Name.Namespace.NamespaceName);
        Assert.Equal("http://www.w3.org/2001/XMLSchema-instance", root.Attribute(XName.Get("xsi", "http://www.w3.org/2000/xmlns/"))?.Value);
        Assert.Equal("http://www.w3.org/2001/XMLSchema", root.Attribute(XName.Get("xsd", "http://www.w3.org/2000/xmlns/"))?.Value);

        var header = root.Element("header");
        Assert.NotNull(header);
        Assert.Equal("Total 2 (1 of 1 files)", header!.Element("summaryScanCase")?.Value);
        Assert.Equal("1 Detected", header.Element("scanCaseDetected")?.Value);
        Assert.Equal("1 Undetected", header.Element("scanCaseUndetected")?.Value);
        Assert.Equal("00:01:11", header.Element("executionTime")?.Value);
        Assert.Equal("sample.exe", header.Element("fileScannedList")?.Value);
        Assert.Equal(@"D:\samples\sample.exe", header.Element("fileList")?.Value);
        Assert.Equal(8, header.Element("shortName")?.Value.Length);

        var scanFile = root.Element("scanFile")?.Element("ScanFile");
        Assert.NotNull(scanFile);
        Assert.Equal(string.Empty, scanFile!.Name.Namespace.NamespaceName);

        var steps = scanFile!.Elements("scanSteps").Elements("ScanStepsScanStep").ToList();
        Assert.Equal(2, steps.Count);

        var detected = steps.Single(s => s.Element("toolAntivirus")?.Value == "Avast");
        Assert.Equal("Detected", detected.Element("result")?.Value);
        Assert.Equal("Win32:Evo-Gen", detected.Element("resultDescription")?.Value);
        Assert.Equal("2026-09-10T00:00:00+00:00", detected.Element("updateDate")?.Value);
        Assert.Equal("23.9.8494.0", detected.Element("vesion")?.Value);

        var clean = steps.Single(s => s.Element("toolAntivirus")?.Value == "Microsoft");
        Assert.Equal("Undetected", clean.Element("result")?.Value);
        Assert.Equal("Undetected", clean.Element("resultDescription")?.Value);
        Assert.Equal("", clean.Element("updateDate")?.Value);

        Assert.Equal("1024", scanFile.Element("fileSize")?.Value);
        Assert.Equal("/gui/file/ba627fd9da492137132bc300d18fedf481a68273db5ca23cab046ee6d42a2084/detection",
            new Uri(scanFile.Element("permalink")?.Value!).PathAndQuery);
        Assert.Equal("1", scanFile.Element("positives")?.Value);
        Assert.Equal("2", scanFile.Element("total")?.Value);
        Assert.Equal("ab4c9af86d963e369cccfaf4a4d92cb2", scanFile.Element("md5")?.Value);
        Assert.Equal("ba627fd9da492137132bc300d18fedf481a68273db5ca23cab046ee6d42a2084", scanFile.Element("resource")?.Value);

        Assert.Contains($"{file.Sha256}-", xml);
        Assert.StartsWith("<?xml version=\"1.0\"", xml);
        Assert.Contains("id=\"stylesheet\"", xml);
    }
}