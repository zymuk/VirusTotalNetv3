using System.Security.Cryptography;
using System.Text;
using System.Xml;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.ReportGenerator;

public static class ReportBuilder
{
    private const string ReportRoot = "ScanVirusTotalProtocol";
    private const string XsiNamespace = "http://www.w3.org/2001/XMLSchema-instance";
    private const string XsdNamespace = "http://www.w3.org/2001/XMLSchema";

    public static string BuildReport(List<ScanFileData> files, TimeSpan duration)
    {
        var detected = files.Sum(f => f.DetectedCount);
        var total = files.Sum(f => f.TotalCount);

        var xml = new StringBuilder();
        xml.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        xml.AppendLine("<?xml-stylesheet type=\"text/xsl\" href=\"#stylesheet\"?>");
        xml.AppendLine("<!DOCTYPE doc [");
        xml.AppendLine("<!ATTLIST xsl:stylesheet");
        xml.AppendLine("id ID #REQUIRED>");
        xml.AppendLine("]>");
        xml.AppendLine("<doc>");
        xml.AppendLine(LoadStylesheet());
        xml.AppendLine();

        var body = new StringBuilder();
        using (var sw = new StringWriter(body))
        using (var writer = XmlWriter.Create(sw, new XmlWriterSettings { Indent = true, OmitXmlDeclaration = true }))
        {
            writer.WriteStartElement(ReportRoot);
            writer.WriteAttributeString("xmlns", "xsi", null, XsiNamespace);
            writer.WriteAttributeString("xmlns", "xsd", null, XsdNamespace);

            writer.WriteStartElement("header");
            writer.WriteElementString("startDateTime", DateTimeOffset.Now.ToString("o"));
            writer.WriteElementString("executionTime", duration.ToString(@"hh\:mm\:ss"));
            writer.WriteElementString("fileScannedList", string.Join("; ", files.Select(f => f.FileName)));
            writer.WriteElementString("fileList", string.Join("; ", files.Select(f => f.PathFile)));
            writer.WriteElementString("summaryScanCase", $"Total {total} ({files.Count} of {files.Count} files)");
            writer.WriteElementString("scanCaseUndetected", $"{total - detected} Undetected");
            writer.WriteElementString("scanCaseDetected", $"{detected} Detected");
            writer.WriteElementString("shortName", ShortName());
            writer.WriteEndElement();

            writer.WriteStartElement("scanFile");
            foreach (var file in files)
                WriteScanFile(writer, file);
            writer.WriteEndElement();

            writer.WriteEndElement();
        }

        xml.Append(body);
        xml.AppendLine("</doc>");
        return xml.ToString();
    }

    private static void WriteScanFile(XmlWriter writer, ScanFileData file)
    {
        writer.WriteStartElement("ScanFile");

        writer.WriteStartElement("scanSteps");
        if (file.Report.Attributes?.LastAnalysisResults is { } results)
        {
            foreach (var (_, result) in results.OrderBy(kv => kv.Key))
            {
                writer.WriteStartElement("ScanStepsScanStep");

                var category = result.Category;
                var detected = category is "malicious" or "suspicious";

                writer.WriteElementString("toolAntivirus", result.EngineName ?? string.Empty);
                writer.WriteElementString("resultDescription", detected ? result.Result : "Undetected");
                writer.WriteElementString("result", detected ? "Detected" : "Undetected");
                writer.WriteElementString("vesion", result.EngineVersion ?? string.Empty);
                writer.WriteElementString("updateDate", result.EngineUpdate ?? string.Empty);

                writer.WriteEndElement();
            }
        }
        writer.WriteEndElement();

        writer.WriteElementString("fileSize", file.FileSize.ToString());
        writer.WriteElementString("fileDateTime", file.FileDateTime.ToString("o"));
        writer.WriteElementString("fileName", file.FileName);
        writer.WriteElementString("pathFile", file.PathFile);
        writer.WriteElementString("md5", file.Md5);
        writer.WriteElementString("permalink", $"https://www.virustotal.com/gui/file/{file.Sha256}/detection");
        writer.WriteElementString("positives", file.DetectedCount.ToString());
        writer.WriteElementString("resource", file.Sha256);
        writer.WriteElementString("scanDate", DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss"));
        writer.WriteElementString("scanId", $"{file.Sha256}-{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}");
        writer.WriteElementString("sha1", file.Sha1);
        writer.WriteElementString("sha256", file.Sha256);
        writer.WriteElementString("total", file.TotalCount.ToString());
        writer.WriteElementString("verboseMsg", "Scan finished, information embedded");

        writer.WriteEndElement();
    }

    private static string ShortName()
    {
        var name = Environment.MachineName;
        using var hasher = MD5.Create();
        var bytes = hasher.ComputeHash(Encoding.UTF8.GetBytes(name));
        return Convert.ToHexString(bytes.AsSpan(0, 4));
    }

    private static string LoadStylesheet()
        => File.ReadAllText(ResolvePath("VirusTotalReport.xslt"));

    private static string ResolvePath(string relative)
    {
        var baseDir = AppContext.BaseDirectory;
        var candidate = Path.Combine(baseDir, relative);
        if (File.Exists(candidate))
            return candidate;

        var assemblyDir = Path.GetDirectoryName(typeof(ReportBuilder).Assembly.Location);
        return Path.Combine(assemblyDir ?? baseDir, relative);
    }
}