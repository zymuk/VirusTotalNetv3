using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using VirusTotalNet.v3;
using VirusTotalNet.v3.Clients;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.ReportGenerator;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var apiKey = Environment.GetEnvironmentVariable("VT_API_KEY");
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            Console.Error.WriteLine("Set the VT_API_KEY environment variable to run the report generator.");
            return 2;
        }

        if (args.Length == 0)
        {
            Console.Error.WriteLine("Pass one or more file paths, e.g.: dotnet run -- D:\\folder\\file1.bin D:\\folder\\file2.dll");
            return 2;
        }

        var files = args.Select(Path.GetFullPath).Where(File.Exists).ToList();
        if (files.Count != args.Length)
            Console.Error.WriteLine($"Skipped {args.Length - files.Count} path(s) that do not exist.");

        var sw = Stopwatch.StartNew();
        using var vt = new VirusTotal(apiKey);

        var scanFiles = new List<ScanFileData>(files.Count);
        foreach (var path in files)
        {
            Console.WriteLine($"Scanning {path} ...");
            try
            {
                var data = await ScanOneAsync(vt, path).ConfigureAwait(false);
                scanFiles.Add(data);
            }
            catch (VirusTotalException ex)
            {
                Console.Error.WriteLine($"  FAILED: {ex.Message}");
            }
        }
        sw.Stop();

        if (scanFiles.Count == 0)
        {
            Console.Error.WriteLine("No file could be scanned; no report written.");
            return 1;
        }

        var report = ReportBuilder.BuildReport(scanFiles, sw.Elapsed);
        var output = Path.Combine(
            AppContext.BaseDirectory,
            $"VirusTotalReport_{DateTime.Now:yyyyMMdd_HHmmss}.xml");
        File.WriteAllText(output, report, new UTF8Encoding(false));

        Console.WriteLine();
        Console.WriteLine($"Report written to {output}");
        Console.WriteLine($"Scanned {scanFiles.Count}/{files.Count} files in {sw.Elapsed:hh\\:mm\\:ss}.");
        return 0;
    }

    private static async Task<ScanFileData> ScanOneAsync(VirusTotal vt, string path)
    {
        var bytes = await File.ReadAllBytesAsync(path).ConfigureAwait(false);
        var md5 = Hash(bytes, HashAlgorithmName.MD5);
        var sha1 = Hash(bytes, HashAlgorithmName.SHA1);
        var sha256 = Hash(bytes, HashAlgorithmName.SHA256);

        FileObject report;
        try
        {
            report = await vt.FileClient.GetFileAsync(sha256).ConfigureAwait(false);
        }
        catch (NotFoundException)
        {
            Console.WriteLine($"  not in VirusTotal yet, uploading {bytes.Length} bytes ...");
            using var stream = new MemoryStream(bytes);
            var analysis = await ScanAsync(vt, stream, path).ConfigureAwait(false);
            await vt.AnalysisClient.WaitForCompletionAsync(analysis.Id).ConfigureAwait(false);
            report = await vt.FileClient.GetFileAsync(sha256).ConfigureAwait(false);
        }

        var info = new FileInfo(path);
        return new ScanFileData
        {
            FileName = info.Name,
            PathFile = path,
            FileSize = info.Length,
            FileDateTime = info.LastWriteTime,
            Md5 = md5,
            Sha1 = sha1,
            Sha256 = sha256,
            Report = report
        };
    }

    private static async Task<AnalysisObject> ScanAsync(VirusTotal vt, MemoryStream stream, string path)
    {
        if (stream.Length <= FileClient.MaxScanSize)
            return await vt.FileClient.ScanFileAsync(stream, fileName: Path.GetFileName(path)).ConfigureAwait(false);

        stream.Position = 0;
        return await vt.FileClient.ScanLargeFileAsync(stream, fileName: Path.GetFileName(path)).ConfigureAwait(false);
    }

    private static string Hash(byte[] data, HashAlgorithmName name)
    {
        using var algo = IncrementalHash.CreateHash(name);
        algo.AppendData(data);
        return Convert.ToHexString(algo.GetHashAndReset()).ToLowerInvariant();
    }
}