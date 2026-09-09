using System.Text;
using VirusTotalNet.v3;

var apiKey = Environment.GetEnvironmentVariable("VT_API_KEY");
if (string.IsNullOrWhiteSpace(apiKey))
{
    Console.WriteLine("Set the VT_API_KEY environment variable to run this example.");
    return;
}

// EICAR is the standard antivirus test file; VirusTotal always has it in its database.
byte[] eicar = Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

using var vt = new VirusTotal(apiKey);

// "Have I seen this before?" — one line, in the spirit of the v2 library.
var file = await vt.GetFileReportAsync(eicar);

Console.WriteLine($"SHA-256 : {file.Id}");
Console.WriteLine($"Malicious: {file.Attributes?.LastAnalysisStats?.Malicious}");

Console.WriteLine();
Console.WriteLine("=== Upload a file -> wait -> fetch result ===");

if (args.Length == 0)
{
    Console.WriteLine("Pass a file path as the first argument, e.g.: dotnet run -- sample.exe");
    return;
}

string path = args[0];
byte[] payload = await File.ReadAllBytesAsync(path);

// 1. Upload the file and get its analysis id.
using var upload = new MemoryStream(payload);
var analysis = await vt.FileClient.ScanFileAsync(upload, fileName: Path.GetFileName(path));

// 2. Wait until the analysis finishes (polls through the shared rate limiter).
var completed = await vt.AnalysisClient.WaitForCompletionAsync(analysis.Id);
Console.WriteLine($"Analysis {completed.Id}: status = {completed.Attributes?.Status}");

// 3. Fetch the final report by SHA-256 and show the detection stats.
string sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload)).ToLowerInvariant();
var report = await vt.FileClient.GetFileAsync(sha256);
Console.WriteLine($"SHA-256   : {report.Id}");
Console.WriteLine($"Malicious : {report.Attributes?.LastAnalysisStats?.Malicious}");