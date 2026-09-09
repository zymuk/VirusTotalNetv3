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