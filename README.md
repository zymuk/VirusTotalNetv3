# VirusTotal.NET - A full implementation of the VirusTotal 3.0 API

[![NuGet](https://img.shields.io/nuget/v/VirusTotalNet.v3.svg?style=flat-square&label=nuget)](https://www.nuget.org/packages/VirusTotalNet.v3/)

### Features

*- Work in progress - files/analyses layer underway.*

* Zero external dependencies; targets `net8.0` (trimmable, AOT-compatible) and `netstandard2.0`, packaged as `VirusTotalNet.v3`
* Single envelope `VtResponse<T>` with lossless `JsonExtensionData` and tolerant JSON converters (string-typed numbers, Unix timestamps, crammed dates) for every endpoint
* `VtClient` — `x-apikey` auth, base URL, AOT-safe overloads, shared rate limiter (4 req/min & 500 req/day), retry with exponential backoff + jitter; maps `error.code` to a typed exception hierarchy (`ThrowOnError` toggle)
* Files — scan (≤ 32 MB), upload > 32 MB via pre-signed URL, report by md5/sha1/sha256, rescan, download
* Analyses — get analysis, `WaitForCompletionAsync` with configurable polling
* URLs / Domains / IPs — scan, get, rescan; resolutions, subdomains
* Comments & votes on any object type (list + create)
* Relationships — typed accessors + generic fallback, descriptor-first ids, memoized `IAsyncEnumerable` traversal
* Search — `/intelligence/search` via `ISearchClient`/`SearchClient` (cursor pagination, `descriptors_only` mode)
* Error handling — `ThrowOnError=false` returns the error envelope; Result-style `VtResult<T>` through `IVtClient.Try*`, so checks never need a try/catch
* `VirusTotal` facade — v2-style one-liners: `GetFileReportAsync(hash)` / `GetFileReportAsync(bytes)`, auto-scans and waits when the file is unknown

### Examples

*- Work in progress - two runnable API examples (EICAR lookup, upload-and-fetch) shipped.*

The classic EICAR "seen before?" check, one line like the v2 library. Set `VT_API_KEY` and run the console project:

```csharp
using System.Text;
using VirusTotalNet.v3;

var vt = new VirusTotal("YOUR_API_KEY");

byte[] eicar = Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

FileObject file = await vt.GetFileReportAsync(eicar);
Console.WriteLine("Malicious: " + file.Attributes.LastAnalysisStats.Malicious);
```

`GetFileReportAsync` looks the file up by its computed SHA-256; if VirusTotal does not know it yet, the facade submits a scan, waits for completion, and returns the fresh report.

Upload a file, wait for the analysis to finish, then fetch the result — the same flow, this time against the underlying module clients:

```csharp
using System.Text;
using VirusTotalNet.v3;

var vt = new VirusTotal("YOUR_API_KEY");

string path = @"C:\path\to\file.exe";          // point at a real file
byte[] payload = await File.ReadAllBytesAsync(path);

// 1. Upload the file and get its analysis id.
using var upload = new MemoryStream(payload);
AnalysisObject analysis = await vt.FileClient.ScanFileAsync(upload, fileName: Path.GetFileName(path));

// 2. Wait until the analysis finishes (polls through the shared rate limiter).
AnalysisObject completed = await vt.AnalysisClient.WaitForCompletionAsync(analysis.Id);
Console.WriteLine("Status: " + completed.Attributes.Status);

// 3. Fetch the final report by SHA-256 and read the detection stats.
string sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload)).ToLowerInvariant();
FileObject report = await vt.FileClient.GetFileAsync(sha256);
Console.WriteLine("Malicious: " + report.Attributes.LastAnalysisStats.Malicious);
```

`ScanFileAsync` returns the created analysis; `WaitForCompletionAsync` polls until the status is terminal; `GetFileAsync` then returns the fresh report including the per-engine statistics.

Walk the links between objects: look a file up, then query it directly by type (M3 clients) or traverse its relationships from the object at hand (M4):

```csharp
using VirusTotalNet.v3;
using VirusTotalNet.v3.Clients;
using VirusTotalNet.v3.Relationships;

var vt = new VirusTotal("YOUR_API_KEY");
FileObject file = await vt.FileClient.GetFileAsync("sha256_of_the_file");

// M3 — query a domain directly by type.
var domains = new DomainClient(vt.Client);
DomainObject domain = await domains.GetDomainAsync("example.com");
VtCollection<DomainObject> subs = await domains.GetSubdomainsAsync("example.com");
VtCollection<ResolutionObject> resolutions = await domains.GetResolutionsAsync("example.com");

// M4 — walk relationships from the file object without knowing API paths.
VtCollection<VtObjectId> commentIds = await vt.Relationships.GetRelatedIdsAsync("files", file.Id, "comments"); // ids only
VtCollection<UrlObject> contacted = await file.ContactedUrlsAsync(vt.Relationships);                          // typed + memoized
await foreach (UrlObject url in vt.Relationships.TraverseAsync<UrlObject>("files", file.Id, "contacted_urls")) // all pages
{
    Console.WriteLine(url.Id);
}
```

M3 clients (`UrlClient`, `DomainClient`, `IpClient`, `FeedbackClient`) target a specific object type you already know. M4 navigation works off an object in hand — no need to remember endpoint paths — and shares one rate limiter plus memoized first pages so traversals stay budget-friendly.

Features and examples in this README only appear once they are implemented and tested.