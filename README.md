# VirusTotal.NET - A full implementation of the VirusTotal 3.0 API

[![NuGet](https://img.shields.io/nuget/v/VirusTotalNet.v3.svg?style=flat-square&label=nuget)](https://www.nuget.org/packages/VirusTotalNet.v3/)

### Features

*- Work in progress - files/analyses layer underway.*

* Zero external dependencies - only System.Text.Json (in-box) - keeps your deployment folder lean
* Targets net8.0, marked trimmable and AOT-compatible
* Packaged as `VirusTotalNet.v3` public preview
* `VtResponse<T>` envelope `{ data, meta, links, error }` — one parse path for every endpoint, lossless via `JsonExtensionData`
* `VirusTotalOptions` + shared `VirusTotalJson` options with tolerant converters (string-typed numbers, `YYYYmmdd`, Unix timestamps, literal `"null"`)
* `VtClient`/`IVtClient` — wraps `HttpClient` with `x-apikey` header and `https://www.virustotal.com/api/v3/` base URL; AOT-safe `GetAsync` overload accepting `JsonTypeInfo<VtResponse<T>>`
* Rate limiter (sliding window, default 4 req/min & 500 req/day) shared across all requests
* Retry policy — exponential backoff with jitter on HTTP 429/5xx and network errors, honors the API `Retry-After` header, configurable via `UseRetry`/`MaxRetries`/`InitialRetryDelay`
* Exception hierarchy `VirusTotalException` → `VtHttpException` → concrete (`NotFound`, `QuotaExceeded`, `Authentication`, `RateLimit`, `InvalidRequest`, `Server`); maps API `error.code` + HTTP status to the right exception, `ThrowOnError` toggles throwing vs. returning the error envelope
* `IFileClient`/`FileClient` — `ScanFileAsync` uploads a file as multipart/form-data (`POST /files`, ≤ 32 MB enforced) and returns an `AnalysisObject` with typed `AnalysisAttributes` (status, date, stats); `ScanLargeFileAsync` handles files over 32 MB via the pre-signed upload URL; `GetFileAsync` retrieves the report for any MD5/SHA-1/SHA-256 (`GET /files/{id}`); `AnalyseFileAsync` rescans a known file (`POST /files/{id}/analyse`); `DownloadAsync`/`GetDownloadUrlAsync` fetch a file's content or a pre-signed URL
* `VtClient.GetStreamAsync` — streaming GET for binary payloads, sharing the same rate limiter and retry policy
* `IAnalysisClient`/`AnalysisClient` — `GetAnalysisAsync` and `WaitForCompletionAsync` (respects the shared rate limiter, configurable poll interval, `AnalysisStatus` constants)
* `VirusTotal` facade — v2-style one-liners: construct with an API key, call `GetFileReportAsync(hash)` or `GetFileReportAsync(byte[])` (computes SHA-256, and auto-scans/waits when the file is not yet known)
* `IUrlClient`/`UrlClient` — `ScanUrlAsync`, `GetUrlAsync` (accepts the URL or its base64url id), `AnalyseUrlAsync` (rescan), plus `EncodeUrlId` for id encoding
* `IDomainClient`/`DomainClient` — `GetDomainAsync`, `AnalyseDomainAsync` (rescan), `GetResolutionsAsync` / `GetSubdomainsAsync` (cursor-paginated `VtCollection`)
* `IIpClient`/`IpClient` — `GetIpAsync`, `AnalyseIpAsync` (rescan), `GetResolutionsAsync` (cursor-paginated)
* `IFeedbackClient`/`FeedbackClient` — comments & votes on any object type: `GetCommentsAsync`, `AddCommentAsync`, `GetVotesAsync`, `AddVoteAsync` (cursor-paginated lists; `VtObjectType` constants for files/urls/domains/ip_addresses)
* `IRelationshipsClient`/`RelationshipsClient` — relationship navigation: generic `GetRelatedAsync<T>`, descriptor-first `GetRelatedIdsAsync` (ids only), memoized first pages per `(type, id, name)`, and `TraverseAsync<T>` `IAsyncEnumerable` traversal; typed extensions (`ContactedUrlsAsync`, `DetectedUrlsAsync`, `BehavioursAsync`, `ResolutionsAsync`, `SubdomainsAsync`, `CommentsAsync`, `VotesAsync`) hanging off the parent object

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

Features and examples in this README only appear once they are implemented and tested.