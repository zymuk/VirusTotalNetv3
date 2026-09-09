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

### Examples

*- Work in progress - first runnable API example (EICAR) shipped.*

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

Features and examples in this README only appear once they are implemented and tested.