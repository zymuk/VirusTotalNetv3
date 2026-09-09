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
* `IFileClient`/`FileClient` — `ScanFileAsync` uploads a file as multipart/form-data (`POST /files`, ≤ 32 MB enforced) and returns an `AnalysisObject` with typed `AnalysisAttributes` (status, date, stats)

### Examples

*- Work in progress - no runnable API examples yet (Milestone M0 scaffold only).*

* `VirusTotalNet.Examples` — console project scaffolding only (builds and runs the .NET template)
* First real example (M2): the classic EICAR "seen before" check, mirroring the v2 library

Features and examples in this README only appear once they are implemented and tested.