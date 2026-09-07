# VirusTotal.NET - A full implementation of the VirusTotal 3.0 API

[![NuGet](https://img.shields.io/nuget/v/VirusTotalNet.v3.svg?style=flat-square&label=nuget)](https://www.nuget.org/packages/VirusTotalNet.v3/)

### Features

*- Work in progress - core envelope/config layer done, HTTP client and endpoints still ahead.*

* Zero external dependencies - only System.Text.Json (in-box) - keeps your deployment folder lean
* Targets net8.0, marked trimmable and AOT-compatible
* Packaged as `VirusTotalNet.v3` public preview
* `VtResponse<T>` envelope `{ data, meta, links, error }` — one parse path for every endpoint, lossless via `JsonExtensionData`
* `VirusTotalOptions` + shared `VirusTotalJson` options with tolerant converters (string-typed numbers, `YYYYmmdd`, Unix timestamps, literal `"null"`)

### Examples

*- Work in progress - no runnable API examples yet (Milestone M0 scaffold only).*

* `VirusTotalNet.Examples` — console project scaffolding only (builds and runs the .NET template)
* First real example (M2): the classic EICAR "seen before" check, mirroring the v2 library

Features and examples in this README only appear once they are implemented and tested.