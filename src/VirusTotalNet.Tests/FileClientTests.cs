using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNet.Tests.TestInternals;
using VirusTotalNet.v3.Clients;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.Tests;

public class FileClientTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    [Fact]
    public async Task ScanFile_SendsMultipartPost_ToFilesEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-1", "links": { "self": "https://x/analyses/analysis-1" } } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("sample-bytes"));
        var analysis = await client.ScanFileAsync(stream, "eicar.txt");

        Assert.NotNull(analysis);
        Assert.Equal("analysis", analysis!.Type);
        Assert.Equal("analysis-1", analysis.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files", request.RequestUri!.ToString());

        Assert.True(request.Headers.TryGetValues("x-apikey", out var authValues));
        Assert.Equal("test-key", Assert.Single(authValues!));

        Assert.NotNull(request.Content);
        var contentType = request.Content!.Headers.ContentType!;
        Assert.Equal("multipart/form-data", contentType.MediaType);
    }

    [Fact]
    public async Task ScanFile_SendsFilePart_WithFieldNameAndFilename()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "a2" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("EICAR"));
        await client.ScanFileAsync(stream, "malware.exe");

Assert.Contains("name=file", handler.LastRequestBody);
        Assert.Contains("filename=malware.exe", handler.LastRequestBody);
        Assert.Contains("EICAR", handler.LastRequestBody);
    }

    [Fact]
    public async Task ScanFile_DeserializesAnalysisAttributes()
    {
        const string json = """
            {
              "data": {
                "type": "analysis",
                "id": "analysis-42",
                "attributes": {
                  "status": "completed",
                  "date": 1704067200,
                  "stats": { "malicious": 12, "harmless": 58, "undetected": 7, "suspicious": 0, "type-unsupported": 2, "timeout": 1 }
                }
              }
            }
            """;

        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, json));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("bytes"));
        var analysis = await client.ScanFileAsync(stream, "x.bin");

        Assert.Equal("analysis", analysis.Type);
        Assert.Equal("analysis-42", analysis.Id);

        var attrs = analysis.Attributes;
        Assert.NotNull(attrs);
        Assert.Equal("completed", attrs!.Status);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1704067200), attrs.Date);
        Assert.Equal(12, attrs.Stats!.Malicious);
        Assert.Equal(58, attrs.Stats.Harmless);
        Assert.Equal(2, attrs.Stats.TypeUnsupported);
    }

    [Fact]
    public async Task ScanFile_OversizedStream_Throws()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        var oversized = new MemoryStream(new byte[FileClient.MaxScanSize + 1]);

        await using (oversized)
        {
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => client.ScanFileAsync(oversized, "big.bin"));
        }

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ScanFile_NullStream_Throws()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => client.ScanFileAsync(null!, "x.bin"));
    }
}