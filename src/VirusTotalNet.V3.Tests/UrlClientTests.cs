using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.V3.Tests.TestInternals;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Tests;

public class UrlClientTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    private const string Url = "https://example.com/";
    private const string UrlId = "aHR0cHM6Ly9leGFtcGxlLmNvbS8";

    private static string AnalysisJson(string id = "analysis-url-1")
        => $$"""{ "data": { "type": "analysis", "id": "{{id}}" } }""";

    [Fact]
    public void EncodeUrlId_ProducesUnpaddedBase64Url()
    {
        var id = UrlClient.EncodeUrlId(Url);
        Assert.Equal(UrlId, id);
        Assert.DoesNotContain("=", id);
        Assert.DoesNotContain("+", id);
        Assert.DoesNotContain("/", id);
    }

    [Fact]
    public void EncodeUrlId_Empty_Throws()
    {
        Assert.Throws<ArgumentException>(() => UrlClient.EncodeUrlId(" "));
    }

    [Fact]
    public async Task ScanUrl_SendsFormPost_ToUrlsEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson("analysis-scan-url")));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UrlClient(vt);

        var analysis = await client.ScanUrlAsync(Url);

        Assert.Equal("analysis", analysis!.Type);
        Assert.Equal("analysis-scan-url", analysis.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "urls", request.RequestUri!.ToString());
        Assert.Equal("application/x-www-form-urlencoded", request.Content!.Headers.ContentType!.MediaType);
        Assert.Contains("url=", handler.LastRequestBody);
        Assert.Contains("example.com", handler.LastRequestBody);
    }

    [Fact]
    public async Task GetUrl_WithUrlText_EncodesId()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "url", "id": "some-id", "attributes": { "url": "https://example.com/", "times_submitted": 7 } } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UrlClient(vt);

        var url = await client.GetUrlAsync(Url);

        Assert.Equal("url", url!.Type);
        Assert.Equal(7, url.Attributes!.TimesSubmitted);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "urls/" + UrlId, request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetUrl_WithEncodedId_UsesAsIs()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "url", "id": "aHR0cHM6Ly9leGFtcGxlLmNvbS8" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UrlClient(vt);

        var url = await client.GetUrlAsync(UrlId);

        Assert.Equal(UrlId, url!.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "urls/" + UrlId, request.RequestUri!.ToString());
    }

    [Fact]
    public async Task AnalyseUrl_Posts_ToRescanEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson("analysis-rescan-url")));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UrlClient(vt);

        var analysis = await client.AnalyseUrlAsync(Url);

        Assert.Equal("analysis-rescan-url", analysis!.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "urls/" + UrlId + "/analyse", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task UrlMethods_EmptyId_Throw()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UrlClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.ScanUrlAsync(" "));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetUrlAsync(""));
        await Assert.ThrowsAsync<ArgumentException>(() => client.AnalyseUrlAsync(" "));

        Assert.Empty(handler.Requests);
    }
}