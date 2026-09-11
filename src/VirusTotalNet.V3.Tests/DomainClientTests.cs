using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.V3.Tests.TestInternals;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Tests;

public class DomainClientTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    private const string Domain = "example.com";

    [Fact]
    public async Task GetDomain_SendsGet_ToDomainsEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "domain", "id": "example.com", "attributes": { "registrar": "Example Registrar", "times_submitted": 3 } } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new DomainClient(vt);

        var domain = await client.GetDomainAsync(Domain);

        Assert.Equal("domain", domain!.Type);
        Assert.Equal(Domain, domain.Id);
        Assert.Equal("Example Registrar", domain.Attributes!.Registrar);
        Assert.Equal(3, domain.Attributes.TimesSubmitted);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "domains/example.com", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task AnalyseDomain_Posts_ToRescanEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-domain" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new DomainClient(vt);

        var analysis = await client.AnalyseDomainAsync(Domain);

        Assert.Equal("analysis-domain", analysis!.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "domains/example.com/analyse", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetResolutions_ReturnsCollection()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": [ { "type": "resolution", "id": "r1", "attributes": { "date": 1609459200, "ip_address": "8.8.8.8", "last_resolved": 1609459200 } } ], "meta": { "count": 1 }, "links": { "next": "https://x/domains/example.com/resolutions?cursor=abc" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new DomainClient(vt);

        var page = await client.GetResolutionsAsync(Domain);

        var item = Assert.Single(page.Items);
        Assert.Equal("resolution", item.Type);
        Assert.Equal("8.8.8.8", item.Attributes!.IpAddress);
        Assert.Equal(1, page.Count);
        Assert.Equal("abc", page.NextCursor);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "domains/example.com/resolutions", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetSubdomains_ReturnsCollection_AndSendsCursor()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": [ { "type": "domain", "id": "www.example.com" } ], "meta": { "count": 1 } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new DomainClient(vt);

        var page = await client.GetSubdomainsAsync(Domain, cursor: "sub-cursor");

        Assert.Equal("www.example.com", Assert.Single(page.Items).Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "domains/example.com/subdomains?cursor=sub-cursor", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task DomainMethods_EmptyDomain_Throw()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new DomainClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.GetDomainAsync(" "));
        await Assert.ThrowsAsync<ArgumentException>(() => client.AnalyseDomainAsync(""));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetResolutionsAsync(" "));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetSubdomainsAsync(""));

        Assert.Empty(handler.Requests);
    }
}