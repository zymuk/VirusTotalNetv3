using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.v3.Tests.TestInternals;
using VirusTotalNet.v3.Clients;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Tests;

public class IpClientTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    private const string Ip = "8.8.8.8";

    [Fact]
    public async Task GetIp_SendsGet_ToIpAddressesEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "ip_address", "id": "8.8.8.8", "attributes": { "country": "US", "asn": 15169, "as_owner": "GOOGLE" } } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new IpClient(vt);

        var ip = await client.GetIpAsync(Ip);

        Assert.Equal("ip_address", ip!.Type);
        Assert.Equal(Ip, ip.Id);
        Assert.Equal("US", ip.Attributes!.Country);
        Assert.Equal(15169, ip.Attributes.Asn);
        Assert.Equal("GOOGLE", ip.Attributes.AsOwner);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "ip_addresses/8.8.8.8", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task AnalyseIp_Posts_ToRescanEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-ip" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new IpClient(vt);

        var analysis = await client.AnalyseIpAsync(Ip);

        Assert.Equal("analysis-ip", analysis!.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "ip_addresses/8.8.8.8/analyse", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetResolutions_ReturnsCollection_WithDomains()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": [ { "type": "resolution", "id": "r1", "attributes": { "date": 1609459200, "domain": "example.com", "last_resolved": 1609459200 } } ], "meta": { "count": 1 }, "links": { "next": "https://x/ip_addresses/8.8.8.8/resolutions?cursor=next-1" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new IpClient(vt);

        var page = await client.GetResolutionsAsync(Ip);

        var item = Assert.Single(page.Items);
        Assert.Equal("example.com", item.Attributes!.Domain);
        Assert.Equal(1, page.Count);
        Assert.Equal("next-1", page.NextCursor);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "ip_addresses/8.8.8.8/resolutions", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetResolutions_WithCursor_AppendsCursorQuery()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": [ ], "meta": { "count": 0 } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new IpClient(vt);

        await client.GetResolutionsAsync(Ip, cursor: "enc cursor");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "ip_addresses/8.8.8.8/resolutions?cursor=enc%20cursor", request.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task IpMethods_EmptyIp_Throw()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new IpClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.GetIpAsync(" "));
        await Assert.ThrowsAsync<ArgumentException>(() => client.AnalyseIpAsync(""));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetResolutionsAsync(" "));

        Assert.Empty(handler.Requests);
    }
}