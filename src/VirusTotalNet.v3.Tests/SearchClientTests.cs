using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.v3.Tests.TestInternals;
using VirusTotalNet.v3.Clients;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Tests;

public class SearchClientTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    private const string Query = "type:url content:malware";

    [Fact]
    public async Task Search_SendsEncodedQuery_AndReturnsCollection()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                $$"""
                    { "data": [
                        { "type": "url", "id": "aHR0cHM6Ly9leGFtcGxlLmNvbS8", "attributes": { "times_submitted": 3, "last_analysis_stats": { "malicious": 2, "harmless": 1 } } },
                        { "type": "file", "id": "bbbb000000000000000000000000000000000000000000000000000000000000" }
                      ],
                      "meta": { "count": 12 },
                      "links": { "next": "https://x/api/v3/intelligence/search?query={{Uri.EscapeDataString(Query)}}&cursor=c-1" } }
                    """));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new SearchClient(vt);

        var page = await client.SearchAsync(Query);

        Assert.Equal(2, page.Items.Count);
        Assert.Equal("url", page.Items[0].Type);
        Assert.Equal("aHR0cHM6Ly9leGFtcGxlLmNvbS8", page.Items[0].Id);
        Assert.Equal("file", page.Items[1].Type);
        Assert.Equal(12, page.Count);
        Assert.Equal("c-1", page.NextCursor);

        // Attributes preserved losslessly in Raw.
        var raw = page.Items[0].Attributes!.Raw;
        Assert.Equal(3, raw["times_submitted"].GetInt32());

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(
            VirusTotalOptions.DefaultBaseAddress + "intelligence/search?query=type%3Aurl%20content%3Amalware",
            request.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task Search_DescriptorsOnly_AndCursor_ArePassed()
    {
        var handler = new StubHttpMessageHandler(
            request => StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": [ { "type": "file", "id": "cccc000000000000000000000000000000000000000000000000000000000000" } ], "meta": { "count": 1 } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new SearchClient(vt);

        var page = await client.SearchAsync(Query, cursor: "next-page", descriptorsOnly: true);

        Assert.Single(page.Items);
        Assert.Null(page.Items[0].Attributes);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(
            VirusTotalOptions.DefaultBaseAddress + "intelligence/search?query=type%3Aurl%20content%3Amalware&descriptors_only=true&cursor=next-page",
            request.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task Search_EmptyQuery_Throws()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": [] }"""));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new SearchClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.SearchAsync(" "));

        Assert.Empty(handler.Requests);
    }
}