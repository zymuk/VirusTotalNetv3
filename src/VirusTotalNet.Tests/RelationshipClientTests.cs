using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.Tests.TestInternals;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;
using VirusTotalNet.v3.Relationships;

namespace VirusTotalNet.Tests;

public class RelationshipClientTests
{
    private const string Sha256 = "aaaa000000000000000000000000000000000000000000000000000000000000";
    private const string UrlId1 = "aHR0cHM6Ly9leGFtcGxlLmNvbS9h";
    private const string UrlId2 = "aHR0cHM6Ly9leGFtcGxlLmNvbS9i";

    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    // Multi-request tests raise the limits so the shared RateLimiter clock (briefly replaced by
    // parallel RateLimiterTests) can never push them into a wait branch.
    private static VirusTotalOptions HighLimitOptions()
        => new() { ApiKey = "test-key", RequestsPerMinute = 100_000, RequestsPerDay = 1_000_000 };

    private static string ContactedUrlsPage1()
        => $$"""
            { "data": [
                { "type": "url", "id": "{{UrlId1}}" },
                { "type": "url", "id": "{{UrlId2}}" }
              ],
              "meta": { "count": 3 },
              "links": { "next": "https://x/api/v3/files/{{Sha256}}/contacted_urls?cursor=c1" } }
            """;

    private static string ContactedUrlsPage2()
        => $$"""
            { "data": [ { "type": "url", "id": "aHR0cHM6Ly9leGFtcGxlLmNvbS9j" } ],
              "meta": { "count": 3 },
              "links": { "next": "" } }
            """;

    [Fact]
    public async Task GetRelatedAsync_GenericFallback_ReturnsCollection()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, ContactedUrlsPage1()));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RelationshipsClient(vt);

        var page = await client.GetRelatedAsync<UrlObject>(VtObjectType.File, Sha256, RelationshipName.ContactedUrls);

        Assert.Equal(2, page.Items.Count);
        Assert.Equal(UrlId1, page.Items[0].Id);
        Assert.Equal(3, page.Count);
        Assert.Equal("c1", page.NextCursor);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + $"files/{Sha256}/contacted_urls", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetRelatedAsync_FirstPage_IsMemoized()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, ContactedUrlsPage1()));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RelationshipsClient(vt);

        var first = await client.GetRelatedAsync<UrlObject>(VtObjectType.File, Sha256, RelationshipName.ContactedUrls);
        var second = await client.GetRelatedAsync<UrlObject>(VtObjectType.File, Sha256, RelationshipName.ContactedUrls);

        Assert.Equal(first.Items.Select(u => u.Id), second.Items.Select(u => u.Id));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetRelatedAsync_WithCursor_BypassesCache()
    {
        var handler = new StubHttpMessageHandler(
            request => StubHttpMessageHandler.Json(HttpStatusCode.OK, ContactedUrlsPage2()));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RelationshipsClient(vt);

        // Seed the cache with page 1.
        await client.GetRelatedAsync<UrlObject>(VtObjectType.File, Sha256, RelationshipName.ContactedUrls);
        var page = await client.GetRelatedAsync<UrlObject>(VtObjectType.File, Sha256, RelationshipName.ContactedUrls, cursor: "c1");

        Assert.Equal("aHR0cHM6Ly9leGFtcGxlLmNvbS9j", Assert.Single(page.Items).Id);
        Assert.Equal(2, handler.Requests.Count);
        Assert.EndsWith("?cursor=c1", handler.Requests[1].RequestUri!.ToString());
    }

    [Fact]
    public async Task GetRelatedIdsAsync_ReturnsDescriptorsOnly()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                $$""""
                    { "data": [
                        { "type": "comment", "id": "c1" },
                        { "type": "comment", "id": "c2" }
                      ],
                      "meta": { "count": 2 },
                      "links": { "next": "https://x/api/v3/files/{{Sha256}}/relationships/comments?cursor=z" } }
                    """"));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RelationshipsClient(vt);

        var page = await client.GetRelatedIdsAsync(VtObjectType.File, Sha256, RelationshipName.Comments);

        Assert.Equal(2, page.Items.Count);
        var (firstType, firstId) = page.Items[0];
        Assert.Equal("comment", firstType);
        Assert.Equal("c1", firstId);
        Assert.Equal(2, page.Count);
        Assert.Equal("z", page.NextCursor);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + $"files/{Sha256}/relationships/comments", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task TraverseAsync_FollowsCursors_UntilLastPage()
    {
        var handler = new StubHttpMessageHandler(
            request => StubHttpMessageHandler.Json(
                HttpStatusCode.OK,
                request.RequestUri!.Query.Contains("cursor") ? ContactedUrlsPage2() : ContactedUrlsPage1()));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RelationshipsClient(vt);

        var ids = new System.Collections.Generic.List<string>();
        var traverse = client.TraverseAsync<UrlObject>(VtObjectType.File, Sha256, RelationshipName.ContactedUrls);
        await foreach (var url in traverse)
            ids.Add(url.Id);

        Assert.Equal(new[] { UrlId1, UrlId2, "aHR0cHM6Ly9leGFtcGxlLmNvbS9j" }, ids);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task TypedExtensions_TargetCorrectEndpoints()
    {
        var handler = new StubHttpMessageHandler(
            _ => StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": [], "meta": { "count": 0 } }"""));
        using var vt = new VtClient(HighLimitOptions(), new HttpClient(handler));
        var client = new RelationshipsClient(vt);

        var file = new FileObject { Type = "file", Id = Sha256 };
        await file.ContactedUrlsAsync(client);
        await file.DetectedUrlsAsync(client);
        await file.BehavioursAsync(client);
        await file.CommentsAsync(client);
        await file.VotesAsync(client);

        AssertMethods(handler, "contacted_urls", "detected_urls", "behaviours", "comments", "votes");
    }

    [Fact]
    public async Task TypedExtensions_DomainAndIp_PointToResolutionsAndSubdomains()
    {
        var handler = new StubHttpMessageHandler(
            _ => StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": [], "meta": { "count": 0 } }"""));
        using var vt = new VtClient(HighLimitOptions(), new HttpClient(handler));
        var client = new RelationshipsClient(vt);

        var domain = new DomainObject { Type = "domain", Id = "example.com" };
        await domain.ResolutionsAsync(client);
        await domain.SubdomainsAsync(client);

        var ip = new IpObject { Type = "ip_address", Id = "8.8.8.8" };
        await ip.ResolutionsAsync(client);

        AssertMethods(handler, "resolutions", "subdomains", "resolutions");
    }

    [Fact]
    public async Task RelationshipMethods_InvalidArgs_Throw()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": [] }"""));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RelationshipsClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.GetRelatedAsync<UrlObject>(" ", Sha256, RelationshipName.ContactedUrls));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetRelatedAsync<UrlObject>(VtObjectType.File, "", RelationshipName.ContactedUrls));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetRelatedAsync<UrlObject>(VtObjectType.File, Sha256, " "));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetRelatedIdsAsync(VtObjectType.File, Sha256, ""));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetRelatedIdsAsync(VtObjectType.File, " ", RelationshipName.Comments));

        Assert.Empty(handler.Requests);
    }

    private static void AssertMethods(StubHttpMessageHandler handler, params string[] relationshipNames)
    {
        Assert.Equal(relationshipNames.Length, handler.Requests.Count);
        for (var i = 0; i < relationshipNames.Length; i++)
            Assert.EndsWith("/" + relationshipNames[i], handler.Requests[i].RequestUri!.ToString());
    }
}