using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.v3.Tests.TestInternals;
using VirusTotalNet.v3.Clients;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Tests;

public class FeedbackClientTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    [Fact]
    public async Task GetComments_ReturnsCollection()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": [ { "type": "comment", "id": "c1", "attributes": { "text": "hello", "html": "<p>hello</p>", "date": 1609459200 } } ], "meta": { "count": 1 }, "links": { "next": "https://x/files/abc/comments?cursor=n1" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FeedbackClient(vt);

        var page = await client.GetCommentsAsync(VtObjectType.File, "abc");

        var comment = Assert.Single(page.Items);
        Assert.Equal("comment", comment.Type);
        Assert.Equal("hello", comment.Attributes!.Text);
        Assert.Equal(1, page.Count);
        Assert.Equal("n1", page.NextCursor);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files/abc/comments", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task AddComment_PostsCommentPayload_OnAnyObjectType()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "comment", "id": "c-new", "attributes": { "text": "hi", "date": 1609459200 } } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FeedbackClient(vt);

        var comment = await client.AddCommentAsync(VtObjectType.IpAddress, "8.8.8.8", "hi");

        Assert.Equal("c-new", comment!.Id);
        Assert.Equal("hi", comment.Attributes!.Text);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "ip_addresses/8.8.8.8/comments", request.RequestUri!.ToString());

        Assert.Contains(""""type":"comment"""", handler.LastRequestBody);
        Assert.Contains(""""text":"hi"""", handler.LastRequestBody);
    }

    [Fact]
    public async Task GetVotes_ReturnsCollection()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": [ { "type": "vote", "id": "v1", "attributes": { "verdict": "malicious", "date": 1609459200 } } ], "meta": { "count": 1 } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FeedbackClient(vt);

        var page = await client.GetVotesAsync(VtObjectType.Url, "aHR0cHM6Ly9leGFtcGxlLmNvbS8");

        var vote = Assert.Single(page.Items);
        Assert.Equal("malicious", vote.Attributes!.Verdict);
        Assert.Equal(1, page.Count);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8/votes", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task AddVote_PostsVotePayload()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "vote", "id": "v-new", "attributes": { "verdict": "harmless", "date": 1609459200 } } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FeedbackClient(vt);

        var vote = await client.AddVoteAsync(VtObjectType.Domain, "example.com", "harmless");

        Assert.Equal("v-new", vote!.Id);
        Assert.Equal("harmless", vote.Attributes!.Verdict);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "domains/example.com/votes", request.RequestUri!.ToString());

        Assert.Contains(""""type":"vote"""", handler.LastRequestBody);
        Assert.Contains(""""verdict":"harmless"""", handler.LastRequestBody);
    }

    [Fact]
    public async Task FeedbackMethods_InvalidArgs_Throw()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FeedbackClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.GetCommentsAsync(" ", "id"));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetCommentsAsync(VtObjectType.File, ""));
        await Assert.ThrowsAsync<ArgumentException>(() => client.AddCommentAsync(VtObjectType.File, "id", " "));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetVotesAsync("", "id"));
        await Assert.ThrowsAsync<ArgumentException>(() => client.AddVoteAsync(VtObjectType.File, "id", ""));
        await Assert.ThrowsAsync<ArgumentException>(() => client.AddVoteAsync(VtObjectType.File, "id", "suspicious"));
        await Assert.ThrowsAsync<ArgumentException>(() => client.AddVoteAsync(VtObjectType.File, "id", "HARMLESS"));

        Assert.Empty(handler.Requests);
    }
}